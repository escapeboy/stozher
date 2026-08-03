"""The offline bootstrap — DEF-4's reproductions, un-quarantined.

Three of these were `test_def4_*` in `test_open_defects.py`. Two of them failed: a cold cache with no
kernel could not open a session at all, and `[gateway] enabled = false` neither disabled the session
nor the gate. The third **passed**, deliberately, as the control that stopped "there is no offline
mode" from reading as true — the offline profile was implemented and worked from a warm cache, and
what was missing was a way to *get* that cached document. It is still here, still a control, and it
is now a control for the bundle path rather than for a defect.

Everything else in this file is the counterfactual side of the fix. A bundle path that accepts
anything is worse than no bundle path, so the tampering cases are not an afterthought: flip one byte
of the policy, of the signature, or of `max-age`, sign with a key nobody enrolled, or let the bundle
expire, and the component must refuse to start with an empty cache — never start on it, never warn
and continue.
"""

from __future__ import annotations

import contextlib
import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway import crypto
from stozher_gateway.bundle import BUNDLE_VERSION
from stozher_gateway.canonical import sha256_hex
from stozher_gateway.config import GatewayConfig
from stozher_gateway.governed import Governor
from stozher_gateway.refusal import RefusalError
from stozher_gateway.runtime import StartupRefusedError
from stozher_gateway.signing import SigningKey, object_id
from stozher_gateway.store import GatewayStore

from .support import baseline_policy

ROOT = SigningKey(bytes.fromhex("31" * 32), "human:ivan")
POLICY_KEY = SigningKey(bytes.fromhex("33" * 32), "org:policy")
#: A root the deployment has never enrolled. Same shape, same algorithm, no standing.
STRANGER = SigningKey(bytes.fromhex("35" * 32), "human:nobody")

#: What `stozher-kernel anchor` prints — carried verbatim, signed over, and not otherwise read.
ANCHOR = {"heads": [{"stream": "kernel:core", "seq": 41, "checkpoint": "c" * 64}]}


def _config(tmp_path: Path, *, enabled: bool = True, bundle: Path | None = None) -> GatewayConfig:
    """The configuration a CI container writes: a dead kernel port and, optionally, a bundle."""
    seed = tmp_path / "identity.seed"
    seed.write_text(secrets.token_hex(32))
    seed.chmod(0o600)
    mandate_file = tmp_path / "mandate.json"
    now = clock_module.now()
    caller_key = SigningKey.derived(
        bytes.fromhex(seed.read_text()), crypto.ROLE_DEVICE, 0, "agent:opsbot/test"
    )
    mandate_file.write_text(
        json.dumps(
            ROOT.sign(
                {
                    "v": "stozher/0.1",
                    "kind": "mandate",
                    "mandate-kind": "standing",
                    "grantor": {"subject": ROOT.subject, "key": ROOT.id, "role": "human"},
                    "grantee": {"subject": "agent:opsbot/test", "key": caller_key.id},
                    "issued-at": clock_module.shift(now, -60),
                    "not-before": clock_module.shift(now, -60),
                    "not-after": clock_module.shift(now, 86400),
                    "parent": None,
                    "max-depth": 1,
                    "scope": {
                        "components": ["gateway"],
                        "actions": ["ops.*"],
                        "classes": ["read", "benign", "consequential", "prohibited"],
                        "resources": ["*"],
                    },
                    "nonce": secrets.token_hex(16),
                }
            )
        )
    )
    gateway: dict[str, Any] = {
        "enabled": enabled,
        "device": "test",
        "state_db": str(tmp_path / "gw.db"),
    }
    if bundle is not None:
        gateway["policy_bundle"] = str(bundle)
    return GatewayConfig.model_validate(
        {
            "gateway": gateway,
            # Nothing is listening on port 9. This is the CI container the defect was reported from.
            "kernel": {"url": "http://127.0.0.1:9"},
            "identity": {"seed_file": str(seed)},
            "org": {
                "policy_key": POLICY_KEY.id,
                "roots": [{"subject": ROOT.subject, "key": ROOT.id}],
            },
            "callers": [
                {
                    "name": "opsbot",
                    "subject": "agent:opsbot/test",
                    "mandate_file": str(mandate_file),
                    "mandate_kind": "standing",
                    "token_sha256": sha256_hex(b"opsbot-token"),
                }
            ],
        }
    )


def _bundle_body(
    *,
    exported_at: str,
    max_age: str = "P7D",
    revocations: list[dict[str, Any]] | None = None,
    anchor: Any = ANCHOR,
) -> dict[str, Any]:
    """The unsigned body `stozher-kernel policy export-bundle` assembles, in this build's shape."""
    return {
        "v": "stozher/0.1",
        "kind": "policy-bundle",
        "bundle-version": BUNDLE_VERSION,
        "exported-at": exported_at,
        "max-age": max_age,
        "policy": POLICY_KEY.sign(
            baseline_policy(
                "2026.07.1", exported_at, ROOT.subject, {"ops.tail_logs": "read"}
            )
        ),
        "revocations": revocations or [],
        "anchor": anchor,
    }


def _write(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(json.dumps(document))
    return path


def _bundle(tmp_path: Path, **kwargs: Any) -> Path:
    """A bundle signed by the enrolled root, exported one minute ago unless told otherwise."""
    kwargs.setdefault("exported_at", clock_module.shift(clock_module.now(), -60))
    return _write(tmp_path / "bundle.json", ROOT.sign(_bundle_body(**kwargs)))


@contextlib.contextmanager
def _credentials(monkeypatch: pytest.MonkeyPatch, config: GatewayConfig) -> Any:
    monkeypatch.setenv("STOZHER_GATEWAY_SEED", str(config.identity.seed_file))
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER_TOKEN", "opsbot-token")
    yield


def _governed(governor: Governor) -> tuple[Any, Any, list[str]]:
    """Two governed functions and the ledger that proves whether their bodies ran."""
    ledger: list[str] = []

    @governor.governed(server="ops", schema={"type": "object", "properties": {}})
    def tail_logs(service: str) -> str:
        ledger.append(service)
        return f"logs for {service}"

    @governor.governed(server="ops", schema={"type": "object", "properties": {}})
    def restart(service: str) -> str:  # unclassified, and therefore consequential
        ledger.append(f"restart:{service}")
        return "restarted"

    return tail_logs, restart, ledger


# -- the bootstrap ------------------------------------------------------------------------------


def test_a_cold_cache_and_no_kernel_opens_a_session_from_a_signed_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEF-4's first failing reproduction, inverted.

    Before: `PolicyProvider.current` raised `policy-not-published` when the pull failed and the cache
    was empty, and `open_session` calls it, so `Governor.__enter__` died before a single call was
    classified. The only writer of that cache was a successful pull.

    Now a root-signed bundle on disk is the other writer. The container has still never reached a
    kernel — port 9 is dead for the whole test — and the session opens, a `read` proceeds, and a
    `consequential` is blocked without reaching the function.
    """
    config = _config(tmp_path, bundle=_bundle(tmp_path))
    with _credentials(monkeypatch, config):
        governor = Governor(config)
        with governor:
            tail_logs, restart, ledger = _governed(governor)
            assert tail_logs("api") == "logs for api"
            with pytest.raises(RefusalError) as refused:
                restart("api")

    # Exported a minute ago and `max-staleness-seconds` is 300, so the policy is still fresh and the
    # consequential call reaches the gate and parks. It is refused either way — the neighbouring
    # test takes the same call past that boundary and watches `policy-stale-offline` — and what is
    # asserted here is the part that must hold in both: the body never ran.
    assert refused.value.document["result"] == "parked"
    assert refused.value.document["reason-code"] == "gate-parked"
    assert ledger == ["api"], "the consequential call never reached the function"


def test_a_bundle_older_than_max_staleness_enforces_the_offline_profile_from_the_first_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§05 §7 from cold: `{read: allow, benign: allow, consequential: block}`.

    The seeded `verified_at` is the bundle's own `exported-at`, so a component booted from a bundle
    exported longer ago than `max-staleness-seconds` (300 in the baseline policy) is **not** fresh —
    which is the truth, since it has never spoken to a kernel. `read` is still allowed because the
    policy says `offline: {read: allow}`; `consequential` is refused `policy-stale-offline` rather
    than parked, because a park is a question and there is nobody to ask.
    """
    bundle = _bundle(tmp_path, exported_at=clock_module.shift(clock_module.now(), -3600))
    config = _config(tmp_path, bundle=bundle)
    with _credentials(monkeypatch, config):
        governor = Governor(config)
        with governor:
            tail_logs, restart, ledger = _governed(governor)
            assert tail_logs("api") == "logs for api", "offline read: allow"
            with pytest.raises(RefusalError) as refused:
                restart("api")

    assert refused.value.document["result"] == "blocked"
    assert refused.value.document["reason-code"] == "policy-stale-offline"
    assert ledger == ["api"], "never proceed, never degrade"


def test_the_bundle_seeds_the_revocation_set_and_the_checkpoint_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The set is enforced offline, not merely carried.

    A revocation the operator signed goes into the same cache the live feed writes, so the gateway
    evaluates it on the hot path from the first call — the preventive half `revocation.py` exists
    for. Without this the bundle would ship a policy and silently leave the component believing
    nothing had ever been revoked, which is the one direction a bootstrap must not fail in.
    """
    revocation = ROOT.sign(
        {
            "v": "stozher/0.1",
            "kind": "revocation",
            "revokes": "b" * 64,
            "revoked-at": clock_module.shift(clock_module.now(), -120),
        }
    )
    bundle = _bundle(tmp_path, revocations=[revocation])
    config = _config(tmp_path, bundle=bundle)
    with _credentials(monkeypatch, config):
        governor = Governor(config)
        try:
            cached = governor._gateway.store.cached_revocations()
            assert cached is not None
            epoch, documents, verified_at = cached
            assert documents == [revocation]
            # The feed's epoch is the kernel's ETag and a bundle cannot know one, so it is empty
            # rather than invented: the first reconnect then pulls unconditionally instead of
            # claiming to hold a version the kernel never issued.
            assert epoch == ""
            policy = governor._gateway.store.cached_policy()
            assert policy is not None and policy[0]["policy-version"] == "2026.07.1"
            assert governor._gateway.store.marked(
                f"policy-bundle:{object_id(json.loads(bundle.read_text()))}"
            ), "the store records which bundle it was seeded from"
        finally:
            governor.close(timeout=1.0)


# -- the control --------------------------------------------------------------------------------


def test_the_offline_profile_is_implemented_and_works_from_a_warm_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEF-4's control, unchanged in substance. It passed while the defect was open and it passes now.

    With one verified policy in the local cache and the kernel unreachable, a `read` proceeds and is
    folded, and a `consequential` parks locally and says the queue never saw it. That is §05 §7
    working as written, with no bundle involved at all. It is kept because it is the evidence for
    the missing-versus-misdesigned split: what CI lacked was a way to *get* that cached document,
    not an offline mode — and if a future change to the bundle path were to become the only way the
    offline profile works, this is the test that would notice.
    """
    config = _config(tmp_path)
    with _credentials(monkeypatch, config):
        governor = Governor(config)
        now = governor._gateway._clock.now()
        governor._gateway.store.cache_policy(
            "2026.07.1",
            POLICY_KEY.sign(
                baseline_policy("2026.07.1", now, ROOT.subject, {"ops.tail_logs": "read"})
            ),
            now,
        )
        with governor:
            tail_logs, restart, ledger = _governed(governor)
            assert tail_logs("api") == "logs for api", "a cached read profile allows a read offline"
            with pytest.raises(RefusalError) as refused:
                restart("api")

    document = refused.value.document
    assert document["result"] == "parked"
    assert document["reason-code"] == "gate-parked"
    # The integrator's verbatim first-call message. It is not a bug: the park is durable locally and
    # says truthfully that no human can see it yet (`enforce.py::_gate`, "held locally").
    assert "held locally" in document["hint"]
    assert ledger == ["api"], "the consequential call never reached the function"


# -- what the bundle path refuses ----------------------------------------------------------------


def _refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bundle: Path) -> str:
    """Build a Governor on `bundle` and return the refusal. Asserts the cache stayed empty."""
    config = _config(tmp_path, bundle=bundle)
    with _credentials(monkeypatch, config), pytest.raises(StartupRefusedError) as refused:
        Governor(config)
    # An unverified bundle is refused, *never cached*. The store was created by the refused
    # construction, so this reads the file the run would have enforced from.
    assert GatewayStore(config.state_db_path()).cached_policy() is None, (
        "a bundle that was refused left a policy behind; the next start would enforce it"
    )
    return str(refused.value)


def test_a_flipped_byte_in_the_policy_is_refused_rather_than_started_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counterfactual that matters: edit the policy inside a signed bundle.

    `github.delete_repo` is `prohibited` in the baseline. Rewriting it to `read` is the whole attack
    in one word — and the bundle is one signed object, so the edit invalidates the root's signature
    over the entire body rather than over some separately-checked half.
    """
    document = ROOT.sign(_bundle_body(exported_at=clock_module.shift(clock_module.now(), -60)))
    document["policy"]["classification"]["by-action"]["github.delete_repo"] = "read"
    message = _refused(tmp_path, monkeypatch, _write(tmp_path / "tampered.json", document))
    assert "bundle-sig-invalid" in message


def test_a_flipped_byte_in_the_signature_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = ROOT.sign(_bundle_body(exported_at=clock_module.shift(clock_module.now(), -60)))
    value = document["sig"]["value"]
    # One hex digit, in the signature itself rather than in what it covers.
    document["sig"]["value"] = ("1" if value[0] != "1" else "2") + value[1:]
    message = _refused(tmp_path, monkeypatch, _write(tmp_path / "tampered.json", document))
    assert "bundle-sig-invalid" in message


def test_an_edited_max_age_is_refused_because_it_is_inside_the_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whoever holds the file cannot extend its life.

    `max-age` is a member of the signed body precisely so that the answer to "how long may this be
    enforced" comes from the root that exported it and not from the machine that stores it. Editing
    it is the same failure as editing the policy.
    """
    document = ROOT.sign(_bundle_body(exported_at=clock_module.shift(clock_module.now(), -60)))
    document["max-age"] = "P3650D"
    message = _refused(tmp_path, monkeypatch, _write(tmp_path / "tampered.json", document))
    assert "bundle-sig-invalid" in message


def test_an_expired_bundle_refuses_to_start_rather_than_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bounded staleness, enforced as a refusal.

    Exported eight days ago with a seven-day `max-age`. A warning here would be a line in a CI log
    nobody reads while a component enforced a policy nobody can vouch for any more.
    """
    bundle = _bundle(
        tmp_path, exported_at=clock_module.shift(clock_module.now(), -8 * 86400), max_age="P7D"
    )
    message = _refused(tmp_path, monkeypatch, bundle)
    assert "bundle-expired" in message


def test_a_bundle_signed_by_a_key_nobody_enrolled_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid Ed25519 signature by a stranger is a valid signature by a stranger."""
    document = STRANGER.sign(_bundle_body(exported_at=clock_module.shift(clock_module.now(), -60)))
    message = _refused(tmp_path, monkeypatch, _write(tmp_path / "stranger.json", document))
    assert "bundle-signer-not-a-root" in message


def test_a_policy_signed_by_the_wrong_key_is_refused_even_inside_a_valid_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The root's signature does not stand in for the organization's policy key.

    Both signatures are checked, independently and for different things: the root vouches that this
    is the set it exported, the policy key makes the document a policy at all. Collapsing the two
    would let any enrolled root publish policy by wrapping it in a bundle, bypassing §05 §5's
    ceremony entirely.
    """
    body = _bundle_body(exported_at=clock_module.shift(clock_module.now(), -60))
    body["policy"] = ROOT.sign(
        baseline_policy("2026.07.1", body["exported-at"], ROOT.subject, {"ops.tail_logs": "read"})
    )
    message = _refused(tmp_path, monkeypatch, _write(tmp_path / "wrong-key.json", ROOT.sign(body)))
    assert "policy-sig-invalid" in message


def test_a_revocation_that_does_not_verify_refuses_the_whole_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unlike the live feed, which drops one and keeps going — and for a stated reason.

    A feed entry arrives on its own and dropping it can only ever miss a refusal. A bundle entry
    arrives inside a set a root signed as a set, so one that does not verify means the set is not
    the one anybody vouched for.
    """
    revocation = ROOT.sign(
        {
            "v": "stozher/0.1",
            "kind": "revocation",
            "revokes": "b" * 64,
            "revoked-at": clock_module.shift(clock_module.now(), -120),
        }
    )
    revocation["revokes"] = "c" * 64  # after signing, so the revocation's own signature is stale
    bundle = _bundle(tmp_path, revocations=[revocation])
    message = _refused(tmp_path, monkeypatch, bundle)
    assert "bundle-revocation-sig-invalid" in message


def test_a_bundle_with_no_anchor_member_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """"We exported no checkpoint" and "we did not say" must not look the same.

    An explicit `"anchor": null` is a statement a root signed. A missing member is a bundle built by
    something that does not know about anchors, and this build cannot tell which.
    """
    body = _bundle_body(exported_at=clock_module.shift(clock_module.now(), -60))
    del body["anchor"]
    message = _refused(tmp_path, monkeypatch, _write(tmp_path / "no-anchor.json", ROOT.sign(body)))
    assert "bundle-missing-member: anchor" in message


def test_an_unknown_bundle_version_is_refused_rather_than_read_optimistically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = _bundle_body(exported_at=clock_module.shift(clock_module.now(), -60))
    body["bundle-version"] = BUNDLE_VERSION + 1
    message = _refused(tmp_path, monkeypatch, _write(tmp_path / "future.json", ROOT.sign(body)))
    assert "bundle-version-unsupported" in message


def test_a_named_bundle_that_is_not_there_refuses_to_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Naming a bundle is a declaration that this deployment may have to enforce without a kernel.

    Starting anyway would put the component back in exactly the state the defect describes, with an
    empty cache and a `policy-not-published` at the first call — but now with a configuration line
    that says it was handled.
    """
    message = _refused(tmp_path, monkeypatch, tmp_path / "absent.json")
    assert "bundle-unreadable" in message


# -- `[gateway] enabled` --------------------------------------------------------------------------


def test_enabled_false_refuses_to_build_a_governor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEF-4's third reproduction, and the ruling it forced.

    Before: `plugin.register` was the only reader of the flag, so a `Governor` built from a
    configuration with `enabled = false` opened a session and gated every call — a key that silently
    means nothing on the path you are using, which reads as an answer.

    The ruling is that the flag governs both paths, and that on this path it can only mean *refuse*.
    The alternative reading — run the decorated functions ungoverned — is a gate disabled by editing
    a config key, and this test is what stops a future change from choosing it: a `Governor` that
    could be built here would be one that runs somebody's `issue_refund` with nothing in front of it.
    """
    config = _config(tmp_path, enabled=False)
    with _credentials(monkeypatch, config), pytest.raises(StartupRefusedError) as refused:
        Governor(config)
    assert "enabled is false" in str(refused.value)


def test_enabled_true_is_still_all_that_is_needed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The paired positive, so the refusal above cannot be satisfied by refusing everything."""
    config = _config(tmp_path, bundle=_bundle(tmp_path))
    with _credentials(monkeypatch, config):
        governor = Governor(config)
        with contextlib.suppress(Exception):
            governor.close(timeout=1.0)

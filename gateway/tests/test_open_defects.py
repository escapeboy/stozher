"""Executable reproductions of defects that are **open**. Quarantined, not skipped.

Every test here is marked `open_defect` and is excluded from the default run (`pyproject.toml`,
`addopts`). Run them with:

    python3 -m pytest gateway/tests -q -m open_defect

They assert the behaviour the design requires, so while a defect is open its test fails and the
failure message carries the observed values. That is the point: the day the defect is fixed, this
file goes green and says so, which is a thing a bug report cannot do.

Nothing here weakens a gate. Each test either observes what the shipped chokepoint does or opens a
session against a kernel that is not there.
"""

from __future__ import annotations

import contextlib
import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module, crypto
from stozher_gateway.canonical import sha256_hex
from stozher_gateway.config import GatewayConfig
from stozher_gateway.governed import Governor
from stozher_gateway.policy import PolicyError
from stozher_gateway.refusal import RefusalError
from stozher_gateway.signing import SigningKey

from .support import baseline_policy
from .test_enforcement import Harness

pytestmark = pytest.mark.open_defect

ROOT = SigningKey(bytes.fromhex("31" * 32), "human:ivan")
POLICY_KEY = SigningKey(bytes.fromhex("33" * 32), "org:policy")


# -- DEF-1: replaying a run duplicates the approval queue ----------------------------------------


def test_def1_a_repeated_identical_call_parks_a_second_request(tmp_path: Path) -> None:
    """DEF-1. Two identical calls, the first still undecided, mint two pending requests.

    Observed (2026-08-03, a nightly job re-run at 04:00 over the 03:00 queue): the same
    `(subject, key, component, mandate-ref, policy-version, classification, action, target,
    args-hash)` parks again with a new `request-hash`, because `gate.action_request` mints a fresh
    128-bit `nonce` per park (`gate.py:87-105`) and the local lookup that could have found the first
    one only matches rows that already carry a decision (`store.py:331-348`,
    `enforce.py:630-643`). Two runs left 54 undecided requests and 20 `(action, args-hash)` pairs
    appearing more than once.

    Expected: a second identical call, made while the first request is still pending and still
    inside its `not-after`, resolves to that request. One human question per pending call — the
    approver's queue must not grow with the number of times an agent was restarted.
    """
    harness = Harness(tmp_path)
    hashes = []
    for _ in range(2):
        with pytest.raises(RefusalError) as refused:
            harness.call("create_issue", title="ship it")
        assert refused.value.document["reason-code"] == "gate-parked"
        hashes.append(refused.value.document["request-hash"])

    pending = harness.store.pending()
    assert hashes[0] == hashes[1], (
        f"the second identical call minted a new action request: {hashes[0]} then {hashes[1]}, "
        f"leaving {len(pending)} requests queued for one call a human has not answered yet"
    )


def test_def1_the_pending_request_is_invisible_to_the_lookup_that_would_reuse_it(
    tmp_path: Path,
) -> None:
    """DEF-1, the exact break: `decided_for` cannot see an *undecided* park.

    Observed: `GatewayStore.decided_for` selects `WHERE decision_json IS NOT NULL`
    (`store.py:341`), so the only question `Enforcer._gate` asks before building a new request
    (`enforce.py:631`) is "is there an answer already?", never "is there an outstanding question
    already?". The identity fields it matches on are the right ones; the row it needs is filtered
    out before they are compared.

    Expected: something the gate consults before minting a request must find the pending row whose
    request describes exactly this call.
    """
    harness = Harness(tmp_path)
    with pytest.raises(RefusalError):
        harness.call("create_issue", title="ship it")

    parked = harness.store.pending()
    assert len(parked) == 1
    request = parked[0].request
    fields = {
        name: request[name]
        for name in (
            "subject",
            "key",
            "component",
            "mandate-ref",
            "policy-version",
            "classification",
            "action",
            "target",
            "args-hash",
        )
    }
    assert harness.store.decided_for(fields) is not None, (
        "a request that is queued and unanswered is not findable by the fields that identify it; "
        f"the row exists ({parked[0].request_hash}) and the lookup skips it for want of a decision"
    )


# -- DEF-4: no offline mode for CI ---------------------------------------------------------------


def _config(tmp_path: Path, *, enabled: bool = True) -> tuple[GatewayConfig, SigningKey, Path]:
    """The configuration an integrator writes, and the caller key it implies."""
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
    config = GatewayConfig.model_validate(
        {
            "gateway": {
                "enabled": enabled,
                "device": "test",
                "state_db": str(tmp_path / "gw.db"),
            },
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
    return config, caller_key, seed


@pytest.fixture()
def offline_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    config, _, seed = _config(tmp_path)
    monkeypatch.setenv("STOZHER_GATEWAY_SEED", str(seed))
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER_TOKEN", "opsbot-token")
    return config


def test_def4_a_cold_cache_and_no_kernel_cannot_open_a_session_at_all(offline_env: Any) -> None:
    """DEF-4. In a fresh CI container `Governor.__enter__` dies before any call is made.

    Observed: `PolicyProvider.current` raises `policy-not-published` when the pull fails and the
    cache is empty (`runtime.py:71-88`), and `open_session` calls it while recording the session
    open (`runtime.py:341`). So the context manager itself raises: not one governed call is
    classified, and the offline profile — `{read: allow, benign: allow, consequential: block}`,
    §05 §7 — never gets to apply, because §05 §7 governs a *cached* policy and there is none.

    Expected: an integrator can run their agent's test suite against a policy they can obtain
    without a live kernel — a seeded cache, a signed document on disk, or a documented CI recipe.
    "Everything works offline" (§00 maxim 5, `docs/design/enforcement-topology.md` §Offline) has to
    include the first run on a machine that has never been online.
    """
    governor = Governor(offline_env)
    try:
        with pytest.raises(PolicyError) as refused:
            governor.open()
        assert refused.value.code == "policy-not-published"
    finally:
        with contextlib.suppress(Exception):
            governor.close(timeout=1.0)
    pytest.fail(
        "a cold cache with no kernel refuses to open a session at all: "
        f"{refused.value.code} — there is no offline path in for a container that has never "
        "reached the kernel"
    )


def test_def4_the_offline_profile_is_implemented_and_works_from_a_warm_cache(
    offline_env: Any,
) -> None:
    """DEF-4, the control. This one **passes**: offline enforcement is not missing.

    With one verified policy in the local cache and the kernel still unreachable, a `read` proceeds
    and is folded, and a `consequential` parks locally and says the queue never saw it. That is
    §05 §7 working as written. It is the evidence for the missing-versus-misdesigned split: what CI
    lacks is a way to *get* that cached document, not an offline mode.
    """
    governor = Governor(offline_env)
    now = governor._gateway._clock.now()
    governor._gateway.store.cache_policy(
        "2026.07.1",
        POLICY_KEY.sign(baseline_policy("2026.07.1", now, ROOT.subject, {"ops.tail_logs": "read"})),
        now,
    )
    ledger: list[str] = []
    with governor:

        @governor.governed(server="ops", schema={"type": "object", "properties": {}})
        def tail_logs(service: str) -> str:
            ledger.append(service)
            return f"logs for {service}"

        @governor.governed(server="ops", schema={"type": "object", "properties": {}})
        def restart(service: str) -> str:  # unclassified and consequential
            ledger.append(f"restart:{service}")
            return "restarted"

        assert tail_logs("api") == "logs for api", "a cached read profile allows a read offline"
        with pytest.raises(RefusalError) as refused:
            restart("api")

    document = refused.value.document
    assert document["result"] == "parked"
    assert document["reason-code"] == "gate-parked"
    # The integrator's verbatim first-call message. It is not a bug: the park is durable locally and
    # says truthfully that no human can see it yet (`enforce.py:689-693`).
    assert "held locally" in document["hint"]
    assert ledger == ["api"], "the consequential call never reached the function"


def test_def4_enabled_false_neither_disables_the_session_nor_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEF-4. `[gateway] enabled = false` is read by the MCP plugin only, never by `Governor`.

    Observed: `plugin.register` returns early when the flag is false (`plugin.py:58-63`), and that
    is the only reader of it. `Governor.__init__` builds a `Gateway` unconditionally
    (`governed.py:57-59`), so with `enabled = false` the session still opens, the decorator still
    routes through `Enforcer.call`, and the call is still gated — the integrator's "session opened
    anyway, call still gated".

    Expected: either the flag governs the in-process path too, or it is documented as the MCP
    server's switch and `Governor` names its own. A configuration key that silently means nothing
    on the path you are using is worse than one that is absent, because it reads as an answer.
    """
    config, _, seed = _config(tmp_path, enabled=False)
    monkeypatch.setenv("STOZHER_GATEWAY_SEED", str(seed))
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER_TOKEN", "opsbot-token")
    governor = Governor(config)
    now = governor._gateway._clock.now()
    governor._gateway.store.cache_policy(
        "2026.07.1",
        POLICY_KEY.sign(baseline_policy("2026.07.1", now, ROOT.subject, {"ops.tail_logs": "read"})),
        now,
    )
    opened = False
    try:
        with governor:
            opened = True

            @governor.governed(server="ops", schema={"type": "object", "properties": {}})
            def restart(service: str) -> str:
                return "restarted"

            with pytest.raises(RefusalError) as refused:
                restart("api")
    finally:
        with contextlib.suppress(Exception):
            governor.close(timeout=1.0)

    assert not opened, (
        "a Governor built from a configuration with `enabled = false` opened a session and then "
        f"refused the call {refused.value.document['reason-code']}"
    )

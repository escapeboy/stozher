"""DEF-2 — a mandate swap silently kills the audit trail.

An evaluation replaced a caller's mandate file and restarted the gateway. The gateway resolved the
new mandate the only way it knows how — it read the file, checked the grantee key, the kind and the
expiry — and served tools for a week. The kernel refused every envelope of that week
(`mandate-unresolved`), the stream never advanced, and nothing anywhere told the agent, the caller or
the operator. The only signal was a console row reading `7d — quiet`.

**What this file reproduces.** The gateway publishes its session mandate at connect time
(`runtime.py::_publish_mandate`), so the ordinary swap works. The defect appears whenever the
kernel refuses the *grant* — for any reason. The trigger used here is the one asymmetry that needs
no tampering to reach: `spec/03 §3` bounds a `standing` mandate's lifetime by the policy's
`delegation.max-standing-lifetime`, the kernel enforces that ceiling at ingest
(`mandate-standing-lifetime-exceeded`), and the gateway's own `verify_mandate_chain` — a faithful
implementation of the §03 §5 algorithm, which does not contain the ceiling — does not. So a human
who signs a longer-lived replacement and drops it in place produces exactly the observed state: the
gateway accepts the mandate, the kernel accepts nothing that cites it, and the calls keep flowing.

The trigger is incidental. Any kernel-side refusal of the grant lands in the same place, because the
gateway's push loop treats a refusal as terminal for those bytes and then carries on
(`emitter.py::push_pending`).

The two tests marked `open_defect` assert the behaviour the design requires, so they fail while the
defect is open; they are excluded from the default run and are run with
`python3 -m pytest gateway/tests -q -m open_defect`.
`test_a_published_mandate_still_reaches_the_kernel` is deliberately *not* quarantined: it is the
counterfactual, it runs in the default suite, and it proves this harness lets a legitimate session
through — so a failure in the two below is the defect rather than a broken fixture.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.config import load_config_file
from stozher_gateway.enforce import Call
from stozher_gateway.runtime import Gateway

from .support import Kernel, gateway_config_file

#: An upstream call that would really have happened. The gateway returns it unchanged when it lets
#: a call through, so seeing it come back *is* "the gateway served this call".
APPLIED = "upstream-applied"


def _standing_mandate(kernel: Kernel, *, days: int) -> dict[str, Any]:
    """A root-signed standing mandate for the gateway's device key, of the given lifetime."""
    now = clock_module.now()
    return kernel.human_root.sign(
        {
            "v": "stozher/0.1",
            "kind": "mandate",
            "mandate-kind": "standing",
            "grantor": {
                "subject": kernel.human_root.subject,
                "key": kernel.human_root.id,
                "role": "human",
            },
            "grantee": {"subject": kernel.gateway_key.subject, "key": kernel.gateway_key.id},
            "issued-at": clock_module.shift(now, -60),
            "not-before": clock_module.shift(now, -60),
            "not-after": clock_module.shift(now, days * 86400),
            "parent": None,
            "max-depth": 1,
            "scope": {
                "components": ["gateway"],
                "actions": ["github.*", "gateway.*", "kernel.*", "harbormaster.*"],
                "classes": ["read", "benign", "consequential", "prohibited"],
                "resources": ["*"],
            },
            "nonce": secrets.token_hex(16),
        }
    )


class World:
    """A live kernel, a gateway configuration, and the mandate file the caller is pointed at."""

    def __init__(self, root: Path, kernel: Kernel, config: Path, mandate_file: Path) -> None:
        self.root = root
        self.kernel = kernel
        self.config = config
        self.mandate_file = mandate_file

    def gateway(self) -> Gateway:
        """A gateway process's worth of state, over the mandate file as it stands right now."""
        return Gateway(load_config_file(self.config))


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("def2")
    seed_file = root / "gateway.seed"
    seed_file.write_text("aa" * 32)
    seed_file.chmod(0o600)

    kernel = Kernel(root, bytes.fromhex("aa" * 32), "agent:claude-code/test-mbp")
    kernel.start()
    try:
        mandate_file = root / "mandate.json"
        mandate_file.write_text(json.dumps(kernel.gateway_mandate))
        config = gateway_config_file(
            root, kernel, seed_file, mandate_file, [sys.executable, "-c", "pass"]
        )
        yield World(root, kernel, config, mandate_file)
    finally:
        kernel.stop()


@pytest.fixture()
def environment(world: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """One gateway state database per test, so no test inherits another's chain position."""
    monkeypatch.setenv("STOZHER_GATEWAY_CONFIG", str(world.config))
    monkeypatch.setenv("STOZHER_GATEWAY_DB", str(tmp_path / "gateway.db"))
    monkeypatch.setenv("STOZHER_GATEWAY_SEED", str(world.root / "gateway.seed"))
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER", "claude-code")
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER_TOKEN", "caller-token")
    monkeypatch.setenv("STOZHER_KERNEL_TOKEN", world.kernel.token)


def _serve_one_read(gateway: Gateway, session: Any) -> Any:
    """Put one governed `read` through the gateway and get its envelopes offered to the kernel."""
    result = gateway.enforcer.call(
        session, Call("github", "get_file", {"path": "README.md"}, None), lambda: APPLIED
    )
    gateway.emitter.flush_windows()
    gateway.emitter.push_pending()
    return result


def test_a_published_mandate_still_reaches_the_kernel(world: World, environment: None) -> None:
    """The counterfactual. Nothing here refuses everything: under the mandate the ceremony granted,
    the gateway serves the call *and* the kernel takes the record. If this ever fails, the two tests
    below are measuring a broken fixture rather than the defect."""
    world.mandate_file.write_text(json.dumps(world.kernel.gateway_mandate))
    gateway = world.gateway()
    session = gateway.open_session()
    gateway.emitter.push_pending()

    assert _serve_one_read(gateway, session) == APPLIED
    count, _ = world.kernel.head(session.stream)
    assert count > 0, "the kernel accepted nothing from a session it should have accepted"
    assert gateway.emitter.pending_push_count() == 0


@pytest.mark.open_defect
def test_the_gateway_stops_serving_once_the_kernel_refuses_its_mandate(
    world: World, environment: None
) -> None:
    """The defect, in one sentence: the kernel has refused this session's mandate grant and every
    envelope citing it, and the next tool call is still served as if nothing happened.

    ADR-0001 requires every effect to happen under a *traceable* mandate. Here the mandate resolves
    only inside the process that benefits from it: the audit the organization actually queries has
    no record of the week, and the caller was never told that the record it was promised does not
    exist.
    """
    world.mandate_file.write_text(json.dumps(_standing_mandate(world.kernel, days=180)))
    gateway = world.gateway()
    session = gateway.open_session()
    gateway.emitter.push_pending()

    # The kernel refused the grant, so nothing on this stream has been accepted.
    count, _ = world.kernel.head(session.stream)
    assert count == 0, "the fixture failed to produce the refused-grant state"
    _, rejections = world.kernel.request("GET", "/v1/rejections?limit=20")
    reasons = {rejection["reason"] for rejection in rejections["rejections"]}
    assert "mandate-standing-lifetime-exceeded" in reasons

    # And yet: the gateway serves, and every envelope it emits is refused `mandate-unresolved`.
    result = _serve_one_read(gateway, session)
    _, rejections = world.kernel.request("GET", "/v1/rejections?limit=20")
    assert "mandate-unresolved" in {r["reason"] for r in rejections["rejections"]}
    count, _ = world.kernel.head(session.stream)
    assert count == 0

    assert result != APPLIED, (
        "DEF-2: the gateway forwarded a call and returned the upstream result while the kernel was "
        "refusing every envelope it emitted; the caller has no way to know the effect is unaudited"
    )


@pytest.mark.open_defect
def test_the_kernels_refusal_survives_somewhere_the_gateway_can_be_asked(
    world: World, environment: None
) -> None:
    """The other half of "silent": even an operator who goes looking cannot find it.

    `emitter.py::push_pending` writes the refusal into `envelopes.push_error` and then calls
    `mark_pushed`, whose UPDATE sets `push_error = NULL` (`store.py::mark_pushed`). The reason code
    the kernel gave exists for the duration of one statement. Afterwards the row is indistinguishable
    from an accepted one, `pending_push_count()` is 0, and the gateway's own state says the push
    queue is healthy. The only trace is a line on stderr.
    """
    world.mandate_file.write_text(json.dumps(_standing_mandate(world.kernel, days=180)))
    gateway = world.gateway()
    session = gateway.open_session()
    gateway.emitter.push_pending()
    _serve_one_read(gateway, session)

    with gateway.store._connect() as connection:  # noqa: SLF001 - reading the store's own record
        errors = [
            row["push_error"]
            for row in connection.execute(
                "SELECT push_error FROM envelopes WHERE stream = ?", (session.stream,)
            ).fetchall()
        ]

    assert any(error and "mandate-unresolved" in error for error in errors), (
        "DEF-2: no row of the local chain records that the kernel refused it, so nothing the "
        "gateway can be asked distinguishes a synced stream from a rejected one"
    )

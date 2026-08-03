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
gateway's push loop treated a refusal as terminal for those bytes and then carried on
(`emitter.py::push_pending`).

**Closed by `spec/05 §7.1`, `spec/09 §4.2`, `spec/10 §1.4` and `spec/04 §7.2`.** These tests are no
longer quarantined; they assert the behaviour the specification now requires. Two assertions moved
when the defect closed, and both moved because the state they described stopped being reachable:

* the calls are refused rather than served, so `_serve_one_read` returns the §06 §4.1 refusal object
  instead of the upstream result;
* nothing is submitted past a wedge (§05 §7.1 clause 3), so the later envelopes of that session no
  longer arrive at the kernel to be rejected `mandate-unresolved` one after another. The test asks
  instead for what the fix is *for*: the kernel's own reason code reaching the caller, the stream
  head unmoved, and the rest of the chain still held locally rather than marked delivered.

`test_a_published_mandate_still_reaches_the_kernel` is the counterfactual and always was: it proves
this harness lets a legitimate session through, so a failure in the two below is the defect rather
than a broken fixture.
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
from stozher_gateway.emitter import Emitter
from stozher_gateway.enforce import Call
from stozher_gateway.kernel_client import KernelResponse
from stozher_gateway.refusal import RefusalError
from stozher_gateway.runtime import Gateway
from stozher_gateway.signing import SigningKey
from stozher_gateway.store import GatewayStore

from .support import Kernel, gateway_config_file

#: An upstream call that would really have happened. The gateway returns it unchanged when it lets
#: a call through, so seeing it come back *is* "the gateway served this call".
APPLIED = "upstream-applied"

#: The stream every gateway in this module writes: `gw:<device>:<caller>` from the configuration
#: `support.gateway_config_file` writes. Named here because the kernel is module-scoped and the
#: tests below need the head *before* they open a session — a session now offers its mandate at
#: connect (§10 §1.4), so measuring afterwards would measure the thing under test.
STREAM = "gw:test-mbp:claude-code"


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
    """Put one governed `read` through the gateway and get its envelopes offered to the kernel.

    Returns the upstream result when the call was served, and the §06 §4.1 refusal object when it
    was not — the two things a caller can actually receive. A refusal is raised, which is what marks
    the MCP result as an error (`refusal.py`), so a helper that let it propagate would fail the test
    that is asking whether the gateway refuses.
    """
    try:
        result = gateway.enforcer.call(
            session, Call("github", "get_file", {"path": "README.md"}, None), lambda: APPLIED
        )
    except RefusalError as refused:
        result = refused.document
    gateway.emitter.flush_windows()
    gateway.emitter.push_pending()
    return result


class _CannotAnswer:
    """A kernel that answers the socket and says nothing about the bytes.

    Byte-for-byte what `http.rs` returns for `ingest::Outcome::Unavailable`: HTTP 503, the
    non-normative `x-store-unavailable`, and a `reason` that says *retry*.
    """

    def __init__(self, status: int = 503, code: str = "x-store-unavailable") -> None:
        self.status = status
        self.code = code
        self.calls = 0

    def ingest(self, envelope: Any, payloads: Any) -> KernelResponse:
        self.calls += 1
        return KernelResponse(
            self.status,
            {
                "stozher": "stozher/0.1",
                "reason-code": self.code,
                "reason": "the kernel could not answer; retry",
            },
        )


def _one_envelope(emitter: Emitter, key: SigningKey, stream: str) -> None:
    emitter.append(
        key,
        stream,
        {
            "v": "stozher/0.1",
            "kind": "effect",
            "emitted-at": clock_module.now(),
            "identity": {"subject": key.subject, "key": key.id, "component": "gateway"},
            "mandate-ref": "11" * 32,
            "policy-version": "2026.07.1",
            "classification": "read",
            "execution": {
                "action": "github.get_file",
                "target": "mcp:github",
                "args-hash": "cc" * 32,
                "outcome": "applied",
                "started-at": clock_module.now(),
                "finished-at": clock_module.now(),
            },
        },
    )


@pytest.mark.parametrize(
    ("status", "code"),
    [(503, "x-store-unavailable"), (401, "x-caller-unauthenticated")],
)
def test_a_kernel_that_could_not_answer_does_not_wedge_the_stream(status: int, code: str) -> None:
    """§05 §7.1 clause 1, in the direction that is not obvious.

    A refusal is the kernel answering **about the bytes submitted** — §04 §7, with a reason code
    this specification names. `503 x-store-unavailable` is the kernel saying it judged nothing, and
    `401 x-caller-unauthenticated` is there being no subject to judge it for; both arrive as HTTP
    answers, and both are `unreachable`.

    This is a regression test with a scar. The first implementation of the wedge keyed on
    `KernelResponse.accepted`, which is false for every status outside `(200, 201)` — so one 503
    from a busy store wedged the stream permanently, refused every `consequential` call outright
    instead of parking it, and could never clear itself, because a wedged stream is one this
    component stops submitting on. A momentary blip became a stop only a root-signed §04 §7.2
    resume could lift: exactly the denial-of-service failure the bounded grace window exists to
    avoid, reintroduced one layer down where the decision function could not see it.
    """
    store = GatewayStore(Path(":memory:"))
    kernel = _CannotAnswer(status, code)
    emitter = Emitter(store, kernel, "gateway")
    key = SigningKey(bytes.fromhex("aa" * 32), "agent:probe")
    stream = "gw:probe:0001"
    _one_envelope(emitter, key, stream)
    _one_envelope(emitter, key, stream)

    emitter.push_pending()
    assert store.wedge(stream) is None, (
        f"a {status} {code} wedged the stream; the kernel said nothing about these bytes, so this "
        "is §05 §7.1's `unreachable` and the component must retry rather than stop"
    )
    assert store.pending_push_count() == 2, "the envelopes were marked delivered to nobody"

    # And the kernel recovering is enough: no operator act, no restart.
    emitter.push_pending()
    assert kernel.calls > 1, "the component stopped offering the envelope it never got an answer on"


def test_a_kernel_that_refused_the_object_still_wedges_the_stream() -> None:
    """The control for the test above, and the reason it is not simply "never wedge".

    A `422` carrying a normative reason code *is* the kernel answering about these bytes. It must
    still stop the stream — otherwise the two tests above this file exists for would pass with the
    wedge removed entirely.
    """
    store = GatewayStore(Path(":memory:"))
    kernel = _CannotAnswer(422, "mandate-unresolved")
    emitter = Emitter(store, kernel, "gateway")
    key = SigningKey(bytes.fromhex("aa" * 32), "agent:probe")
    stream = "gw:probe:0002"
    _one_envelope(emitter, key, stream)

    emitter.push_pending()
    wedge = store.wedge(stream)
    assert wedge is not None
    assert wedge.reason_code == "mandate-unresolved"


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


def test_the_gateway_stops_serving_once_the_kernel_refuses_its_mandate(
    world: World, environment: None
) -> None:
    """The defect, in one sentence: the kernel has refused this session's mandate grant and every
    envelope citing it, and the next tool call was still served as if nothing happened.

    ADR-0001 requires every effect to happen under a *traceable* mandate. The mandate resolved only
    inside the process that benefits from it: the audit the organization actually queries had no
    record of the week, and the caller was never told that the record it was promised does not
    exist. §05 §7.1 clause 4 now refuses every class under a `mandate-*` reason — `read` included,
    because a read without authority is still an effect — and clause 5 makes the caller's answer the
    kernel's own reason code.
    """
    world.mandate_file.write_text(json.dumps(_standing_mandate(world.kernel, days=180)))
    before, _ = world.kernel.head(STREAM)
    gateway = world.gateway()
    session = gateway.open_session()
    gateway.emitter.push_pending()

    # The kernel refused the grant, so nothing this session emits has been accepted.
    count, _ = world.kernel.head(session.stream)
    assert count == before, "the fixture failed to produce the refused-grant state"
    _, rejections = world.kernel.request("GET", "/v1/rejections?limit=20")
    reasons = {rejection["reason"] for rejection in rejections["rejections"]}
    assert "mandate-standing-lifetime-exceeded" in reasons

    result = _serve_one_read(gateway, session)

    assert result != APPLIED, (
        "DEF-2: the gateway forwarded a call and returned the upstream result while the kernel was "
        "refusing every envelope it emitted; the caller has no way to know the effect is unaudited"
    )
    # The caller is told, in the §06 §4.1 shape, carrying the kernel's reason code verbatim.
    assert result["result"] == "blocked"
    assert result["reason-code"] == "mandate-standing-lifetime-exceeded"

    # And nothing was submitted past the wedge: the head has not moved, and the envelopes emitted
    # after the refusal are still held locally rather than marked delivered (§05 §7.1 clause 3).
    count, _ = world.kernel.head(session.stream)
    assert count == before
    assert gateway.emitter.pending_push_count() > 0


def test_the_kernels_refusal_survives_somewhere_the_gateway_can_be_asked(
    world: World, environment: None
) -> None:
    """The other half of "silent": even an operator who goes looking could not find it.

    `emitter.py::push_pending` wrote the refusal into `envelopes.push_error` and then called
    `mark_pushed`, whose UPDATE was `SET pushed_at = ?, push_error = NULL`
    (`store.py::mark_pushed`). The reason code the kernel gave existed for the duration of one
    statement. Afterwards the row was indistinguishable from an accepted one, `pending_push_count()`
    was 0, and the gateway's own state said the push queue was healthy. The only trace was a line on
    stderr. §05 §7.1 clause 2 now forbids erasing the reason on any later transition of the row.
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

    assert any(
        error and "mandate-standing-lifetime-exceeded" in error for error in errors
    ), (
        "DEF-2: no row of the local chain records that the kernel refused it, so nothing the "
        "gateway can be asked distinguishes a synced stream from a rejected one"
    )
    # And the same fact is answerable without reading the chain row by row: the wedge is the
    # component's own account of "is anything I emit reaching the audit".
    wedge = gateway.store.wedge(session.stream)
    assert wedge is not None
    assert wedge.reason_code == "mandate-standing-lifetime-exceeded"
    assert gateway.store.refused_push_count() == 1

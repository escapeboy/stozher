"""`@governor.governed` — the integrator's rejection, answered.

An engineer with a working Python agent system evaluated this product and rejected it: their tools
were plain functions, the only way in was to re-expose all of them as an MCP server, the adaptation
layer came to 134 lines against a 123-line application, and their tool state had to leave their
process. Their driver's own assertions then read an empty ledger.

The subprocess was never buying a security property. The gateway holds one private key — its own
emitter seed — and `org.roots` holds public key ids; the approving key is on a human's machine
either way, and the gateway process is spawned by the agent's own MCP client as the same user on
the same host. What these tests hold is that the in-process path is the *same* enforcement, not a
lighter one: same classification, same gate, same envelopes, same refusal, and the state stays put.
"""

from __future__ import annotations

import contextlib
import secrets
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import object_hash, sha256_hex
from stozher_gateway.config import GatewayConfig
from stozher_gateway.governed import Governor
from stozher_gateway.refusal import RefusalError
from stozher_gateway.signing import SigningKey, object_id

from .support import baseline_policy

ROOT = SigningKey(bytes.fromhex("21" * 32), "human:ivan")
POLICY_KEY = SigningKey(bytes.fromhex("23" * 32), "org:policy")


@pytest.fixture
def governor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: Any) -> Any:
    """A Governor over a real store and a real enforcer, with no kernel behind it.

    The kernel is absent on purpose, exactly as in `test_enforcement.py`: the local chain is the
    record of truth until the kernel has it, and everything asserted here is what the component did
    before anything was pushed.
    """
    now = clock_module.now()
    seed = tmp_path / "identity.seed"
    seed.write_text(secrets.token_hex(32))
    seed.chmod(0o600)
    mandate_file = tmp_path / "mandate.json"

    # `indirect=True` parametrisation supplies a `clock-advance`; without it there is none, which is
    # every deployment that has not asked for one.
    advance = getattr(request, "param", None)
    config = GatewayConfig.model_validate(
        {
            "gateway": {"enabled": True, "device": "test", "state_db": str(tmp_path / "gw.db")},
            **(
                {
                    "clock": {
                        "advance": advance,
                        "acknowledged": clock_module.CLOCK_ADVANCE_ACKNOWLEDGEMENT,
                    }
                }
                if advance
                else {}
            ),
            "kernel": {"url": "http://127.0.0.1:9"},
            "identity": {"seed_file": str(seed)},
            "org": {"policy_key": POLICY_KEY.id, "roots": [{"subject": ROOT.subject, "key": ROOT.id}]},
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
    monkeypatch.setenv("STOZHER_GATEWAY_SEED", str(seed))
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER_TOKEN", "opsbot-token")

    governor = Governor(config)
    # The caller key is derived from the seed the config names, so the mandate has to be granted to
    # *that* key — a fixture whose grantee is a constant would make the gateway refuse for a reason
    # that has nothing to do with the test.
    from stozher_gateway import crypto

    caller_key = SigningKey.derived(bytes.fromhex(seed.read_text()), crypto.ROLE_DEVICE, 0, "agent:opsbot/test")
    mandate_file.write_text(
        __import__("json").dumps(
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
    policy = POLICY_KEY.sign(
        baseline_policy("2026.07.1", now, ROOT.subject, {"ops.tail_logs": "read"})
    )
    # Verified on the deployment's clock, not the host's: `max-staleness-seconds` is 300, so a
    # policy stamped with the host's `now` on an advanced deployment is stale the moment it is
    # cached, and a `consequential` call takes the offline rule (`block`) instead of parking. A real
    # gateway pulls it from the kernel, whose clock is the same advanced one.
    governor._gateway.store.cache_policy("2026.07.1", policy, governor._gateway._clock.now())
    yield governor
    # Teardown must not mask the assertion that failed: a Governor the test never opened, or one a
    # refusal left half-open, has nothing to flush and its close is not what the test is about.
    with contextlib.suppress(Exception):
        governor.close(timeout=1.0)


def test_an_ordinary_function_is_governed_without_leaving_the_process(governor: Any) -> None:
    ledger: list[str] = []

    with governor:

        @governor.governed(server="ops", schema={"type": "object", "properties": {}})
        def tail_logs(service: str) -> str:
            ledger.append(service)
            return f"logs for {service}"

        assert tail_logs("checkout") == "logs for checkout"

    # The whole point of the integrator's rejection: their `LEDGER` ended up in a subprocess and
    # their driver's assertions read an empty one. It is a plain list in this process.
    assert ledger == ["checkout"]


def test_a_gated_function_refuses_and_never_runs_its_body(governor: Any) -> None:
    ran: list[str] = []

    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            ran.append(order_id)
            return "refunded"

        with pytest.raises(RefusalError) as refused:
            issue_refund("ORD-88214", 4_999_000)

    assert refused.value.document["result"] == "parked"
    assert refused.value.document["action"] == "ops.issue_refund"
    # Not "the call was refused after the fact": the body did not run.
    assert ran == [], "the wrapped function ran despite the refusal"


def test_the_same_call_written_two_ways_is_one_action(governor: Any) -> None:
    """Positional and keyword calls must produce the same `args-hash`, or one approval binds only
    one spelling of what is visibly one action.

    Not the same *request* hash: a request carries a nonce and a timestamp, so two parks of the same
    call are two requests by construction. What has to match is the commitment to the arguments.
    """
    hashes: list[str] = []

    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            return "refunded"

        for call in (
            lambda: issue_refund("ORD-1", 500),
            lambda: issue_refund(order_id="ORD-1", amount_cents=500),
        ):
            with pytest.raises(RefusalError) as refused:
                call()
            parked = governor._gateway.store.parked(refused.value.document["request-hash"])
            hashes.append(parked.request["args-hash"])

    assert hashes[0] == hashes[1], "the same action committed to two different argument hashes"


def test_what_the_gate_records_is_what_the_function_receives(governor: Any) -> None:
    """The defect a first integrator hit, and the worst one this module can carry.

    `BoundArguments.arguments` keys a `**kwargs` parameter under its own name, so calling
    `function(**arguments)` passed `{'extra': {'cc': ...}}` as a single keyword named `extra` —
    which `**extra` then collected under the key `'extra'`. The approver signed `cc`; the function
    received a dict called `extra` containing it. No exception, no warning, and the two records
    that are supposed to be the same thing disagreed.
    """
    seen: list[dict[str, Any]] = []

    with governor:

        # `tool=` so the action is one the fixture's policy classifies `read`: what is under test is
        # the signature, not the classification.
        @governor.governed(server="ops", tool="tail_logs")
        def send_email(to: str, subject: str = "(none)", **extra: Any) -> str:
            seen.append({"to": to, "subject": subject, "extra": extra})
            return "sent"

        assert send_email("ops@example.com", cc="boss@example.com", priority=1) == "sent"

    assert seen == [
        {
            "to": "ops@example.com",
            "subject": "(none)",
            "extra": {"cc": "boss@example.com", "priority": 1},
        }
    ], "the function did not receive the arguments the caller passed"


def test_a_positional_only_parameter_is_governable(governor: Any) -> None:
    """The same line, with a different symptom: there is no keyword spelling for a positional-only
    parameter, so `function(**arguments)` raised `TypeError` on a signature Python has had since
    3.8. A gate that cannot wrap a legal signature is a gate that gets removed from that tool."""
    seen: list[tuple[str, str]] = []

    with governor:

        @governor.governed(server="ops", tool="tail_logs")
        def run_query(query: str, /, database: str = "main") -> str:
            seen.append((query, database))
            return "0 rows"

        assert run_query("SELECT 1") == "0 rows"

    assert seen == [("SELECT 1", "main")]


def test_an_async_function_is_refused_rather_than_recorded_as_applied(governor: Any) -> None:
    """`Enforcer.call` is synchronous: it chains `applied` as soon as `forward()` returns, and for a
    coroutine function that is when the coroutine is *constructed*. Decorating one produced a chain
    that said the effect had been applied before the body ran — and said it still if the caller
    never awaited, or if the await raised. Refusing at decoration is the honest answer."""

    with pytest.raises(TypeError, match="async"):

        @governor.governed(server="ops")
        async def fetch(url: str) -> str:
            return "body"


@pytest.mark.parametrize("governor", ["PT5H"], indirect=True)
def test_a_gated_call_still_parks_on_a_clock_advanced_deployment(governor: Any) -> None:
    """The defect three independent evaluations reached, and the one that turned the gate off.

    The gateway stamped `not-after` from the host clock while the kernel ran ahead, so every gated
    call arrived already expired: `gate-request-expired`, `result: blocked`, `retryable: false` —
    not queued, not approvable, dead. The request's own window has to be on the deployment's clock.

    Companion to `test_deployment_clock.py`; it lives here because this is where the fixture that
    builds a whole gateway does.
    """
    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str) -> str:
            return "refunded"

        with pytest.raises(RefusalError) as refused:
            issue_refund("ORD-1")

        assert refused.value.document["result"] == "parked"
        parked = governor._gateway.store.parked(refused.value.document["request-hash"])
        # Ahead of the host by the advance, so a kernel running ahead accepts it rather than
        # answering `gate-request-expired`. An advance longer than the session mandate's own window
        # would refuse the session instead, which is ADR-0023 working: an advance expires a mandate,
        # it never resurrects one.
        assert parked.request["not-after"] > clock_module.shift(clock_module.now(), 4 * 3600)


def test_a_configuration_path_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    """`load_config` treats a missing file as a disabled gateway, which is right for the MCP server
    and wrong for a caller who named one: they got a Governor built from defaults and discovered it
    at the first call. A typo in a path is not a decision to run ungoverned."""
    from stozher_gateway.config import ConfigError

    with pytest.raises(ConfigError, match="no such configuration file"):
        Governor.from_config(tmp_path / "absent.toml")


def test_the_exception_a_caller_must_catch_is_importable_from_the_package(governor: Any) -> None:
    """`deploy/README.md` names `RefusalError` and it was importable only from a private submodule,
    which sent the first integrator into the source to find out from where."""
    import stozher_gateway

    assert stozher_gateway.RefusalError is RefusalError


def test_a_governor_that_was_never_opened_refuses_rather_than_running_ungoverned(
    governor: Any,
) -> None:
    """The failure mode worth being loud about: a decorated function that quietly runs unrecorded."""
    ran: list[str] = []

    @governor.governed(server="ops")
    def issue_refund(order_id: str) -> str:
        ran.append(order_id)
        return "refunded"

    with pytest.raises(Exception, match="not open"):
        issue_refund("ORD-1")
    assert ran == []


# -- what carries the authority, and what only carries a name ---------------------------------
#
# ADR-0002's anti-lesson: FleetQ re-executed an approved proposal by flipping an ambient container
# binding, because the authority to act lived in process state rather than in the call. `Governor`
# holds a session open for the life of a `with` block, which is exactly the shape that mistake had.
# These four bind what that session is: an identity and a mandate reference, both re-verified on
# every call, never a standing permission any later call can ride on.


def _chain(governor: Any) -> list[dict[str, Any]]:
    """Every envelope this gateway has chained. Nothing is pushed — the kernel is unreachable."""
    return [envelope for _, envelope, _ in governor._gateway.store.unpushed(limit=1000)]


def _approve(governor: Any, request_hash: str, approver: SigningKey = ROOT) -> dict[str, Any]:
    """Sign a real gate decision over a parked request, the way the console's approver would."""
    now = clock_module.now()
    decision = approver.sign(
        {
            "v": "stozher/0.1",
            "kind": "gate-decision",
            "request-hash": request_hash,
            "decision": "approve",
            "decided-at": clock_module.shift(now, -1),
            "not-after": clock_module.shift(now, 900),
            "single-use": True,
            "reason": None,
        }
    )
    governor._gateway.store.record_decision(request_hash, decision, None)
    return decision


def test_the_approving_signature_travels_in_the_envelope_the_kernel_verifies(governor: Any) -> None:
    """The approval is carried, not remembered.

    Nothing in the emitted record says "a human said yes at some point in this session". It carries
    the approver's signature and the request that signature commits to, and §06 §2 step (10) pins
    that request to this envelope's own action, target and `args-hash` — so a verifier that never
    saw the process can decide whether the effect was authorized.
    """
    applied: list[str] = []

    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            applied.append(order_id)
            return "refunded"

        with pytest.raises(RefusalError) as refused:
            issue_refund("ORD-1", 500)
        _approve(governor, refused.value.document["request-hash"])

        assert issue_refund("ORD-1", 500) == "refunded"

    assert applied == ["ORD-1"]
    effects = [
        envelope
        for envelope in _chain(governor)
        if envelope["kind"] == "effect" and envelope["execution"]["action"] == "ops.issue_refund"
    ]
    assert [envelope["execution"]["outcome"] for envelope in effects] == ["applied"]
    assert len(effects) == 1
    authorization = effects[0]["authorization"]
    assert authorization["decision"]["sig"]["key"] == ROOT.id
    assert authorization["decision"]["request-hash"] == object_hash(authorization["request"])
    # Step (10): the signature binds *these* arguments, not this session.
    assert authorization["request"]["args-hash"] == effects[0]["execution"]["args-hash"]
    assert authorization["request"]["action"] == effects[0]["execution"]["action"] == "ops.issue_refund"
    assert authorization["request"]["mandate-ref"] == effects[0]["mandate-ref"]


def test_a_second_call_cannot_ride_on_the_first_calls_approval(governor: Any) -> None:
    """The one thing an open session must not become: a permission.

    Same process, same `with` block, same function, same arguments, immediately after an approved
    call — and it parks again. The decision was consumed and its request hash recorded as used, so
    there is no cached verdict for the second call to reuse and its body does not run.
    """
    applied: list[str] = []

    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            applied.append(order_id)
            return "refunded"

        with pytest.raises(RefusalError) as refused:
            issue_refund("ORD-1", 500)
        first_request = refused.value.document["request-hash"]
        _approve(governor, first_request)
        assert issue_refund("ORD-1", 500) == "refunded"

        with pytest.raises(RefusalError) as second:
            issue_refund("ORD-1", 500)

    assert second.value.document["result"] == "parked"
    assert second.value.document["request-hash"] != first_request
    assert applied == ["ORD-1"], "the second call ran on the first call's authority"
    consumed = governor._gateway.store.parked(first_request)
    assert consumed.consumed_at is not None
    assert governor._gateway.store.gate_seen(first_request) is True


def test_a_decision_signed_for_another_request_authorizes_nothing(governor: Any) -> None:
    """Transplanting a genuine signature onto a second identical call.

    The approver's signature is over one request hash, so pairing it with the request the second
    call parked is refused at §06 §2 step (2) — before the mandate walk, before anything forwards.
    An attacker with the previous approval in hand and full control of the local store still cannot
    make this call proceed, which is what "the authority is in the call" has to mean.
    """
    applied: list[str] = []

    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            applied.append(order_id)
            return "refunded"

        with pytest.raises(RefusalError) as refused:
            issue_refund("ORD-1", 500)
        stolen = _approve(governor, refused.value.document["request-hash"])
        assert issue_refund("ORD-1", 500) == "refunded"

        with pytest.raises(RefusalError) as parked_again:
            issue_refund("ORD-1", 500)
        # The real signature, against the request the *second* park created.
        governor._gateway.store.record_decision(
            parked_again.value.document["request-hash"], stolen, None
        )

        with pytest.raises(RefusalError) as replayed:
            issue_refund("ORD-1", 500)

    assert replayed.value.document["result"] == "blocked"
    assert replayed.value.document["reason-code"] == "gate-authorization-request-hash-mismatch"
    assert applied == ["ORD-1"]


def test_an_open_session_is_an_identity_and_not_a_standing_permission(governor: Any) -> None:
    """The mandate is walked on every call, at the time of that call.

    A session that authenticated an hour ago and whose mandate has since expired is refused mid-
    block, with the function already decorated and the session still open. Nothing was cached at
    `open()` beyond the subject, the derived key and the mandate document itself — the verdict is
    recomputed, so the mandate is a credential presented per call rather than a door held open.
    """
    ran: list[str] = []

    with governor:

        @governor.governed(server="ops", tool="tail_logs")
        def tail_logs(service: str) -> str:
            ran.append(service)
            return f"logs for {service}"

        assert tail_logs("checkout") == "logs for checkout"
        # The fixture's mandate runs for a day; the deployment's clock moves past it. ADR-0023: an
        # advance expires a mandate, it never resurrects one.
        governor._gateway.enforcer._clock = clock_module.AdvancedClock("P2D")

        with pytest.raises(RefusalError) as refused:
            tail_logs("checkout")

    assert refused.value.document["result"] == "blocked"
    assert refused.value.document["reason-code"].startswith("mandate")
    assert ran == ["checkout"], "a call ran under an expired mandate because the session was open"


def test_reads_fold_into_one_aggregate_that_only_the_flush_puts_in_the_chain(governor: Any) -> None:
    """§10 §5 on this path too — and the exact record an unflushed process loses.

    Three `read` calls produce no per-call envelope; they live in an in-memory window keyed by
    (stream, subject-key, mandate-ref, policy-version). Only `close()` — which the context manager
    makes unforgettable — seals them into one `aggregate`. A process that exits without it keeps
    every effect envelope it wrote and loses every read since the last window boundary.
    """
    with governor:

        @governor.governed(server="ops", tool="tail_logs")
        def tail_logs(service: str) -> str:
            return f"logs for {service}"

        for service in ("checkout", "billing", "search"):
            tail_logs(service)

        in_flight = _chain(governor)
        # `gateway.session_open` is an effect of its own (§10 §1.6); the reads are not in here.
        assert [envelope["execution"]["action"] for envelope in in_flight if envelope["kind"] == "effect"] == [
            "gateway.session_open"
        ]
        assert [envelope for envelope in in_flight if envelope["kind"] == "aggregate"] == []

    aggregates = [envelope for envelope in _chain(governor) if envelope["kind"] == "aggregate"]
    assert len(aggregates) == 1
    assert aggregates[0]["classification"] == "read"
    assert aggregates[0]["counts"] == {"total": 3, "by-action": {"ops.tail_logs": 3}}
    assert {envelope["kind"] for envelope in _chain(governor)} == {"mandate", "effect", "aggregate"}


def test_importing_the_package_does_not_import_the_runtime() -> None:
    """`__init__.py` promises nothing runs at import. Exporting `Governor` must not break it."""
    import subprocess
    import sys

    probe = (
        "import sys, stozher_gateway;"
        "assert 'stozher_gateway.runtime' not in sys.modules, sorted(sys.modules);"
        "assert stozher_gateway.Governor is not None;"
        "assert 'stozher_gateway.runtime' in sys.modules"
    )
    done = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_one_governor_driven_from_several_threads_builds_one_unbroken_chain(
    governor: Any,
) -> None:
    """ADR-0028 §6: *"nothing in the suite exercises one `Governor` from several threads. Treat
    concurrent use as unverified until a test says otherwise."*

    Two things had to be got right before this test was worth anything, and both were found by
    mutating rather than by reasoning:

    **The class matters.** Written first against a `read` action it passed with every guard removed,
    because `read` folds into aggregates (§02 §7) — ninety-six calls made two envelopes and the
    chaining it claimed to exercise barely ran. `benign` emits one envelope per call, so the calls
    contend for one chain position each.

    **The GIL matters more.** Even on `benign` the test passed with the emitter's chain lock, its
    window lock, the store's thread lock and the `BEGIN IMMEDIATE` each removed in turn. CPython
    switches threads every 5ms by default and the read-head-then-insert section finishes far inside
    that, so a thread was essentially never preempted where it counts. `setswitchinterval(1e-6)`
    makes the contention real. Test-only — no seam is added to shipped code for it.

    A concurrency test that cannot fail when the lock is removed is not evidence, and would have
    been filed as evidence (ADR-0013 §2).
    """
    now = clock_module.now()
    governor._gateway.store.cache_policy(
        "2026.07.2",
        POLICY_KEY.sign(
            baseline_policy(
                "2026.07.2", now, ROOT.subject, {"ops.tail_logs": "read", "ops.touch": "benign"}
            )
        ),
        governor._gateway._clock.now(),
    )

    threads = 8
    per_thread = 24
    errors: list[BaseException] = []
    barrier = threading.Barrier(threads)
    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)

    try:
        with governor:

            @governor.governed(server="ops", schema={"type": "object", "properties": {}})
            def touch(name: str) -> str:
                return f"touched {name}"

            def drive(n: int) -> None:
                try:
                    barrier.wait(timeout=30)  # release them together, so they actually contend
                    for i in range(per_thread):
                        touch(f"n-{n}-{i}")
                except BaseException as exc:  # noqa: BLE001 — a thread's failure must reach the test
                    errors.append(exc)

            workers = [threading.Thread(target=drive, args=(n,)) for n in range(threads)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=120)
            assert not any(w.is_alive() for w in workers), "a governed worker did not finish"
    finally:
        sys.setswitchinterval(previous_interval)

    assert not errors, f"governed calls raised under contention: {errors[:3]}"

    envelopes = [e for _, e, _ in governor._gateway.store.unpushed(limit=1000)]
    # Filtered by action rather than counting every effect: opening the session is itself a `benign`
    # effect (§10 §1.6), so the stream carries one envelope this workload did not produce.
    effects = [
        e for e in envelopes if e["kind"] == "effect" and e["execution"]["action"] == "ops.touch"
    ]
    assert len(effects) == threads * per_thread, (
        f"{threads * per_thread} governed calls were made and {len(effects)} effects recorded — "
        "an audit that undercounts under load is the failure this test exists for"
    )

    # The chain is whole: contiguous from 0 per stream, every link naming its predecessor. A guard
    # that did not hold across read-and-insert shows up here and nowhere else.
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for envelope in envelopes:
        by_stream.setdefault(envelope["stream"], []).append(envelope)
    for stream, chain in by_stream.items():
        chain.sort(key=lambda e: e["seq"])
        assert [e["seq"] for e in chain] == list(range(len(chain))), (
            f"{stream} has a gap or a duplicate position: {[e['seq'] for e in chain]}"
        )
        previous: str | None = None
        for envelope in chain:
            assert envelope["prev-hash"] == previous, (
                f"{stream} seq {envelope['seq']} does not name its predecessor"
            )
            previous = object_id(envelope)

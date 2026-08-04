"""A wedged stream must be able to become unwedged. Until 2026-08-04 it could not.

Found by a design-partner evaluation running the system as an SRE would: revoke a mandate — an
ordinary incident action — the stream wedges correctly per `spec/05 §7.1`, and then the documented
recovery act does not recover it. Their words: *"a routine mandate revocation permanently removes a
component from the fleet and no shipped command brings it back."*

# The loop, read out of the code rather than inferred from the symptom

`Store.clear_wedge` has exactly one caller: `push_pending`, on `response.accepted`. And
`push_pending` skipped every wedged stream *before* it could ever attempt a submission:

    if stream in wedged or self._store.wedge(stream) is not None:
        wedged.add(stream)
        continue

So a wedged stream submits nothing, therefore has nothing accepted, therefore never clears. The exit
`spec/04 §7.2` specifies — a root-approved `kernel.resume_stream` that binds `(stream, resume-seq)`
— is real on the kernel side and the gateway had no way to notice it had happened.

# What the exit is here

The refused position stays refused and stays empty; that is §04 §7.2's whole design, and it is why
the probe is the envelope *after* it rather than a retry of the refused bytes. The envelopes of a
wedged stream are held locally, in order, so the first unpushed one is exactly that envelope. It is
offered once per push cycle: accepted means an operator has published the resume and the stream is
live again; refused means they have not, the wedge stands, and — importantly — the probe stays
unpushed so it can be offered again.

The cost is one refused submission per push cycle per wedged stream, and therefore one kernel
rejection record. That is deliberate and it is the cheaper side of the trade: the alternative that
was shipped is a component that is permanently and silently dead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from stozher_gateway import clock as clock_module
from stozher_gateway.emitter import Emitter
from stozher_gateway.kernel_client import KernelResponse
from stozher_gateway.signing import SigningKey
from stozher_gateway.store import GatewayStore

STREAM = "gw:probe:0003"


class _RefusesUntilResumed:
    """A kernel that refuses everything until `resumed` is set, then accepts.

    Which is what an operator publishing a root-approved `kernel.resume_stream` looks like from the
    gateway's side: nothing about the gateway changed, and the same bytes now land.
    """

    def __init__(self) -> None:
        self.resumed = False
        self.offered: list[str] = []

    def ingest(self, envelope: dict[str, Any], payloads: Any) -> KernelResponse:
        self.offered.append(str(envelope.get("id", envelope.get("seq"))))
        if self.resumed:
            return KernelResponse(201, {"stozher": "stozher/0.1", "accepted": True})
        return KernelResponse(
            422,
            {
                "stozher": "stozher/0.1",
                "reason-code": "mandate-unresolved",
                "reason": "the mandate this envelope cites is revoked",
            },
        )


def _effect(emitter: Emitter, key: SigningKey, action: str) -> None:
    now = clock_module.now()
    emitter.append(
        key,
        STREAM,
        {
            "v": "stozher/0.1",
            "kind": "effect",
            "emitted-at": now,
            "identity": {"subject": key.subject, "key": key.id, "component": "gateway"},
            "mandate-ref": "11" * 32,
            "policy-version": "2026.07.1",
            "classification": "read",
            "execution": {
                "action": action,
                "target": "mcp:github",
                "args-hash": "cc" * 32,
                "outcome": "applied",
                "started-at": now,
                "finished-at": now,
            },
        },
    )


def test_a_resumed_stream_delivers_the_records_that_were_held() -> None:
    """The assertion the SRE evaluation was owed: the exit exists and the held records arrive."""
    store = GatewayStore(Path(":memory:"))
    kernel = _RefusesUntilResumed()
    emitter = Emitter(store, kernel, "gateway")
    key = SigningKey(bytes.fromhex("aa" * 32), "agent:probe")

    _effect(emitter, key, "github.get_file")
    emitter.push_pending()
    assert store.wedge(STREAM) is not None, "the fixture must actually wedge"

    # Work carries on locally while the stream is refused — that is the point of the local chain.
    _effect(emitter, key, "github.list_issues")
    _effect(emitter, key, "github.read_readme")

    # Still refused: the probe is offered and turned away, and nothing is lost by it.
    assert emitter.push_pending() == 0
    assert store.wedge(STREAM) is not None, "the wedge was cleared without a resume"
    assert store.pending_push_count() == 2, (
        "a probe that was refused consumed the envelope it probed with; the record is gone and no "
        "later resume can deliver it"
    )

    # The operator publishes the root-approved resume (§04 §7.2). Nothing about the gateway changes.
    kernel.resumed = True

    assert emitter.push_pending() == 2, "the held records did not reach the kernel after the resume"
    assert store.wedge(STREAM) is None, "the stream is delivering again and still reads as wedged"
    assert store.pending_push_count() == 0


def test_a_stream_that_was_never_resumed_stays_wedged_and_keeps_its_reason() -> None:
    """The control. The fix must not become "retry until it works", which is the wedge removed.

    `spec/05 §7.1` clause 3 is what stops a refused envelope's successors being submitted into a
    chain the kernel has a different view of. The probe is one envelope, not the queue.
    """
    store = GatewayStore(Path(":memory:"))
    kernel = _RefusesUntilResumed()
    emitter = Emitter(store, kernel, "gateway")
    key = SigningKey(bytes.fromhex("bb" * 32), "agent:probe")

    _effect(emitter, key, "github.get_file")
    emitter.push_pending()
    for _ in range(3):
        _effect(emitter, key, "github.list_issues")

    before = len(kernel.offered)
    emitter.push_pending()
    assert len(kernel.offered) - before == 1, (
        "more than one envelope was submitted past the wedge; §05 §7.1 clause 3 holds the rest"
    )

    wedge = store.wedge(STREAM)
    assert wedge is not None
    assert wedge.reason_code == "mandate-unresolved", "the probe overwrote the original reason"

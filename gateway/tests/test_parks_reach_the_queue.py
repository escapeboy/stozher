"""A park held locally must reach the queue on its own. DEF-16.

Found by the commerce design partner on 2026-08-04: with the kernel down, a gated call comes back
`result: parked` with a request hash the kernel then 404s. Nothing is queued, and no human will ever
see it.

**Verified here, and the report was half wrong in the system's favour** — the refusal's `hint` does
say *"held locally; the kernel was unreachable, so nothing was queued for a human to see"*. So the
gateway was not lying about the state. What made `parked` optimistic rather than false was the only
route out of it: `_queue_with_kernel` is re-submitted when the *caller retries*, and if the agent
reported the park to its user and stopped — which is exactly what §06 §4.1 says a well-behaved agent
should do with a terminal answer — the request stayed local forever.

So the fix is not a new reason code for a state that resolves. It is to make it resolve without
depending on the agent to come back: the parks a session holds are re-offered when a session opens,
beside `recover_intents` and `apply_pending_seeds`, which are there for the same class of reason.

The submission route is idempotent by `request-hash` (§06 §4.3 rule 1), so re-offering one already
queued costs a `200`, and no notification is fired — approval fatigue is an availability attack
(§09 §7), and a ping per reconnect is exactly that delivered by the component meant to prevent it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.kernel_client import KernelResponse, KernelUnreachableError

from .test_enforcement import Harness


def _request(action: str) -> dict[str, Any]:
    """The members a real gate-request carries. A thinner fixture passes the happy path and then
    fails inside the refusal builder, which is where the first version of this file went wrong."""
    return {
        "action": action,
        "target": "mcp:github",
        "classification": "consequential",
        "subject": "agent:claude-code",
        "key": "ed25519:" + "1" * 64,
        "component": "gateway",
        "mandate-ref": "m" * 32,
        "policy-version": "2026.07.1",
        "args-hash": "a" * 64,
    }


class _KernelThatComesBack:
    """Unreachable until `up` is set, then queueing normally. Records what it was offered."""

    def __init__(self) -> None:
        self.up = False
        self.offered: list[str] = []

    def park_gate_request(self, request: dict[str, Any], arguments: Any = None) -> KernelResponse:
        if not self.up:
            raise KernelUnreachableError("the kernel is down")
        self.offered.append(str(request.get("action")))
        return KernelResponse(status=201, body={})

    def gate_request(self, _request_hash: str) -> KernelResponse:
        return KernelResponse(status=404, body={})


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_a_park_held_while_the_kernel_was_down_is_offered_when_a_session_opens(
    harness: Harness,
) -> None:
    """The assertion the commerce evaluation was owed: the request stops being invisible."""
    kernel = _KernelThatComesBack()
    harness.enforcer._kernel = kernel

    harness.store.park(
        "e" * 64,
        _request("github.create_issue"),
        "github",
        "create_issue",
        "consequential",
        None,
        True,
        clock_module.now(),
    )
    assert kernel.offered == [], "the fixture must start with nothing queued"

    # Still down: offering changes nothing and must not raise.
    assert harness.enforcer.requeue_parks(harness.session) == 0
    assert kernel.offered == []

    kernel.up = True
    assert harness.enforcer.requeue_parks(harness.session) == 1, (
        "a request held locally through an outage never reached the queue; the agent reported a "
        "park to its user, stopped as §06 §4.1 asks it to, and no human will ever see the request"
    )
    assert kernel.offered == ["github.create_issue"]


def test_an_answered_park_is_not_offered_again(harness: Harness) -> None:
    """The control. Re-offering everything on every session open is a queue that grows by itself,
    and the cap it would fill is the one DEF-18 is about."""
    kernel = _KernelThatComesBack()
    kernel.up = True
    harness.enforcer._kernel = kernel

    harness.store.park(
        "f" * 64,
        _request("github.create_issue"),
        "github",
        "create_issue",
        "consequential",
        None,
        True,
        clock_module.now(),
    )
    harness.store.record_gate_decision("f" * 64, {"decision": "approve"})

    assert harness.enforcer.requeue_parks(harness.session) == 0, (
        "a request a human has already answered was offered to the queue again"
    )
    assert kernel.offered == []


def test_a_re_offered_park_still_carries_what_the_approver_must_read(harness: Harness) -> None:
    """The half that makes the re-offer worth doing rather than merely visible.

    §06 §4.4 rule 7 makes the *first accepted* submission's values the recorded ones. So a park
    re-offered without its arguments would land a permanently blank row — an approver asked to sign
    for a call nobody can describe. That is worse than the invisibility it was fixing, which is why
    `parked` gained a column and the gateway store gained its first real migration to carry it.
    """
    seen: list[Any] = []

    class _Recording(_KernelThatComesBack):
        def park_gate_request(
            self, request: dict[str, Any], arguments: Any = None
        ) -> KernelResponse:
            seen.append(arguments)
            return super().park_gate_request(request, arguments)

    kernel = _Recording()
    harness.enforcer._kernel = kernel

    request_hash = "a1" * 32
    harness.store.park(
        request_hash,
        _request("github.create_issue"),
        "github",
        "create_issue",
        "consequential",
        None,
        True,
        clock_module.now(),
    )
    harness.store.record_park_arguments(request_hash, {"title": "delete production"})

    kernel.up = True
    assert harness.enforcer.requeue_parks(harness.session) == 1
    assert seen == [{"title": "delete production"}], (
        "the re-offered park carried no arguments; §06 §4.4 rule 7 makes that blank permanent, and "
        "the approver is asked to sign for a call nobody can describe"
    )


def test_one_park_the_kernel_refuses_does_not_stop_the_session(harness: Harness) -> None:
    """A recovery loop must not be able to stop a session from starting.

    Found by installing this on a real deployment an hour after writing `requeue_parks`. A park from
    five days earlier was re-offered, the kernel refused it `gate-request-expired` — correctly, a
    request's `not-after` is an hour — and `_queue_with_kernel` *raises* on a kernel refusal by
    design, because for a fresh park that refusal means "this is in no queue and reporting it as
    parked would be a lie". Propagating out of `requeue_parks` it meant something else entirely:
    **enforcement mode did not start at all**, so the gateway served its tools ungoverned.

    One stale row turned into a total outage of the thing that governs. That is worse than the
    invisibility `requeue_parks` was written to fix, and it is the failure mode of every recovery
    loop that treats one item's failure as its own.
    """
    class _RefusesEverything(_KernelThatComesBack):
        def park_gate_request(
            self, request: dict[str, Any], arguments: Any = None
        ) -> KernelResponse:
            return KernelResponse(status=422, body={"reason-code": "gate-request-expired"})

    harness.enforcer._kernel = _RefusesEverything()

    for i, request_hash in enumerate(("b1" * 32, "b2" * 32)):
        harness.store.park(
            request_hash,
            _request(f"github.tool_{i}"),
            "github",
            f"tool_{i}",
            "consequential",
            None,
            True,
            clock_module.now(),
        )

    # Must not raise, and must not stop after the first refusal.
    assert harness.enforcer.requeue_parks(harness.session) == 0
    assert len(harness.store.pending()) == 2, "a refused re-offer discarded the park it was for"

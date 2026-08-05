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
        {"action": "github.create_issue", "target": "mcp:github"},
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
        {"action": "github.create_issue", "target": "mcp:github"},
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
        {"action": "github.create_issue", "target": "mcp:github"},
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

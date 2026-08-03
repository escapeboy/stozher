"""DEF-1, closed: one call is one question, however many times the run is replayed (§06 §4.2).

These were the quarantined reproductions in `test_open_defects.py`. They are here, unquarantined and
in the default suite, because a defect's evidence is only worth keeping if it goes on being run — a
red test in a quarantine nobody executes and a deleted test differ by one command.

What was observed, and what these hold shut: a nightly job re-run at 04:00 over its own 03:00 queue
parked every call again. `GatewayStore.decided_for` selected on `decision_json IS NOT NULL`, so an
*outstanding* request was filtered out before its identity fields were ever compared, and
`Enforcer._gate` minted a fresh `nonce` (`gate.action_request`, "128 bits of fresh entropy") and
parked a second row. Two runs left 54 undecided requests and 20 `(action, args-hash)` pairs appearing
more than once. The kernel's own route is idempotent by `request-hash` exactly as §06 §4.3 rule 1
requires and cannot help, because §06 §1.1 puts the nonce inside the hashed object.

Nothing here weakens a gate: every call below is still refused, and the whole subject is how many
times one human is asked about it.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.refusal import RefusalError

from .test_enforcement import Harness

IDENTITY = (
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


def _fields(request: dict[str, Any]) -> dict[str, Any]:
    return {name: request[name] for name in IDENTITY}


def _park(harness: Harness, **arguments: Any) -> str:
    """Make a gated call, assert it parked, and return the `request-hash` it was refused with."""
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", **arguments)
    assert refused.value.document["reason-code"] == "gate-parked"
    return str(refused.value.document["request-hash"])


def test_a_repeated_identical_call_resolves_to_the_request_already_pending(tmp_path: Path) -> None:
    """The defect itself: two identical calls, the first still undecided, are one question.

    The second call's refusal carries the *first* request's hash, which is the one an approver is
    looking at and the one their signature will bind. A second hash would be a request nobody has
    been asked about, offered to an agent as the thing to wait for.
    """
    harness = Harness(tmp_path)
    first = _park(harness, title="ship it")
    second = _park(harness, title="ship it")

    assert first == second, f"the second identical call minted a new action request: {first}, {second}"
    pending = harness.store.pending()
    assert len(pending) == 1, (
        f"{len(pending)} requests are queued for one call a human has not answered yet: "
        f"{[row.request_hash for row in pending]}"
    )


def test_the_pending_request_is_findable_by_the_fields_that_identify_it(tmp_path: Path) -> None:
    """The exact break, at the store: an *outstanding* request must be locatable field-wise.

    `decided_for` answers "has this been answered?" and `outstanding_for` answers "has this been
    asked?". They were one query and it could only ask the first, so the row the gate needed was
    filtered out before the identity fields were compared.
    """
    harness = Harness(tmp_path)
    _park(harness, title="ship it")

    parked = harness.store.pending()
    assert len(parked) == 1
    fields = _fields(parked[0].request)
    now = harness.enforcer._clock.now()

    outstanding = harness.store.outstanding_for(fields, now)
    assert outstanding is not None, (
        f"the row exists ({parked[0].request_hash}) and the lookup that must find it does not"
    )
    assert outstanding.request_hash == parked[0].request_hash
    assert harness.store.decided_for(fields) is None, (
        "an unanswered request must not be offered as a decision; the two halves are disjoint"
    )


def test_two_identical_calls_racing_park_exactly_one_request(tmp_path: Path) -> None:
    """The same-second case, which a check outside the write would leave open.

    A stdio gateway is one process per client connection, so two connections of one caller are two
    processes over one database file, and a scheduled job that starts twice a second apart has both
    of them reading "nothing is outstanding" before either writes. `park_unique` does the lookup and
    the insert inside one `BEGIN IMMEDIATE`, which is atomic against the other process and not only
    against the other thread.
    """
    harness = Harness(tmp_path)
    ready = threading.Barrier(2)
    hashes: list[str] = []
    errors: list[Exception] = []

    def run() -> None:
        ready.wait(timeout=10)
        try:
            hashes.append(_park(harness, title="ship it"))
        except Exception as e:
            # Recorded rather than raised: an exception in a worker thread is otherwise printed and
            # the test passes on a `hashes` list that never filled.
            errors.append(e)

    threads = [threading.Thread(target=run, name=f"racer-{n}") for n in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert len(hashes) == 2
    assert hashes[0] == hashes[1], f"the race minted two action requests: {hashes}"
    pending = harness.store.pending()
    assert len(pending) == 1, f"{len(pending)} rows parked for one call: {[p.request_hash for p in pending]}"


def test_a_request_past_its_not_after_is_not_reused(tmp_path: Path) -> None:
    """Expiry. Reuse is bounded by the request's own `not-after` and stops there.

    Past that instant nobody can answer it — §06 §2 step 8 refuses a decision made later, and §06
    §4.4 rule 7 has the kernel erase the arguments an approver would read — so resolving to it would
    hand the caller a `request-hash` that can never become an approval. Without this the fix would
    quietly resurrect dead requests, which is a worse failure than the duplicate it replaced: the
    duplicate is at least answerable.
    """
    harness = Harness(tmp_path)
    first = _park(harness, title="ship it")
    expired = harness.store.parked(first)
    assert expired is not None

    # Two hours: `_REQUEST_LIFETIME_SECONDS` is one, so the first request is an hour dead.
    harness.enforcer._clock = clock_module.AdvancedClock("PT2H")
    second = _park(harness, title="ship it")

    assert second != first, "an expired request was reused; no decision about it can ever arrive"
    outstanding = harness.store.outstanding_for(_fields(expired.request), harness.enforcer._clock.now())
    assert outstanding is not None
    assert outstanding.request_hash == second, (
        "the dead request is still the one the lookup returns, so every later call parks against it"
    )


def test_two_different_calls_still_park_separately(tmp_path: Path) -> None:
    """The counterfactual, and the thing this change must not have done.

    Collapsing *every* call onto one pending row would pass the reuse tests above and would be a
    gate that approves one action by approving another. The two calls here differ only in an
    argument value, so they differ only in `args-hash` — the narrowest gap between two calls the
    protocol recognises, and the one §06 §2 step 10 compares.
    """
    harness = Harness(tmp_path)
    first = _park(harness, title="ship it")
    second = _park(harness, title="ship something else")

    assert first != second, "two different calls resolved to one pending request"
    pending = harness.store.pending()
    assert len(pending) == 2, [row.request_hash for row in pending]
    assert {row.request_hash for row in pending} == {first, second}


def test_the_operator_is_notified_once_for_one_question(tmp_path: Path) -> None:
    """A notification per retry is the approval fatigue §09 §7 names, delivered by the gate.

    The park notifier fires when a request enters the queue, not when a caller asks again about one
    already in it. Re-notifying would leave the console holding one row and the operator holding a
    message per restart — the queue fixed and the human's attention still multiplied.
    """
    log = tmp_path / "notifications"
    harness = Harness(tmp_path, park_notify=["/bin/sh", "-c", f"cat >> {log}"])
    first = _park(harness, title="ship it")
    second = _park(harness, title="ship it")
    harness.enforcer.drain_park_notifications(timeout=10)

    assert first == second
    notified = [line for line in log.read_text().splitlines() if line.strip()]
    assert len(notified) == 1, f"the operator was pinged {len(notified)} times for one request"
    assert first in notified[0]

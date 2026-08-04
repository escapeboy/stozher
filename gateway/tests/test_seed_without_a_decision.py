"""The documented quick start crashed on every tool a deployment has not already classified.

Found by two independent design-partner evaluations on 2026-08-04, reproducing each other exactly:
`./deploy/gate/clean-install.sh` — the project's own release gate, on the path `README.md`
headlines — failed at step 5 with

    GATE FAILED: the approved call did not reach the downstream server — the approval bought nothing
    'NoneType' object is not subscriptable

# The mechanism

A first call to an unclassified tool parks **two** requests: the call, and a
`kernel.seed_catalog_entry` question about what class the tool is (§10 §4.3 — two decisions, two
signatures, deliberately). `bin/stozher-approve` answers one of them. On the retry:

* `_consume` verifies the call's decision, then calls `_seed_catalog` for the seed;
* `_seed_catalog` guards `parked.seed is None` and then reads
  `parked.seed["decision"]["request-hash"]` — and `decision` is `None`, because nobody answered the
  second question.

`TypeError`, no refusal document, no audit record, and the agent sees `refusal: null`. The gate
records nothing about a call that reached this line, which is worse than the crash: the one thing
this system exists to guarantee is that nothing happens silently.

# And why approving it afterwards did not help

`_collect_seed_decision` runs only from inside `_collect_decisions`, which iterates
`store.pending()` — `WHERE decision_json IS NULL`. The moment the *call's* decision lands, the row
leaves that set forever, so the seed's answer can never be collected afterwards. The first partner
called the result "permanently wedged" and was right: the approver answers the second question, and
nothing ever reads it.

Two defects, one symptom. Fixing only the crash would leave a tool that parks a question no answer
can ever reach.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module

from .test_enforcement import ROOT, Harness


def _seed_request(action: str) -> dict[str, Any]:
    now = clock_module.now()
    return {
        "v": "stozher/0.1",
        "kind": "gate-request",
        "subject": "agent:claude-code",
        "key": "ed25519:" + "1" * 64,
        "component": "gateway",
        "mandate-ref": "m" * 32,
        "policy-version": "2026.07.1",
        "classification": "consequential",
        "action": action,
        "target": "mcp:github",
        "args-hash": "b" * 64,
        "requested-at": now,
        "single-use": True,
    }


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_a_seed_nobody_answered_is_not_in_force_and_does_not_crash(harness: Harness) -> None:
    """The crash, at its narrowest. A seed with no decision is a question, not an authority.

    `_seed_catalog` already returns `False` for "no class proposed" and "no seed parked". An
    unanswered seed is the same kind of nothing and must take the same exit — not a `TypeError`
    three lines later, on a path where a refusal document would at least have been recorded.
    """
    request_hash = "c" * 64
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
    harness.store.park_seed(request_hash, _seed_request("github.create_issue"), "consequential")
    parked = harness.store.parked(request_hash)
    assert parked is not None and parked.seed is not None
    assert parked.seed.get("decision") is None, "the fixture must be a seed nobody has answered"

    applied = harness.enforcer._seed_catalog(harness.session, parked, harness.policy, [])

    assert applied is False, "an unanswered classification question put a catalog entry in force"
    assert harness.store.catalog_entry("github", "create_issue") is None


def test_a_seed_can_still_be_collected_after_the_call_has_been_decided(harness: Harness) -> None:
    """The second half, and the one that made the first unrecoverable.

    `store.pending()` is `WHERE decision_json IS NULL`, so a row whose *call* has been answered
    leaves it. If that is the only route to `_collect_seed_decision`, an approver who answers the
    classification question second is answering into a void.
    """
    request_hash = "d" * 64
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
    harness.store.park_seed(request_hash, _seed_request("github.create_issue"), "consequential")
    harness.store.record_gate_decision(request_hash, ROOT.sign({"decision": "approve"}))

    assert harness.store.pending() == [], "the fixture must have left the pending set"
    awaiting = harness.store.seeds_awaiting_a_decision()
    assert [row.request_hash for row in awaiting] == [request_hash], (
        "a parked classification question with no answer is unreachable once its call is decided; "
        "the approver's second signature can never be collected"
    )

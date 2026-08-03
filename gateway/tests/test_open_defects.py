"""Executable reproductions of defects that are **open**. Quarantined, not skipped.

Every test here is marked `open_defect` and is excluded from the default run (`pyproject.toml`,
`addopts`). Run them with:

    python3 -m pytest gateway/tests -q -m open_defect

They assert the behaviour the design requires, so while a defect is open its test fails and the
failure message carries the observed values. That is the point: the day the defect is fixed, this
file goes green and says so, which is a thing a bug report cannot do.

Nothing here weakens a gate. Each test observes what the shipped chokepoint does.

DEF-4's three reproductions used to live here and no longer do: the defect is closed, so its tests
are in the default suite as `tests/test_policy_bundle.py` — including the one that always passed,
which is still the control it always was.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from stozher_gateway.refusal import RefusalError

from .test_enforcement import Harness

pytestmark = pytest.mark.open_defect


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


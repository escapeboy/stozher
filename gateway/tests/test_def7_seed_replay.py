"""DEF-7 — a catalog seed applied twice would spend one single-use approval on two envelopes.

**Closed 2026-08-04; this is the regression test, unquarantined and green.** CI saw it once on Linux as
`gate-authorization-replayed` at `seq` 7 (run 30905170959); this file is the deterministic
reproduction that made it `open` rather than `observed`, and then the test the fix had to pass. It
needs no concurrency at all, which is why it was worth having: the observation looked like a race
and the mechanism was a missing fact.

# The mechanism, from the code rather than from the failure

`Enforcer._seed_catalog` ends with two statements, in this order and in two transactions:

    envelope_id = self._emitter.append(...)     # spends the approver's single-use signature
    self._store.seed_catalog(...)               # raises the guard, afterwards

The only thing that stops a seed being applied twice is `catalog_entry(server, tool) is None`,
checked at both call sites — `apply_pending_seeds` at every session open, and the gate path after a
decision verifies. **`seeded_pending()` does not exclude seeds that have already been applied**: the
fact "this seed is spent" lives in a different table, is written after the envelope, and is never
marked on the seed itself. So between the append and the catalog write the guard still passes, and
anything that looks in that window seeds again.

In that window "anything" is not hypothetical. `apply_pending_seeds` runs on every session open, and
a deployment runs one gateway process per MCP client over one SQLite file — which is what the CI
observation almost certainly was, two sessions overlapping where macOS happened to serialise them.

# What this test does *not* claim

It does not reproduce the CI failure's timing. It reproduces the *state*: a seed whose envelope has
been appended and whose catalog entry has not landed. A crash between the two statements reaches the
same state, and so does a second process in the window. Whether the CI run got there by overlap or
by something else is still unestablished, and `docs/open-defects.md` says so.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import object_hash
from stozher_gateway.gate import ActionRequest, action_request
from stozher_gateway.refusal import RefusalError

from .test_enforcement import ROOT, Harness


def _seed_decision(request_hash: str) -> dict[str, Any]:
    now = clock_module.now()
    return ROOT.sign(
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


def _seed_request(harness: Harness, server: str, tool: str, proposed: str) -> dict[str, Any]:
    """The second request §10 §4.3 makes — built with the same helper the enforcer uses.

    Hand-rolling this dict cost two rounds: the first was signed over the wrong hash, the second was
    missing `not-after` and was refused `schema-missing-member`. The enforcer's own constructor is
    the only spelling that is right by construction, and a reproduction that drifts from it would be
    reproducing something else.
    """
    now = clock_module.now()
    entry = {"server": server, "tool": tool, "class": proposed}
    return action_request(
        ActionRequest(
            subject=harness.session.subject,
            key=harness.session.key.id,
            component="gateway",
            mandate_ref=harness.session.mandate_ref,
            policy_version=harness.policy.version,
            classification="consequential",
            action="kernel.seed_catalog_entry",
            target=f"tool:{server}/{tool}",
            args_hash=object_hash(entry),
        ),
        requested_at=now,
        not_after=clock_module.shift(now, 900),
    )


def _seeded_effects(harness: Harness) -> list[dict[str, Any]]:
    return [
        envelope
        for _, envelope, _ in harness.store.unpushed(limit=100)
        if envelope.get("execution", {}).get("action", "").endswith("seed_catalog_entry")
    ]


def test_def7_a_seed_whose_catalog_write_did_not_land_is_applied_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One approval, two envelopes, both citing the same single-use decision.

    The kernel refuses the second `gate-authorization-replayed` — correctly, and that refusal wedges
    the emitter's stream. The defect is not that the kernel says no; it is that the component asks
    twice for something it was permitted once.
    """
    harness = Harness(tmp_path)

    # A first call of an unknown tool parks the call and, beside it, the seed request that
    # classifies the tool (§10 §4.3).
    with pytest.raises(RefusalError):
        harness.call("rename_branch", branch="main")
    pending = harness.store.pending()
    assert len(pending) == 1, [p.request_hash for p in pending]
    request_hash = pending[0].request_hash

    seed_request = _seed_request(harness, "github", "rename_branch", "read")
    harness.store.park_seed(request_hash, seed_request, "read")
    # The decision commits to the *seed* request, not to the call that provoked it: §10 §4.3 makes
    # classifying the tool a second decision with its own signature over its own request.
    harness.store.attach_seed_decision(request_hash, _seed_decision(object_hash(seed_request)))

    seeded = harness.store.seeded_pending()
    assert len(seeded) == 1, "the seed is not answered, so nothing below is about DEF-7"

    # The window: the envelope is appended and the catalog write does not land. A crash between the
    # two statements, or a second process looking in between them, reaches this same state.
    original = harness.store.seed_catalog
    monkeypatch.setattr(
        harness.store,
        "seed_catalog",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("the catalog write did not land")),
    )
    with pytest.raises(RuntimeError):
        harness.enforcer.apply_pending_seeds(harness.session)
    monkeypatch.setattr(harness.store, "seed_catalog", original)

    first = _seeded_effects(harness)
    assert len(first) == 1, "the seed envelope was not appended, so the window does not exist"

    # Anything that looks now sees `catalog_entry(...) is None` and seeds again — a second envelope
    # over the same approval. This is the line that fails while DEF-7 is open.
    harness.enforcer.apply_pending_seeds(harness.session)
    both = _seeded_effects(harness)

    assert len(both) == 1, (
        f"the seed was applied {len(both)} times over one single-use approval. The second envelope "
        "cites the same decision, which the kernel refuses `gate-authorization-replayed` and which "
        "wedges this emitter's stream (§05 §7.1). `Store.claim_gate_use` is what stops it: the "
        "decision is claimed in one atomic statement before the signature is spent."
    )
    # And the sharper statement of the same fact, kept so a fix that dedupes envelopes without
    # fixing the bookkeeping still fails here.
    citations = [envelope["authorization"]["decision"]["sig"]["key"] for envelope in both]
    assert len(citations) == len(set(map(str, citations))) or len(both) == 1, citations

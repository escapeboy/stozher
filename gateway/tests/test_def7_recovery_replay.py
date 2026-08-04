"""DEF-7, the fourth site — recovery is the one path that re-emits, and it closed its own record last.

# What CI was actually failing on

Not a race. `gateway — ruff, mypy --strict, tests` failed **12 of the last 13 red runs** on one
signature, and the log names it exactly:

    the kernel refused this session's stream gw:test-mbp:claude-code at seq 3
    (gate-authorization-replayed: request 690c6f9e… was already used); no call will be served
    under it until an operator resumes the stream (spec/04 §7.2)

The refusal comes from the **kernel**, not from the gateway's own `claim_gate_use` guard — which is
the whole tell. The three sites fixed on 2026-08-04 all guard the *spend*: they stop this component
handing the same approval to two envelopes. `recover_intents` never asks. It re-emits a write-ahead
record verbatim, `authorization` and all, and the local `gate_seen` claim it would collide with was
written by the original spend and is therefore *already* there in both the legitimate and the
illegitimate case. The local ledger cannot tell them apart; the kernel can, and does.

# The mechanism, from the code

`Enforcer.recover_intents` ends with two statements, in this order and in two transactions:

    self._emitter.append(session.key, session.stream, record, payloads)   # chains the effect
    self._store.resolve_intent(intent_id, now)                            # closes the record, after

That is the same shape as the three sites already closed, in the one function whose job is to run
after a process stopped somewhere it should not have. `append_next` grew a `resolve_intent`
parameter for exactly this hazard, and its own docstring names *this* function as the consumer of
the bug — but `_chain_effect` was threaded through it and recovery was not. The producer was fixed;
the re-emitter kept the window.

So: recovery chains the effect, the `UPDATE` does not land, and the intent is still open. The next
session opens, recovers the *same* record a second time, and now there genuinely are two envelopes
carrying one single-use authorization. Both sync. The kernel takes the first and refuses the second,
and the stream wedges at that `seq` for everything behind it — which is why one failure takes the
two tests after it down with a `None` body.

# Why Linux and not macOS

`resolve_intent` opens its own connection and takes SQLite's writer lock. Under a busy database it
can raise `database is locked` rather than return — the kernel suite hit precisely that on the same
day (`s6_divergent_decisions_contend_for_the_core_stream`, run 30928079238). A lost `UPDATE` needs
no crash and no signal; it needs a lock timeout. That is not a microsecond window, which is why the
observed rate was 38% of runs and not one in a thousand.

# What this test does and does not claim

It reproduces the **state**, deterministically and without concurrency: an effect chained by
recovery whose write-ahead record did not close. `resolve_intent` is stubbed to do nothing, which
is what a process stopping between the two statements — or a lock timeout swallowing the second —
leaves behind. It does not reproduce CI's timing, and does not need to: with the fix the second
statement does not exist to lose.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module

from .test_enforcement import DEVICE, Harness


def _intent_body(harness: Harness, request_hash: str) -> dict[str, Any]:
    """An effect whose call was applied and whose envelope never chained — carrying its approval."""
    now = clock_module.now()
    return {
        "v": "stozher/0.1",
        "kind": "effect",
        "emitted-at": now,
        "identity": {
            "subject": harness.session.subject,
            "key": DEVICE.id,
            "component": "gateway",
        },
        "mandate-ref": harness.session.mandate_ref,
        "policy-version": harness.policy.version,
        "classification": "consequential",
        "execution": {
            "action": "github.create_issue",
            "target": "mcp:github",
            "args-hash": "a" * 64,
            "outcome": "attempted",
            "started-at": now,
            "finished-at": now,
        },
        # The single-use approval. Recovery re-emits this verbatim, which is the point.
        "authorization": {
            "request": {"request-hash": request_hash},
            "decision": {"request-hash": request_hash, "decision": "approve"},
        },
    }


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_a_recovered_effect_is_not_recovered_twice_when_its_record_fails_to_close(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The assertion DEF-7 turns on: one write-ahead record MUST become at most one envelope.

    Two would carry one single-use authorization, and the kernel refuses the second
    `gate-authorization-replayed` — permanently wedging the emitter's stream (§04 §7.2). The
    gateway's own `claim_gate_use` guard cannot catch this one: the claim was written by the
    original spend, so it reads "already claimed" in the legitimate case too.
    """
    request_hash = "b" * 64
    harness.store.record_intent(
        "intent-def7",
        harness.session.stream,
        DEVICE.id,
        _intent_body(harness, request_hash),
        [],
        clock_module.now(),
    )

    # The process stops — or the writer lock times out — after the effect is chained and before its
    # record closes. Stubbing the second statement is what that leaves on disk.
    monkeypatch.setattr(harness.store, "resolve_intent", lambda intent_id, at: None)

    assert harness.enforcer.recover_intents(harness.session) == 1
    assert harness.enforcer.recover_intents(harness.session) == 0, (
        "the same write-ahead record was recovered a second time; its effect is now on the chain "
        "twice under one single-use approval, which the kernel refuses gate-authorization-replayed"
    )

    chained = harness.chain()
    assert len(chained) == 1, f"one intent became {len(chained)} envelopes"
    assert chained[0]["authorization"]["decision"]["request-hash"] == request_hash


def test_recovery_closes_the_write_ahead_record_in_the_appends_own_transaction(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stated as a property rather than an outcome, so the fix cannot be re-broken by a rewrite.

    `open_intents` must come back empty even though the separate `resolve_intent` statement did
    nothing — because there is no separate statement left to run.
    """
    harness.store.record_intent(
        "intent-def7-closed",
        harness.session.stream,
        DEVICE.id,
        _intent_body(harness, "c" * 64),
        [],
        clock_module.now(),
    )
    monkeypatch.setattr(harness.store, "resolve_intent", lambda intent_id, at: None)

    harness.enforcer.recover_intents(harness.session)

    assert harness.store.open_intents(harness.session.stream, DEVICE.id) == [], (
        "the record is still open after its effect was chained; the next session re-emits it"
    )

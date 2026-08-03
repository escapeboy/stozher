# DEF-1 closed: one call is one question, however many times the run is replayed

**2026-08-03.** The gateway parked a second action request for a call a human was already being asked
about. Replaying a run therefore multiplied the approval queue: a nightly job re-run at 04:00 over its
own 03:00 queue asked for every signature again, and two runs left **54 undecided requests and 20
`(action, args-hash)` pairs appearing more than once**. That is what disqualified scheduled and
standing-mandate operation — the safe-autonomy rung of this product — because §09 §7 names approval
fatigue as an availability attack and this was the component delivering it.

**`spec/` was silent, and the silence was the classification.** §06 §4.3 rule 1 puts idempotency on
the kernel and it is discharged. §06 §1.1 makes the fresh `nonce` normative — *"so an approval of one
is not an approval of the other"* — which forecloses deriving the nonce from the call's fields. §06
§4.2 said what an approval covers and nothing about a component holding an **unanswered** request. No
clause required the reuse and none forbade it, so the duplicate was conformant.

## The rule, and the correction it needed

`spec/06 §4.2` now opens its second half with **"Re-submission of an identical request MUST be
idempotent."** A component MUST look for a request it already holds for the same call before building
one, and where one exists it MUST resolve to that request — returning the §4.1 `parked` refusal
carrying **that** request's `request-hash` — rather than enqueue a duplicate. Four numbered clauses
follow: identity is **field-wise** over §1.1's nine members; a pending request is matched on them
*before* it is classified as decided or new; a held request past its `not-after` MUST NOT be reused;
a decided or consumed row belongs to §3 and not here.

The proposal's phrasing — "idempotent by the same request-hash" — is **wrong and was corrected**, and
the correction is the whole content of the rule. `nonce` is inside the hashed object, so two
submissions of one call *never* share a `request-hash`; that is exactly the defect. The same property
that stops an approval of one request from approving another is what makes the hash unusable as the
identity of the *call*. The section says so explicitly, and says why the duty cannot be pushed to the
queue: the kernel is right to keep the two rows apart, and collapsing them there would be the kernel
deciding on the approver's behalf.

**Bound by vectors in the same change.** `spec/vectors/gate-resubmission.json` — 12 vectors,
`role: "primitive"` — covering the reuse, the oldest-copy rule, the decided and consumed rows, an
expired request, an expired copy that must not hide a live one, and four counterfactuals where a
single differing field (target, `args-hash`, classification, mandate) makes it a different call. Every
vector carries the request the component *would* have minted, whose hash differs from every held hash,
so "deduplicate by request-hash" fails the file rather than passing it. A second generator run leaves
`git status --short spec/vectors/` empty. The gateway runs the file against a real `GatewayStore`; the
kernel runs it against the real `gatequeue::validate`, which is the half it owns — request identity
and expiry.

## The fix

`store.py`: the one query became two disjoint ones. `decided_for` answers *"has this been answered?"*;
`outstanding_for` answers *"has this been asked?"* — undecided, unconsumed, still inside `not-after`,
oldest first. It was a single `SELECT` on `decision_json IS NOT NULL`, which discarded the row it
needed before the identity fields were ever compared. `park_unique` does the lookup and the insert in
one `BEGIN IMMEDIATE`, because a stdio gateway is one process per client connection: two connections
of one caller are two processes over one database file, and a job that starts twice a second apart has
both reading "nothing is outstanding" before either writes. A check outside the write would have closed
the 03:00/04:00 case and left the same-second one open.

`enforce.py::_gate` resolves to the held request, re-submits **that same object** to the kernel — whose
route is idempotent for it, and which repairs a park that never reached the queue during an outage —
and raises the same `parked` refusal with the original `request-hash`. It does not re-notify the
operator, and it does not re-park the §10 §4.3 catalog seed: that second request carries a fresh nonce
of its own and would duplicate in exactly the way the first no longer does.

## What binds it

The two quarantined reproductions left the quarantine and became six unquarantined tests in
`gateway/tests/test_def1_replay_idempotence.py`: the reuse, the store lookup, **two identical calls
racing to park exactly one request**, **a request past its `not-after` that must not be reused**, one
operator notification per question, and the counterfactual that two calls differing only in
`args-hash` still park separately. They drive the gateway's own minting path, not a fixture's — which
is why nothing caught this before: `stozher-testkit` derives `nonce` deterministically from the call's
fields, so every kernel test re-parked the *same* object and watched idempotency work. A fixture that
imitates the producer does not bind to it.

The kernel's quarantined test was un-ignored and its expectation corrected. It had asked the kernel to
collapse two requests differing only in nonce; that is the one thing §06 §1.1 forbids. It now asserts
both halves — the queue is idempotent for one *request* (201 then 200, one row) and must not be for one
*call* (two rows, two nonces) — which is precisely the division of duty the new §4.2 rests on.

**Mutation-tested, three counterfactuals, each reverted after being observed:**

1. `enforce.py` reverted, `store.py` kept → `test_a_repeated_identical_call_resolves_to_the_request_already_pending`,
   the race test and the notify-once test **fail**; the store lookup, expiry and different-calls tests
   still pass. The fix is load-bearing exactly where it is claimed to be.
2. The nine-field comparison replaced by "match everything" →
   `test_two_different_calls_still_park_separately` **fails**, and so does
   `gate-resubmission.json/a-different-target-is-a-different-call`. This is the counterfactual that
   matters: the change did not make every call resolve to one pending row.
3. The `not-after` guard removed → `test_a_request_past_its_not_after_is_not_reused` **fails**, and so
   does `gate-resubmission.json/the-outstanding-request-has-expired`. Without it the fix would have
   silently resurrected requests nobody can answer.

## Measured

```
./gateway/.venv/bin/python3 -m pytest gateway/tests -q                 188 passed, 5 deselected
./gateway/.venv/bin/python3 -m pytest gateway/tests -q -m open_defect  4 failed, 1 passed
cargo test --manifest-path kernel/Cargo.toml                           351 passed, 1 ignored
```

From 181 passed / 7 deselected and 349 passed / 2 ignored. The gateway gains DEF-1's two
reproductions plus four new tests, and the `gate-resubmission.json` vector case; the kernel gains the
new vector test and the un-ignored DEF-1 test. The quarantine is smaller by DEF-1 and still red by
design for DEF-2 and DEF-4, with DEF-4's control still passing.

`cargo clippy --all-targets -- -D warnings` and `cargo fmt --all --check` clean;
`ruff check src/ tests/` and `mypy --strict src/stozher_gateway/` clean. `#[allow]` stays at 1
(pre-existing, unchanged by this run); `type: ignore` stays at 2 (`governed.py`, `money.py`).
`cargo fmt --all --check` had one pre-existing violation in `open_defects.rs` (a chain over the
60-column `chain_width` in `request_for`, untouched by the defect work); it is reflowed here because
the file was being edited anyway and the gate is meant to be green.

`docs/open-defects.md` records DEF-1 **closed** with the rule that closed it, and
`test_defect_register.py` is green in both directions — the register and the `open_defect` marker
agree, and no quarantined test outlives its defect. `docs/spec-debt.md` §2 records the hole as paid,
distinguishing it from the eight rows still outstanding.

**What this restores.** A component that cannot be run twice cannot be scheduled and cannot hold a
standing mandate. A cron job, a nightly agent and a restarted long-running session now ask a human
once per pending call, whatever their restart count — which is the rung the product's safe-autonomy
claim stands on, and it was not standing before this change.

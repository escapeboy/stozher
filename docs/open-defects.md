# Open defects — the register the quarantined tests bind to

Every defect reported after the 2026-07-28 QA remediation, with its classification and the
executable evidence for it. **This file is the register; `tests/test_defect_register.py` fails if it
and the `open_defect` marker disagree.** A defect with no test is a claim, and a quarantined test for
a defect nobody recorded is orphaned evidence — the meta-test forbids both.

Evidence is *committed and excluded*, not deleted:

```sh
./gateway/.venv/bin/python3 -m pytest gateway/tests -q                 # 188 passed, 5 deselected
./gateway/.venv/bin/python3 -m pytest gateway/tests -q -m open_defect  # 4 failed, 1 passed
cargo test --manifest-path kernel/Cargo.toml                           # 351 passed, 1 ignored
cargo test --manifest-path kernel/Cargo.toml --test def2_mandate_swap -- --ignored
```

The quarantined run is **red by design**. Each failure is the defect stating itself; the one pass is
a control (see DEF-4). DEF-1's evidence left the quarantine when it was closed, which is why
`--test open_defects -- --ignored` no longer names anything: that file's one test is in the default
run.

| Id | Status | Classification | Severity | One line |
|---|---|---|---|---|
| DEF-1 | closed | **spec hole**, now stated | high | Replaying a run duplicated the approval queue: the gateway re-parked instead of resolving to its own outstanding request. §06 §4.2 now requires the reuse; the gateway does it. |
| DEF-2 | open | **spec hole** + one implementation defect alongside | high | A component whose envelopes the kernel refuses keeps serving and keeps returning success; to `spec/` a refused emitter is merely a late one. |
| DEF-3 | closed | scope limit, stated | — | `Governor` does not support `async def`. It now refuses at decoration instead of recording `applied` before the body runs. |
| DEF-4 | open | **spec hole** (tooling/documentation) | high for adoption, none for security | No way to obtain a verified policy without a live kernel, so a cold CI container cannot open a session at all. The offline profile itself works. |
| DEF-5 | not a defect | — | — | Proposed: ambient-state authorization on the `Governor` path. Investigated and **not found**; four independent bindings recompute authority per call. |

## DEF-1 — the queue duplicated on replay. Closed 2026-08-03.

**The exact break:** `GatewayStore.decided_for` selected `WHERE decision_json IS NOT NULL AND
consumed_at IS NULL`, so a request that was *outstanding* was filtered out before its identity fields
were compared. `Enforcer._gate` therefore minted a fresh `nonce` (`gate.action_request`, *"128 bits
of fresh entropy"*) and parked a second row. The kernel's own route is correct and idempotent by
`request-hash` (`http.rs`, `"the route recognised the request it already holds"`), which cannot help
because `nonce` is inside the hashed object.

**Why it was a spec hole rather than a bug:** §06 §4.3 rule 1 puts the idempotency duty on the kernel
and it is discharged. §06 §1.1 makes the fresh `nonce` normative — *"so an approval of one is not an
approval of the other"* — which forecloses deriving it from the call's fields. §06 §4.2 said what an
approval covers and nothing about a component holding an **unanswered** request. No clause required
reuse and none forbade it.

**The rule that closed it:** §06 §4.2, *"Re-submission of an identical request MUST be idempotent"* —
four numbered clauses making identity **field-wise** over the nine members of §1.1 rather than by
`request-hash`, requiring the match *before* a row is classified as decided or new, forbidding reuse
past `not-after`, and leaving decided and consumed rows to §3. Bound by
`spec/vectors/gate-resubmission.json` (12 vectors), which both implementations run.

**The fix:** `store.py` splits the one query into `decided_for` (answered) and `outstanding_for`
(unanswered, still inside `not-after`, oldest first), and `park_unique` does the lookup and the
insert inside one `BEGIN IMMEDIATE` — the duplicate is created by a race between two stdio processes
as readily as by a 04:00 re-run, and a check outside the write closes only the second.
`Enforcer._gate` resolves to the held request, re-submits **that same object** to the kernel (whose
route is idempotent for it, and which repairs a park that never reached the queue), and returns the
same `parked` refusal with the original `request-hash`. It does not re-notify, and it does not
re-park the §10 §4.3 catalog seed, which carries a fresh nonce of its own.

**Why no test caught it:** `stozher-testkit` derives `nonce` deterministically from the call's fields
(`stozher-testkit/src/lib.rs`, `action_request`), so every kernel test re-parked the same object and
observed idempotency working. Only the gateway mints entropy. A fixture that imitates the producer
does not bind to it — the same failure mode as the console parser in the 2026-07-28 entry. The
reproductions therefore drive the gateway's own minting path rather than a fixture's.

**Consequence, now removed:** it disqualified scheduled and standing-mandate operation. Every restart
multiplied one human's queue, and §09 §7 names approval fatigue as an availability attack.

**Evidence, unquarantined and in the default run:**
`gateway/tests/test_def1_replay_idempotence.py` (six, including the race, the expiry bound, the
notify-once bound, and the counterfactual that two genuinely different calls still park separately),
`gateway/tests/test_vectors.py` against `gate-resubmission.json`,
`kernel/stozher-kernel/tests/open_defects.rs::def1_the_queue_is_idempotent_for_one_request_and_cannot_be_for_one_call`,
`kernel/stozher-kernel/tests/kernel_vectors.rs::every_gate_resubmission_vector_matches_this_implementation`.

## DEF-2 — a refused component is indistinguishable from a healthy one

Full analysis and the proposed normative fix: **`docs/proposals/DEF-2-mandate-continuity.md`**.

The specification models an emitter in two states, chained locally and synced, and treats the
distance as latency (§04 §3). **A permanent refusal is a third state the text does not name**, so
every MUST that fires in it lands on the kernel — which discharges all of them (§04 §7 rejection
records, §09 §4.2 quiet streams). Nothing is required of the component: not to stop serving, not to
tell its caller, not even to keep the reason code. §03 §7 describes the state exactly and concedes
the cost in five words — *"and no explanation"* — in a rationale bullet with no RFC 2119 keyword.

**No vector covers a mid-stream mandate change.** Twenty vector files; this state is in none.

**Alongside, and not the cause:** `emitter.py:253` writes the kernel's reason into
`envelopes.push_error`, then `mark_pushed` runs `SET pushed_at = ?, push_error = NULL`
(`store.py:236`). The reason survives one statement, the row becomes indistinguishable from an
accepted one, and `pending_push_count()` reports zero. `push_error` is written in two places and read
nowhere. This is what makes the silence total rather than merely unhelpful. Left unfixed
deliberately: it does not remedy DEF-2 and fixing it alone would manufacture a sense of closure.

**Detection latency observed: seven days.** Bounded below by `checkpoint-interval` and above by
nothing — the only signal is a console row nobody has to open.

**Evidence:** `gateway/tests/test_def2_mandate_swap.py` (two quarantined, plus an unquarantined
counterfactual proving the harness lets a legitimate session through),
`kernel/stozher-kernel/tests/def2_mandate_swap.rs`.

## DEF-3 — `async def`, closed as a stated scope limit

`Enforcer.call` is synchronous and chains `applied` when `forward()` returns. For a coroutine
function that is the moment the coroutine is *constructed* — before the body runs, and still if
nobody awaits or the await raises. `governed.py:136` now refuses `iscoroutinefunction` and
`isasyncgenfunction` at decoration with a `TypeError` that says what to do
(`test_an_async_function_is_refused_rather_than_recorded_as_applied`, unquarantined and green).

Closed as a **defect**; open as a **limitation**. Every governed tool needs a synchronous entry
point, which is trivial for a script and awkward inside a running loop. Supporting it means an async
chokepoint in `Enforcer`, not a change to `governed`.

## DEF-4 — the offline profile works; there is no way in from cold

Three claims, verified independently:

- **Missing.** No path obtains a verified policy without a live kernel. `PolicyProvider.current`
  raises `policy-not-published` when the pull fails and the cache is empty; `open_session` calls it,
  so a cold CI container dies in `__enter__` before anything is classified. The only writer of that
  cache is a successful pull, and no CLI subcommand seeds it — the sole offline seeding in the
  repository is tests calling `store.cache_policy(...)` directly, which is why the in-process path
  always *looked* testable.
- **Implemented and working.** With one cached policy and the kernel on a dead port, a `read`
  proceeds and folds and a `consequential` parks locally — `{read: allow, benign: allow,
  consequential: block}` exactly as §05 §7 requires. This is the run's one **passing quarantined
  test**, kept as a control: without it, "no offline mode" reads as true.
- **Misdesigned, small.** `[gateway] enabled = false` is read only by `plugin.py:58` and a `config
  check` finding. `Governor` builds a `Gateway` unconditionally, so the session opens and the call is
  gated. Nothing documents the flag as MCP-only while the README presents it as *the* switch.

An agent suite that needs a *consequential* call to succeed cannot be satisfied by any offline mode —
§05 §7 means it can never acquire a human signature offline. What it needs is a fixture-signed
approval.

**Evidence:** `gateway/tests/test_open_defects.py::test_def4_*`.

## DEF-5 — proposed, investigated, not found

The `Governor` path was audited for ambient-state authorization, the ADR-0002 anti-lesson. **None
exists**, and it is the same code as the proxied path: the mandate is walked per call at that call's
time; the gate decision is located by the call's own nine fields including `args-hash`; it is consumed
single-use and durably, with a reinstated row refused `gate-authorization-replayed`; and §06 §2 binds
the decision to `object_hash(request)`, which the kernel re-verifies at ingest. **The session is
identity, not authority.**

Bound by five green, unquarantined tests in `gateway/tests/test_governed_functions.py`, including one
that moves the clock two days past the mandate mid-`with` and watches the next call blocked. Recorded
in ADR-0028.

## Last updated

2026-08-03, DEF-1 closed. `main` = `develop` = `47fc577` plus this run's work.

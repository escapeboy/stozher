# Open defects — the register the quarantined tests bind to

Every defect reported after the 2026-07-28 QA remediation, with its classification and the
executable evidence for it. **This file is the register; `tests/test_defect_register.py` fails if it
and the `open_defect` marker disagree.** A defect with no test is a claim, and a quarantined test for
a defect nobody recorded is orphaned evidence — the meta-test forbids both.

Evidence is *committed and excluded*, not deleted:

```sh
./gateway/.venv/bin/python3 -m pytest gateway/tests -q                 # the default run
./gateway/.venv/bin/python3 -m pytest gateway/tests -q -m open_defect  # the quarantine, and only it
cargo test --manifest-path kernel/Cargo.toml -- --test-threads=1       # the kernel
```

*(The pass counts that used to stand in those comments were four days stale by 2026-08-04. A number
in a document is a claim with no test behind it — `docs/CONTRIBUTING.md` says why, at length.)*

## The three statuses, and the one added on 2026-08-04

- **`open`** — the mechanism is known well enough to reproduce, and a quarantined test does. This is
  the only status the meta-test demands evidence for.
- **`observed`** — *added 2026-08-04 for DEF-7.* Something real happened and is on record, and the
  mechanism is **not yet established**, so no honest reproduction can be written. A row here MUST
  cite where the observation lives (a CI run id, a log) so a reader can go and look. It is a
  deliberately uncomfortable status: it exists so that "we saw it once and could not pin it" has
  somewhere to be written down, instead of being rounded to "flake" and forgotten — which is what
  nearly happened to DEF-6, and DEF-6 was real.
- **`closed`** / **`not a defect`** — the reproduction has moved into the default suite, or there
  was nothing to reproduce.

**The quarantine is empty.** All four of the original defects are closed, and each one's evidence moved into
the default suite as it went: DEF-1 to `gateway/tests/test_def1_replay_idempotence.py`, DEF-2 to
`gateway/tests/test_def2_mandate_swap.py` and `kernel/stozher-kernel/tests/def2_mandate_swap.rs`,
DEF-4 to `gateway/tests/test_policy_bundle.py`. DEF-4's deliberate *pass* went with them and is
still a control: it is the reason "there is no offline mode" cannot be said.

The marker and its two commands stay. `test_defect_register.py` binds them to this file in both
directions, so the next open defect has somewhere to go and cannot be recorded without evidence.

| Id | Status | Classification | Severity | One line |
|---|---|---|---|---|
| DEF-1 | closed | **spec hole**, now stated | high | Replaying a run duplicated the approval queue: the gateway re-parked instead of resolving to its own outstanding request. §06 §4.2 now requires the reuse; the gateway does it. |
| DEF-2 | closed | **spec hole** + one implementation defect alongside | high | A component whose envelopes the kernel refuses keeps serving and keeps returning success; to `spec/` a refused emitter is merely a late one. |
| DEF-3 | closed | scope limit, stated | — | `Governor` does not support `async def`. It now refuses at decoration instead of recording `applied` before the body runs. |
| DEF-4 | closed | **spec hole** (tooling/documentation), closed in the implementation | high for adoption, none for security | There was no way to obtain a verified policy without a live kernel, so a cold CI container could not open a session at all. `policy export-bundle` is the way in; the offline profile itself always worked. |
| DEF-5 | not a defect | — | — | Proposed: ambient-state authorization on the `Governor` path. Investigated and **not found**; four independent bindings recompute authority per call. |
| DEF-6 | closed | implementation defect, introduced by DEF-2's fix | high (availability) | One `503 x-store-unavailable` — the kernel's own *"could not answer; retry"* — wedged the emitter's stream permanently. Found by an intermittent `blocked` where `parked` was expected; reproduced deterministically. |
| DEF-7 | observed | two sites fixed; the residue has no established mechanism | high (availability); **no confidence loss** — the kernel refused correctly throughout | A catalog seed could be applied twice, spending one single-use approval on two envelopes; the kernel refused the second `gate-authorization-replayed` and the emitter's stream wedged. Found by CI on Linux (run **30905170959**, 1 of 3 runs) — never on the author's macOS in eight days; reproduced deterministically with no concurrency; **two** check-then-act sites found and fixed (`Store.claim_gate_use`), each bound by a reproduction that fails deterministically when reverted — **and the original CI failure still reproduces on Linux at 1-in-2** (run 30910475650, the commit containing both fixes). Two real defects are closed inside this one; the defect the row was opened for is not. |

## DEF-7 — one approval, two envelopes. Open, with a deterministic reproduction.

**Found by CI on its first run, on a machine that was not the author's.** Eight days of running this
suite many times a day on macOS never produced it; the first Linux run did — `test_the_gate`, an
effect refused `gate-authorization-replayed` at `seq` 7 and the stream wedged. GitHub Actions run
**30905170959**, job 91978477109. It failed 1 of 3 runs of that job.

**Reproduced deterministically, and it needs no concurrency at all** —
`gateway/tests/test_def7_seed_replay.py`, quarantined. The observation looked like a race. It is not
one; it is a missing fact.

### The mechanism

`Enforcer._seed_catalog` ends with two statements, in this order and in two separate transactions:

```python
envelope_id = self._emitter.append(...)   # spends the approver's single-use signature
self._store.seed_catalog(...)             # raises the guard, afterwards
```

The only thing preventing a second application is `catalog_entry(server, tool) is None`, checked at
both call sites — `apply_pending_seeds`, which runs at **every session open**, and the gate path
after a decision verifies. And `seeded_pending()` does not exclude seeds that have already been
applied: **the fact "this seed is spent" lives in a different table, is written after the envelope,
and is never marked on the seed itself.**

So the window between the append and the catalog write is one in which the guard still passes.
Anything that looks in it seeds again: a crash between the two statements, or a second gateway
process — a deployment runs one per MCP client over one SQLite file, and `apply_pending_seeds` is
the first thing each of them does.

### What is established, and what is still not

*Established:* the double application, from the code and from a test that provokes it without
concurrency. Also that the kernel is right — a single-use approval presented twice is refused, which
is `spec/06 §5` working. **No authority leaked.** The cost is availability: the emitter wedges its
own stream, and §05 §7.1's grace then serves a `read` while flagging it, which is also correct.

*Still not:* which of the three routes into the window the CI run actually took. The reproduction
shows the state is reachable and that the code re-applies from it; it does not show that overlapping
sessions are what got there on 2026-08-04. That distinction is kept because the fix differs — an
idempotence marker on the seed fixes all three, while serialising session open fixes only one.

### Correction to this row's first version

Filed on 2026-08-04 as `observed`, with the mechanism called *"a hypothesis and recorded as one"* and
the next step costed as *"running the e2e file in a loop on Linux"*. The loop was never needed: the
cheaper half of that plan — read whether the catalog write and the decision's consumption are one
transaction — answered it in one file read. **Recording the hypothesis as a hypothesis is what made
the cheap check the obvious next move instead of the expensive one.**

### Two sites fixed, and the defect this row was opened for is not

`Store.claim_gate_use` is the mechanism: the same `INSERT OR IGNORE` into `gate_seen`, whose
`request_hash` is a PRIMARY KEY, **read for its outcome instead of run for its effect**. Exactly one
caller wins it, across threads and across processes, in one statement that cannot be half-done.

**Site 1 — `_seed_catalog`.** The seed's decision is claimed before the envelope that spends it, and
the seed's verification is given the seen-set the call path always had (it was passed `set()`, so a
seed this very process had spent verified as fresh). Bound by
`test_def7_a_seed_whose_catalog_write_did_not_land_is_applied_again`, which needs no concurrency.

**Site 2 — `_authorize`, the call's own approval.** This looked correct: `record_gate_use` is written
*before* the effect is emitted, which reads like claim-before-spend. It is not. An `INSERT OR IGNORE`
nobody reads means two callers in the window both "succeed" and both emit. Bound by
`test_def7_two_callers_racing_one_approval_spend_it_once`, which fails **6 of 6** when the site is
reverted and passes 5 of 5 with it — deterministic in both directions.

Both are real defects and both are closed. Neither is the one this row was opened for.

### The correction, which is the important part of this section

**This row was marked `closed` on 2026-08-04 and that was wrong.** The evidence offered for it was
local: 224 passed × 5, `test_the_gate` 8 of 8 in isolation, against roughly 1-in-6 before. Every one
of those numbers was true and none of them was the claim. CI on the very commit carrying both fixes
failed the same way — `gate-authorization-replayed`, `seq` 7, same stream — run **30910475650**,
while the *same commit* on the other branch passed (30910472179).

**Correction to the rate, made the next hour.** That paragraph first said the residue reproduces on
Linux *"at roughly 1 in 2"*. It was an estimate from a sample of two — the one failure and the one
pass that happened to sit beside it — written into a document as though it were measured. On the
fixed code the record is **1 failure in 8 Linux runs** — 30910475650 failed; 30910472179,
30910991085, 30911348123, 30911348909 and three dispatched runs (30911638257, 30911640302,
30911642652) passed. Before the fixes it was 1 in 3. **These two rates are not distinguishable at
these sample sizes and this row does not claim they are**: the one failure sits on a commit carrying
both fixes, so the residue is real whatever the rate. Sampling stopped here rather than running the
workflow until it failed — the instrumentation added the same day means the next occurrence, whenever
it comes, names the action in its own failure message. A rate is a claim like any other and
this one had no test behind it, which is the failure this file spent the week correcting elsewhere.

The mistake has a name and this repository has been cataloguing it all week: **a fix was verified
against the symptom's frequency rather than against the symptom.** An intermittent failure getting
rarer looks identical to an intermittent failure being fixed, and the only thing that separates them
is a reproduction — which existed for the two sites, and not for this.

### What is known about the residue

Nothing established. The gateway's own "already claimed" line never appears in the failing run, so
whatever emits the second envelope does not pass through site 1's claim. The e2e runs three gateway
**processes** in sequence over one SQLite file, and the refused envelope is at `seq` 7 of a stream
those processes share.

**Next diagnostic, in order of cost:** read the failing run's envelope at `seq` 7 to learn which
action replayed — the log truncates it — before proposing any third site. `gh run view --job <id>
--log` carries the full record. Only after that is it worth theorising, and this time the theory
does not get to be the fix.

## DEF-6 — a kernel that could not answer was recorded as one that said no

**Introduced by DEF-2's fix, found during merge verification of it, and reproduced deterministically
rather than left as a flake.** The symptom was `assert parked["result"] == "parked"` failing with
`'blocked'` in `test_s4_native_gates.py`, twice, never on a targeted re-run.

**The exact break.** `emitter.py::push_pending` recorded a wedge on `if response.accepted:` being
false, and `KernelResponse.accepted` (`kernel_client.py`) is
`status in (200, 201) and body["result"] in (None, "ok", "accepted")`. The kernel answers a genuine
refusal with **422** and a normative reason code (`http.rs`, `ingest::Outcome::Rejected`); it answers
**503 `x-store-unavailable`, *"the kernel could not answer; retry"*** for any store error, and **401
`x-caller-unauthenticated`** when there is no subject to judge for. All three were "not accepted", so
all three wedged.

**Why it was severe rather than untidy.** A wedged stream is one `push_pending` stops submitting on,
so nothing can ever be accepted on it, so **the wedge can never clear itself** — §05 §7.2 rule 2
makes acceptance the only exit. A momentary SQLite contention in the kernel therefore became a hard
stop liftable only by a root-signed §04 §7.2 resume, and every `consequential` call in between was
refused outright instead of parking. That is precisely the denial-of-service failure §05 §7.1's
rationale paragraph claims the bounded grace window avoids — reintroduced one layer below the
decision function, where `sync.decide` could not see it. The decision function was never wrong; the
*storage* blurred two outcomes it is required to distinguish.

**The fix.** `KernelResponse.refuses_the_object` — an answer is a refusal only when the kernel judged
the bytes: not 5xx, not 401/403, and carrying a reason code without the `x-` prefix that §00 §1
reserves for conditions this specification does not name (`codes.rs::REGISTER` is exactly the set of
non-refusals). Anything else is §05 §7.1's `unreachable`: retried, logged at `warning`, no wedge.
`spec/05 §7.1` clause 1 gains the converse MUST NOT, because only one direction of it was obvious.

**Evidence:** `gateway/tests/test_def2_mandate_swap.py::test_a_kernel_that_could_not_answer_does_not_wedge_the_stream`
(parametrized over 503 and 401) and `::test_a_kernel_that_refused_the_object_still_wedges_the_stream`
as its control. Unquarantined and in the default run. Mutation-tested: restoring
`return not self.accepted` fails both parametrizations and leaves the control green.

**Not proven:** that a 503 is what the two observed `test_s4_native_gates.py` failures actually hit.
The mechanism is proven to produce exactly that symptom from a transient condition, and the failing
runs' logs were not kept. A recurrence is self-identifying — the emitter logs the reason code and the
stream on both paths, and they no longer read alike.

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

## DEF-2 — a refused component was indistinguishable from a healthy one — **closed**

Full analysis and the proposal this change implements: **`docs/proposals/DEF-2-mandate-continuity.md`**.

The specification modelled an emitter in two states, chained locally and synced, and treated the
distance as latency (§04 §3). **A permanent refusal was a third state the text did not name**, so
every MUST that fired in it landed on the kernel — which discharged all of them (§04 §7 rejection
records, §09 §4.2 quiet streams). Nothing was required of the component: not to stop serving, not to
tell its caller, not even to keep the reason code. §03 §7 described the state exactly and conceded
the cost in five words — *"and no explanation"* — in a rationale bullet with no RFC 2119 keyword.
**Detection latency observed: seven days.**

**What closed it.**

- **`spec/05 §7.1`, "Refused is not offline"** — three submission outcomes rather than two; a
  component MUST NOT treat `refused` as `unreachable`; the reason decides whether grace exists
  (`mandate-*` and `policy-not-published`: none, for any class), the class decides who may use it
  (`read`/`benign` only, each served effect a counted finding); expiry blocks everything; the caller
  gets the §06 §4.1 object carrying the kernel's reason code verbatim. `§7.2` adds the component's
  side of recovery.
- **`spec/09 §4.2`** gains a third bullet: refused is surfaced immediately and distinguishably from
  quiet. *Quiet is the absence of evidence; refused is evidence.*
- **`spec/04 §7.2`, "Resuming a wedged stream"** — the exit ADR-0007 §6 asked for and `spec/`
  never had: a root-approved `kernel.resume_stream` envelope on `kernel:core` bridging exactly one
  position with the `object-hash` the rejection record already holds. It validates nothing: the
  refused envelope stays refused and the rejection record stays.
- **`spec/10 §1.4`** names the resolver — *"resolvable" means resolvable by the kernel*.
- **Three new vector files** (`sync-outcome.json` 16, `stream-status.json` 9,
  `stream-recovery.json` 7), including the case that stops "refuse everything" passing:
  `unreachable` + `read` + `offline.read: allow` → **serve**.

**Alongside, and not the cause — also fixed here:** `emitter.py::push_pending` wrote the kernel's
reason into `envelopes.push_error`, then `mark_pushed` ran `SET pushed_at = ?, push_error = NULL`
(`store.py::mark_pushed`). The reason survived one statement, the row became indistinguishable from
an accepted one, and `pending_push_count()` reported zero. `mark_pushed` now takes the outcome and
writes it in one statement; §05 §7.1 clause 2 forbids erasing it on any later transition.

**Evidence, now unquarantined and in the default runs:**
`gateway/tests/test_def2_mandate_swap.py` (three, including the counterfactual proving the harness
lets a legitimate session through), `kernel/stozher-kernel/tests/def2_mandate_swap.rs` (three,
including both recovery negatives).

**What remains, and is not this defect:** external security review of the recovery act, and the
fleet-wide question of what an operator console should offer as the *action* — the kernel accepts a
signed resume, and no CLI subcommand mints one yet, so today an operator assembles it the way they
assemble any other gated effect. Tracked in `docs/spec-debt.md` row 3.

## DEF-3 — `async def`, closed as a stated scope limit

`Enforcer.call` is synchronous and chains `applied` when `forward()` returns. For a coroutine
function that is the moment the coroutine is *constructed* — before the body runs, and still if
nobody awaits or the await raises. `governed.py:136` now refuses `iscoroutinefunction` and
`isasyncgenfunction` at decoration with a `TypeError` that says what to do
(`test_an_async_function_is_refused_rather_than_recorded_as_applied`, unquarantined and green).

Closed as a **defect**; open as a **limitation**. Every governed tool needs a synchronous entry
point, which is trivial for a script and awkward inside a running loop. Supporting it means an async
chokepoint in `Enforcer`, not a change to `governed`.

## DEF-4 — the offline profile works; there was no way in from cold. Closed.

Three claims, verified independently at triage, and what each of them turned into:

- **Missing → built.** No path obtained a verified policy without a live kernel. `PolicyProvider`'s
  `current` raises `policy-not-published` when the pull fails and the cache is empty; `open_session`
  calls it, so a cold CI container died in `__enter__` before anything was classified. The only
  writer of that cache was a successful pull, and no CLI subcommand seeded it. There is now a second
  writer: **`stozher-kernel policy export-bundle`** signs the policy, the revocation set and a
  checkpoint anchor into one root-signed document, and `Gateway._bootstrap_from_bundle` verifies it
  against `org.roots` and seeds both caches before the policy provider ever reads them. `max-age`
  lives **inside** the signature, so the file-holder cannot extend it, and an expired bundle refuses
  to start rather than warning (`bundle.py::load_policy_bundle`, "an expired bundle makes the
  component refuse to start").
- **Implemented and working, and still is.** With one cached policy and the kernel on a dead port, a
  `read` proceeds and folds and a `consequential` parks locally — `{read: allow, benign: allow,
  consequential: block}` exactly as §05 §7 requires. This was the run's one **passing quarantined
  test** and it is now
  `test_policy_bundle.py::test_the_offline_profile_is_implemented_and_works_from_a_warm_cache`,
  unquarantined and kept deliberately as a control: it uses no bundle, so if the bundle path ever
  became the only way the offline profile works, this is the test that notices.
- **Misdesigned → ruled.** `[gateway] enabled = false` was read only by `plugin.register` ("the
  default. A Harbormaster with the distribution installed but enforcement off…") and a `config check`
  finding. `Governor` now honours it too, by **refusing to be built**. The other reading — run the
  decorated functions ungoverned — is a gate disabled by editing a config key, so on this path the
  flag can only mean *refuse*. The two paths differ because "off" has a safe meaning for the MCP
  server (register nothing; Harbormaster is what it was) and none for a `Governor`, whose caller has
  already wrapped functions that apply effects.

An agent suite that needs a *consequential* call to succeed still cannot be satisfied by any offline
mode — §05 §7 means it can never acquire a human signature offline. What it needs is a fixture-signed
approval, and `gateway/README.md` §"Running an agent suite in CI" is the recipe.

**What was not done:** no `spec/` text. The bundle is an implementation of §05 §7's bootstrap and
needs no new normative clause to be correct, but the wire object deserves one before a second
implementation reads it — the proposal is `docs/proposals/DEF-4-policy-bundle.md`.

**Evidence:** `gateway/tests/test_policy_bundle.py` (16 tests, default suite),
`kernel/stozher-kernel/tests/policy_bundle_cli.rs` (5 tests against the real binary).

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

2026-08-03, triage run: the four defects classified and quarantined.

2026-08-03, fix run. **DEF-1 closed** — `spec/06 §4.2` gains the idempotent-re-submission rule and
identity is field-wise, not by `request-hash`. **DEF-4 closed** — `policy export-bundle` on the
kernel, bundle verification with bounded staleness on the gateway, and the `[gateway] enabled`
ruling that it governs the in-process path too. The normative text the bundle still lacks is
proposed in `docs/proposals/DEF-4-policy-bundle.md`; no `spec/` edit was made for it.

2026-08-03, fix run. **DEF-2 closed** — `spec/05 §7.1` names the refused state, the grace is
reason-gated then class-bound, and `kernel.resume_stream` makes a wedge reversible under a root
signature without validating anything it bridges.

2026-08-03, same run. **DEF-6 closed** (`ae0d127`, `26eafe9`) — `push_pending` treated anything that
was not an acceptance as a verdict about the bytes, so one `503 x-store-unavailable` (the kernel's
own *"could not answer; retry"*) wedged the emitter's stream permanently. Found as an intermittent
`blocked` where `parked` was expected, and reproduced deterministically before it was fixed rather
than filed as a flake. The row was marked closed in the table above on the day and **this entry was
not written until 2026-08-04**, which is the same ledger-staleness the spec-debt inventory was found
to have; recorded late rather than backdated.

2026-08-04. **No defect opened or closed.** The run closed the last of `docs/spec-debt.md` — row 8,
`spec/06 §4.4` rule 9, ADR-0032 — and reconciled five stale claims in that inventory. Noted here
because "the defect register did not change" is a fact worth being able to read, and because the
`gate-arguments-hash-mismatch` record it added is now a **finding** on `/console/rejections`: the
class of event this register exists for, arriving through a surface rather than through a log.

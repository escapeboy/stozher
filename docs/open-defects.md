# Open defects — the register the quarantined tests bind to

Every defect reported after the 2026-07-28 QA remediation, with its classification and the
executable evidence for it. **This file is the register; `tests/test_defect_register.py` fails if it
and the `open_defect` marker disagree.** A defect with no test is a claim, and a quarantined test for
a defect nobody recorded is orphaned evidence — the meta-test forbids both.

Evidence is *committed and excluded*, not deleted:

```sh
./gateway/.venv/bin/python3 -m pytest gateway/tests -q                 # 209 passed
./gateway/.venv/bin/python3 -m pytest gateway/tests -q -m open_defect  # 209 deselected — empty, all four closed
cargo test --manifest-path kernel/Cargo.toml                           # 356 passed, 1 ignored
```

**The quarantine is empty.** All four defects are closed, and each one's evidence moved into
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

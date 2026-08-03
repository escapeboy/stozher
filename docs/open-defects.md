# Open defects — the register the quarantined tests bind to

Every defect reported after the 2026-07-28 QA remediation, with its classification and the
executable evidence for it. **This file is the register; `tests/test_defect_register.py` fails if it
and the `open_defect` marker disagree.** A defect with no test is a claim, and a quarantined test for
a defect nobody recorded is orphaned evidence — the meta-test forbids both.

Evidence is *committed and excluded*, not deleted:

```sh
./gateway/.venv/bin/python3 -m pytest gateway/tests -q                 # 197 passed, 4 deselected
./gateway/.venv/bin/python3 -m pytest gateway/tests -q -m open_defect  # 4 failed
cargo test --manifest-path kernel/Cargo.toml                           # 354 passed, 2 ignored
cargo test --manifest-path kernel/Cargo.toml --test open_defects -- --ignored
cargo test --manifest-path kernel/Cargo.toml --test def2_mandate_swap -- --ignored
```

The quarantined run is **red by design**. Each failure is the defect stating itself. It used to carry
one deliberate *pass* — DEF-4's control — which moved into the default suite when DEF-4 closed
(`gateway/tests/test_policy_bundle.py`); it is still a control, and still the reason "there is no
offline mode" cannot be said.

| Id | Status | Classification | Severity | One line |
|---|---|---|---|---|
| DEF-1 | open | **spec hole** | high | Replaying a run duplicates the approval queue: the gateway re-parks instead of resolving to its own outstanding request. |
| DEF-2 | open | **spec hole** + one implementation defect alongside | high | A component whose envelopes the kernel refuses keeps serving and keeps returning success; to `spec/` a refused emitter is merely a late one. |
| DEF-3 | closed | scope limit, stated | — | `Governor` does not support `async def`. It now refuses at decoration instead of recording `applied` before the body runs. |
| DEF-4 | closed | **spec hole** (tooling/documentation), closed in the implementation | high for adoption, none for security | There was no way to obtain a verified policy without a live kernel, so a cold CI container could not open a session at all. `policy export-bundle` is the way in; the offline profile itself always worked. |
| DEF-5 | not a defect | — | — | Proposed: ambient-state authorization on the `Governor` path. Investigated and **not found**; four independent bindings recompute authority per call. |

## DEF-1 — the queue duplicates on replay

**The exact break:** `store.py:341` — `decided_for` selects `WHERE decision_json IS NOT NULL AND
consumed_at IS NULL`, so a request that is *outstanding* is filtered out before its identity fields
are compared. `enforce.py:630` therefore mints a fresh `nonce` (`gate.py:87`) and parks a second row.
The kernel's own route is correct and idempotent by `request-hash` (`http.rs:449`), which cannot help
because `nonce` is inside the hashed object.

**Why it is a spec hole rather than a bug:** §06 §4.3 rule 1 puts the idempotency duty on the kernel
and it is discharged. §06 §1.1 makes the fresh `nonce` normative — *"so an approval of one is not an
approval of the other"* — which forecloses deriving it from the call's fields. §06 §4.2 says what an
approval covers and nothing about a component holding an **unanswered** request. No clause requires
reuse and none forbids it.

**Why no test caught it:** `stozher-testkit` derives `nonce` deterministically from the call's fields
(`stozher-testkit/src/lib.rs:441`), so every kernel test re-parks the same object and observes
idempotency working. Only the gateway mints entropy. A fixture that imitates the producer does not
bind to it — the same failure mode as the console parser in the 2026-07-28 entry.

**Consequence:** disqualifies scheduled and standing-mandate operation. Every restart multiplies one
human's queue, and §09 §7 names approval fatigue as an availability attack.

**Evidence:** `gateway/tests/test_open_defects.py::test_def1_*`,
`kernel/stozher-kernel/tests/open_defects.rs::def1_one_call_parked_twice_becomes_two_questions_for_one_human`.

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

2026-08-03, triage run. `main` = `develop` = `cf64bf7` plus this run's uncommitted work.
2026-08-03, DEF-4 closed: `policy export-bundle` on the kernel, bundle verification and bounded
staleness on the gateway, and the `[gateway] enabled` ruling. Proposal for the normative text the
bundle still lacks: `docs/proposals/DEF-4-policy-bundle.md`.

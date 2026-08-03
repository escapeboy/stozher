# Open defects — the register the quarantined tests bind to

Every defect reported after the 2026-07-28 QA remediation, with its classification and the
executable evidence for it. **This file is the register; `tests/test_defect_register.py` fails if it
and the `open_defect` marker disagree.** A defect with no test is a claim, and a quarantined test for
a defect nobody recorded is orphaned evidence — the meta-test forbids both.

Evidence is *committed and excluded*, not deleted:

```sh
./gateway/.venv/bin/python3 -m pytest gateway/tests -q                 # the default run
./gateway/.venv/bin/python3 -m pytest gateway/tests -q -m open_defect  # the quarantine
cargo test --manifest-path kernel/Cargo.toml
cargo test --manifest-path kernel/Cargo.toml --test open_defects -- --ignored
```

The quarantined run is **red by design**. Each failure is the defect stating itself; the one pass is
a control (see DEF-4). DEF-2's reproductions left the quarantine when it closed and are in the
default runs.

| Id | Status | Classification | Severity | One line |
|---|---|---|---|---|
| DEF-1 | open | **spec hole** | high | Replaying a run duplicates the approval queue: the gateway re-parks instead of resolving to its own outstanding request. |
| DEF-2 | closed | **spec hole** + one implementation defect alongside | high | A component whose envelopes the kernel refused kept serving and kept returning success; to `spec/` a refused emitter was merely a late one. Closed by naming the state (`spec/05 §7.1`), surfacing it (`spec/09 §4.2`), giving it an exit (`spec/04 §7.2`) and naming §10 §1.4's resolver. |
| DEF-3 | closed | scope limit, stated | — | `Governor` does not support `async def`. It now refuses at decoration instead of recording `applied` before the body runs. |
| DEF-4 | open | **spec hole** (tooling/documentation) | high for adoption, none for security | No way to obtain a verified policy without a live kernel, so a cold CI container cannot open a session at all. The offline profile itself works. |
| DEF-5 | not a defect | — | — | Proposed: ambient-state authorization on the `Governor` path. Investigated and **not found**; four independent bindings recompute authority per call. |
| DEF-6 | closed | implementation defect, introduced by DEF-2's fix | high (availability) | One `503 x-store-unavailable` — the kernel's own *"could not answer; retry"* — wedged the emitter's stream permanently. Found by an intermittent `blocked` where `parked` was expected; reproduced deterministically. |

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

2026-08-03. DEF-2 closed by the mandate-continuity change off `47fc577`; DEF-1, DEF-4 still open.

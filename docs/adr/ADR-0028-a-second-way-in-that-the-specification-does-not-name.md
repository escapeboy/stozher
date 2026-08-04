# ADR-0028 — A second way in that the specification does not name

**Date:** 2026-08-03
**Status:** accepted

ADR-0026 records *why* `Governor` exists: an integrator's rejection, and the security argument
against an in-process API that did not survive reading the code. It does not record that shipping it
put a **second entry point into the product that `spec/` does not describe**, and it says nothing
about what that entry point may emit or where its authority comes from. This is that record.

Per ADR-0013's rule, every claim below names the test that fails if it stops being true.

## 1. The deviation

`spec/` describes one way an action reaches the chain: an agent calls a tool, a proxy fronts the
upstream server, and the call transits the eleven steps of §10 §2 in order. Every conformance
statement is written about that caller.

`Governor` is a second way in. It opens the same session `Gateway.open_session` opens and puts a
**plain Python function in the caller's own process** through the same `Enforcer.call`, with no MCP
client, no stdio transport and no subprocess. It shipped on 2026-08-02 and is documented in exactly
two places — `deploy/README.md` §"a plain Python program" and the module docstring of
`gateway/src/stozher_gateway/governed.py`. `grep -rl Governor spec/` returns nothing.

What the deviation is, precisely:

- **It does not change the steps.** `governed_call` binds the arguments to names and calls
  `Enforcer.call(session, Call(server, tool, arguments, schema), forward)` — the same function, the
  same order, the same refusals, the same envelope bodies built by the same `_effect_body`. There is
  no second enforcement path to keep in step with the first.
- **It changes what "the caller" is.** On the proxied path the tool code is upstream, behind a
  transport, and `target` names the server the gateway is fronting. Here the tool code is a function
  in the same process and `server=` is a *scope the integrator declares*, which is what decides
  whether the action is `billing.issue_refund` or `acme.issue_refund` and therefore whether policy
  and the shipped catalog have anything to say about it. A conformance reader who assumes the scope
  came from a configured upstream will be wrong about this path.
- **It changes who can remove it.** The undecorated function is right there in the module. This is
  stated plainly in ADR-0026 and repeated here because it is the thing a spec reader would otherwise
  have to infer.

## 2. Where the authority comes from, checked rather than claimed

ADR-0002 is the anti-lesson this product exists to answer: FleetQ re-executed approved proposals by
flipping an ambient container binding, and authority that lives in process state cannot be audited.
`Governor` holds an open session for the life of a `with` block, which is the same *shape* that
mistake had. So the question is not whether the docstring says "same chokepoint" — it is whether a
second call can proceed on the first call's authority. The code says no, four ways:

1. **The mandate is walked on every call, at the time of that call.** `_require_mandate` re-runs
   `verify_mandate_chain(... at=self._clock.now(), revocations=…)` per call. Nothing is cached at
   `open()` but the subject, the derived key and the mandate document itself; the *verdict* is
   recomputed. A session whose mandate expires mid-block is refused mid-block.
2. **The gate decision is located by the call's own fields, never by the session.**
   `_gate` builds `fields` from subject, key, component, mandate-ref, policy-version, class, action,
   target and `args-hash`, and `store.decided_for` matches a parked row on all of them —
   `WHERE decision_json IS NOT NULL AND consumed_at IS NULL`. Different arguments are a different
   `args-hash` and find nothing.
3. **An approval is single-use, and its consumption is durable.** `_consume` calls
   `store.consume(request_hash)` and `store.record_gate_use(request_hash)`, so the next identical
   call finds no undecided row and parks afresh; and if the row were reinstated, `_seen_hashes`
   feeds §06 §2 step (11) and the decision is refused `gate-authorization-replayed`.
4. **The signature travels in the envelope.** `_effect_body` writes
   `authorization = {"request": …, "decision": …}` into the body that is signed, chained and pushed.
   §06 §2 step (2) binds the decision to `object_hash(request)` and step (10) binds that request to
   the envelope's own identity, mandate-ref, policy-version, class, action, target and `args-hash`.
   The kernel re-verifies all of it at ingest, on the only write route it has.

**Verdict: no ambient authorization on the Governor path.** The open session is an *identity* — a
subject, a derived signing key, a mandate reference and a stream — and every call presents that
identity's credentials again and has them checked again. There is no flag, no cached verdict and no
"approved" bit that a second call can read. What persists across calls is enforcement *input*
(policy, revocations, budgets, the catalog), each of which is either re-resolved per call or has a
staleness rule of its own; none of it is a decision about a call.

The one thing that genuinely outlives the call that provoked it is the **catalog seed** (§10 §4.3):
an approver's answer to a first call also classifies the tool, so later calls of that tool resolve
through a class instead of parking. That is not ambient state — it is a second signature in its own
chained envelope, verified by `verify_authorization` before it comes into force, dropped if it does
not verify — but an adopter should know that approving a first call answers two questions, and that
the second answer is durable.

## 3. What this path can emit

Three envelope kinds, and no others. `cognition` and `manifest` appear only in the conformance
driver; nothing on this path produces them.

| Kind | When | Class |
|---|---|---|
| `mandate` | once per session, at `open()`, deduped by a store mark | — |
| `effect` | `gateway.session_open`; every gated/refused/applied call; a catalog seed coming into force | whatever policy computes: `read`, `benign`, `consequential`, `prohibited` |
| `aggregate` | a `read` window closing — 500 events, 300 seconds, or `close()` | always `read` |

Effect outcomes are the five of §02 §4: `attempted` (the write-ahead row, chained only by
`recover_intents` after a crash), `applied`, `failed`, `blocked`, `denied`. A parked call emits
**nothing** — parking is a refusal with a request hash, not a record of an attempt.

**Reads fold exactly as on the proxied path.** A call classified `read` with no authorization takes
the `folded` branch: no write-ahead, no per-call envelope, one increment in an in-memory window keyed
by `(stream, subject-key, mandate-ref, policy-version)`. The window closes on a bound or on
`Emitter.stop()`, which `Governor.close()` calls.

**What a process that exits without flushing loses:** every `read` since the last window boundary,
in full — not degraded to a count, absent. Effect envelopes are already chained on disk and survive;
so does an open write-ahead row, which the next session chains as `attempted`. The reads are the only
records held solely in memory, which is why `close()` is not optional and why `__exit__` calls it.
A program that uses `Governor(...)` without the `with` block, or that is killed with `SIGKILL`,
loses them.

## 4. Stated scope limits (not defects)

**`async def` is refused at decoration**, with a `TypeError` that says why. `Enforcer.call` is
synchronous and chains `applied` as soon as `forward()` returns; for a coroutine function that is the
moment the coroutine object is *constructed* — before the body runs, and still if nobody awaits or if
the await raises. A record that says the effect happened before it did fails in the one direction an
audit must never fail in, so the decorator refuses rather than lying. This is a **scope limit with a
test**, not a silent defect.

What it costs an adopter whose tools are async: every governed tool must have a synchronous entry
point. In practice that is `asyncio.run(...)` or `loop.run_until_complete(...)` inside a small
synchronous wrapper, which is trivial for a script and awkward for a program that is already inside a
running event loop — there, the wrapper must hand the coroutine to another thread and block, and a
single-threaded async application effectively cannot use this path today. An in-process gate for
async tools needs an async chokepoint (`await forward()` between the write-ahead and the chain), and
that is a change to `Enforcer`, not to `governed`.

## 5. What was rejected

- **A second, lighter in-process check.** The obvious "fast path" — classify locally, skip the
  chain for cheap calls — is ADR-0002 rebuilt: two places that decide, one of them unaudited.
  `governed` gets no decision logic of its own; it binds arguments and calls the chokepoint.
- **Making `governed` accept `async def` by scheduling the coroutine.** Any variant that returns
  before the body has run chains `applied` for work that has not happened. Refusing at decoration
  was preferred over a record that is wrong.
- **Blocking the whole session on a park.** A gated call raises `parked` and the session survives;
  the alternative stalls the caller's loop for up to an hour on an approval that may never come.
- **Treating the in-process path as a second conformance surface in `spec/`.** The specification
  governs envelopes, the chain and the eleven steps — all of which this path produces unchanged. A
  spec chapter about a Python decorator would document a language binding as if it were a protocol.
  The deviation is recorded here instead, which is what an ADR is for; if a second host language ever
  grows the same entry point, that decision must be revisited.

## 6. Residuals

- **No attestation, on either path.** Nothing proves a program went through the gateway at all. A
  clean audit trail and a bypassed one are indistinguishable today (ADR-0026), and in-process does
  not make this worse — the MCP client's own config is one edit away from the same result.
- **Thread-safety is now exercised, and is still not *discriminated*.** ~~Nothing in the suite
  exercises one `Governor` from several threads.~~ Something does:
  `gateway/tests/test_governed_functions.py::test_one_governor_driven_from_several_threads_builds_one_unbroken_chain`
  drives one `Governor` from eight threads released together on a barrier, ninety-six `benign` calls
  contending for ninety-six chain positions, and asserts every effect was recorded and every stream
  is contiguous from 0 with each `prev-hash` naming its predecessor.

  **What that is worth, stated precisely, because the obvious summary would overstate it.** The
  observable property holds under real contention — that is more than existed before, and it is what
  "treat concurrent use as unverified" was asking for. But four mutations were tried, each removing
  one guard independently: the emitter's window lock, the emitter's chain lock, the store's thread
  lock, and the `BEGIN IMMEDIATE` that makes the read-and-insert atomic. **The test passed under
  every one of them.** Under CPython's GIL this workload does not interleave at the critical
  section, so the test is a smoke test for concurrent use, not evidence that any particular guard is
  load-bearing.

  Recording that rather than writing "thread-safety is bound" is the whole of ADR-0013 §2: a test
  that cannot fail when the guard is removed protects nothing, and a residual closed on one is worse
  than one left open, because the next reader stops looking.

  **What would discriminate it:** a seam that forces a yield between the head read and the insert,
  or a free-threaded build. Neither exists here today. An earlier draft of this test used a `read`
  action and was weaker still — `read` folds into aggregates (§02 §7), so ninety-six calls produced
  two envelopes and the chaining it claimed to exercise barely ran; the `benign` workload is that
  correction.
- **The scope string is the integrator's.** `server="billing"` is asserted, not authenticated. Policy
  is written against action names, so an adopter who names two different things `billing` gives them
  one policy. The proxied path derives the scope from configuration; this one does not.
- **`close()` is the flush.** Documented in the docstring, in `deploy/README.md` and in §3 above, and
  still forgettable by anyone who calls `open()` directly.

## 7. What now fails if this stops being true

| Claim | Test |
|---|---|
| The approving signature travels in the envelope and binds this call's arguments | `gateway/tests/test_governed_functions.py::test_the_approving_signature_travels_in_the_envelope_the_kernel_verifies` |
| A second call cannot ride on the first call's approval | `gateway/tests/test_governed_functions.py::test_a_second_call_cannot_ride_on_the_first_calls_approval` |
| A genuine signature transplanted onto another request authorizes nothing | `gateway/tests/test_governed_functions.py::test_a_decision_signed_for_another_request_authorizes_nothing` |
| An open session is an identity, not a standing permission | `gateway/tests/test_governed_functions.py::test_an_open_session_is_an_identity_and_not_a_standing_permission` |
| Reads fold into one aggregate, and only the flush chains it | `gateway/tests/test_governed_functions.py::test_reads_fold_into_one_aggregate_that_only_the_flush_puts_in_the_chain` |
| A gated function refuses and its body does not run | `gateway/tests/test_governed_functions.py::test_a_gated_function_refuses_and_never_runs_its_body` |
| The gate records what the function actually receives | `gateway/tests/test_governed_functions.py::test_what_the_gate_records_is_what_the_function_receives` |
| Two spellings of one call commit to one `args-hash` | `gateway/tests/test_governed_functions.py::test_the_same_call_written_two_ways_is_one_action` |
| `async def` is refused at decoration rather than recorded as applied | `gateway/tests/test_governed_functions.py::test_an_async_function_is_refused_rather_than_recorded_as_applied` |
| A Governor that was never opened refuses rather than running ungoverned | `gateway/tests/test_governed_functions.py::test_a_governor_that_was_never_opened_refuses_rather_than_running_ungoverned` |
| A named configuration file that does not exist is refused | `gateway/tests/test_governed_functions.py::test_a_configuration_path_that_does_not_exist_is_refused` |
| The tool state stays in the caller's process | `gateway/tests/test_governed_functions.py::test_an_ordinary_function_is_governed_without_leaving_the_process` |
| A gated call still parks on a clock-advanced deployment | `gateway/tests/test_governed_functions.py::test_a_gated_call_still_parks_on_a_clock_advanced_deployment` |
| Importing the package still runs nothing | `gateway/tests/test_governed_functions.py::test_importing_the_package_does_not_import_the_runtime` |
| The kernel refuses a gated envelope with no authorization, through its only write route | `kernel/stozher-kernel/tests/no_ambient_approval.rs::a_gated_envelope_without_authorization_is_refused_through_the_only_write_route` |
| No header, query parameter or body member marks a call approved | `kernel/stozher-kernel/tests/no_ambient_approval.rs::no_header_query_parameter_or_body_member_marks_a_call_approved` |
| A re-execution path cannot proceed on a remembered approval | `kernel/stozher-kernel/tests/no_ambient_approval.rs::a_re_execution_path_cannot_proceed_on_a_remembered_approval` |

The last three rows are the kernel's half of the same property. They were written about the proxied
path and hold for this one for a reason worth stating: the Governor path reaches the kernel through
the same ingest route with the same envelope bodies, so there is no door here that those tests do not
already try.

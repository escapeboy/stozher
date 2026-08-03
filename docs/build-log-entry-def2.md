# 2026-08-03 — DEF-2: naming the state the specification did not have

Off `47fc577` (`main` = `develop`). One change: vectors, then normative text, then implementation.

## What was true

A component whose envelopes the kernel was **refusing** was, to `spec/`, a component that was merely
**behind**. The specification modelled an emitter in two states — chained locally, and synced — and
treated the distance between them as latency (§04 §3). A permanent refusal is a third state, and the
normative text named it exactly once, descriptively, in a rationale bullet about revocation (§03 §7)
that conceded the whole defect in five words: *"and no explanation"*.

Every MUST that fired in that state landed on the **kernel**, and the kernel discharged all of them
— §04 §7 recorded every rejection with its reason code, §09 §4.2 tracked the last accepted `seq`.
Nothing was required of the component: not to stop serving, not to tell its caller, not even to keep
the reason code it had been given. A gateway served a week of tool calls into a kernel that accepted
none of them, and that was conformant. **Observed detection latency: seven days**, bounded below by
`checkpoint-interval` and above by nothing, because the only signal was a console row nobody has to
open.

## What is true now

**`spec/05 §7.1`, "Refused is not offline"** — three submission outcomes rather than two. A component
MUST NOT treat `refused` as `unreachable`: the `offline` map governs a kernel that cannot answer,
never one that has answered. It MUST record the reason durably and MUST NOT erase it on any later
transition of the row. It MUST NOT submit past the wedge, renumber it, or rewrite it.

The grace rule is a product-owner decision and a synthesis of two proposals, and it is the part worth
reading twice. **The reason decides whether grace exists at all**: under a `mandate-*` reason or
`policy-not-published` every class is refused immediately, `read` and `benign` included, because
authority the organization cannot resolve is not authority (ADR-0001) and a read without authority is
still an effect. **The class decides who may use it when it does**: `read`/`benign` may run out
`policy.wedge-grace` (default `PT5M`), each served effect a counted finding; `consequential` and
`prohibited` stop at once, because grace over `consequential` is exactly the window an auditor asks
*"what else was still permitted"* about. Expiry blocks everything, measured from the **first** refusal
so a wedge cannot be re-graced by re-offering bytes.

The shape is a bridge between two failures that are both real. Unilateral stop-on-any-refusal is a
denial-of-service weapon: one malformed envelope halts a fleet, and an adversary who can provoke a
rejection can provoke an outage. Unbounded grace is an accountability hole. The specification says
both of those sentences, because the next person to read §7.1 will want to make it stricter and
should be told why it is not.

**`spec/09 §4.2`** gains a third bullet: a refused stream is surfaced immediately and distinguishably
from a quiet one, with its reason code. *Quiet is the absence of evidence; refused is evidence.*

**`spec/04 §7.2`, "Resuming a wedged stream"** — the exit ADR-0007 §6 asked §04 for and §04 never
had. A root-approved `kernel.resume_stream` envelope on `kernel:core`, binding one
`(stream, resume-seq)` and the `object-hash` of the refused bytes; the kernel then accepts exactly one
envelope at `resume-seq + 1` whose `prev-hash` is that hash. The emitter renumbers nothing. **A resume
validates nothing**: the refused envelope stays refused, its rejection record stays, and the position
stays empty — if one act could say both *"this stream may continue"* and *"that envelope was fine
after all"*, every refusal would be appealable by whoever can obtain one signature.

**`spec/10 §1.4`** finally names its resolver: *"resolvable" means resolvable by the kernel*. The
gateway publishes the session mandate and observes acceptance before serving anything under it.

## Numbers, measured on this branch

| | before (`47fc577`) | after |
|---|---|---|
| `./gateway/.venv/bin/python3 -m pytest gateway/tests -q` | 181 passed, 7 deselected | **186 passed, 5 deselected** |
| `cargo test --manifest-path kernel/Cargo.toml` | 349 passed, 2 ignored | **355 passed, 1 ignored** |
| `spec/vectors/` | 20 files, 313 vectors | **23 files, 345 vectors** |

The gateway delta is +2 (DEF-2's reproductions left the quarantine) and +3 (one parametrized case per
new vector file). The kernel delta is +3 (`def2_mandate_swap.rs` un-ignored and grown to four), +2
(`stream-status` and `stream-recovery` runners), +1 (the policy negative below); the remaining
`ignored` is DEF-1's. `cargo clippy --all-targets -- -D warnings` clean; `#[allow]` count unchanged at
1 (pre-existing, `tests/concurrency.rs`); `mypy --strict` clean; `type: ignore` unchanged at 2.

## Mutation tests — the counterfactual that mattered

Five, each reverted after being watched fail. The one worth recording is the second, because it is the
answer to *"did you just make it refuse everything?"*:

`sync.decide` mutated to refuse every outcome that is not an acceptance →
`test_vector_file[sync-outcome.json]` fails at
`unreachable-read-under-offline-allow-serves/action: expected 'serve', got 'refuse'`. That vector is in
the corpus for exactly this reason. Refusing everything is not a stricter fix; it is the
denial-of-service weapon §7.1 spends a paragraph refusing to build.

The fourth mutation changed the work. Removing `kernel.resume_stream` from
`ingest::ROOT_APPROVED_ACTIONS` did **not** fail anything: the baseline profile gates `consequential`
anyway, so the negative test passed for a reason that had nothing to do with the root rule. A test
that passes for the wrong reason is worse than a missing one, so `def2_no_policy_can_make_a_resume_free`
was added — an organization publishes a policy classifying the resume `benign`, which the baseline
allows outright. Unmutated it is refused `gate-authorization-missing`; mutated, the envelope is
**accepted**. That is §05 §5.6 with something behind it.

## Honest notes

- **Two assertions in `test_def2_mandate_swap.py` moved**, and both moved because the state they
  described stopped being reachable. The test asserted that a later envelope of the session reaches the
  kernel and is refused `mandate-unresolved`; §05 §7.1 clause 3 forbids submitting past a wedge, so it
  does not. The test now asks for what the fix is for — the kernel's reason code reaching the caller,
  the head unmoved, and the rest of the chain still held locally rather than marked delivered. Said
  plainly because "I changed the failing test" is the sentence that most needs to be volunteered.
- **`wedge-grace` is the first OPTIONAL member of `spec/05 §1`'s closed set.** Making it REQUIRED would
  invalidate every signed document and every vector at once, for a member that bounds a degraded state
  rather than granting authority. §09 §7's parenthetical claim that *every* member is REQUIRED was
  narrowed to the members that grant or bound authority — a small edit to a sentence whose argument is
  unaffected, and one a reviewer should look at anyway.
- **The stream-status tie-break was found by a test, not by design.** Under the kernel's `FixedClock`
  the last acceptance and the refusal carry the same instant, and `refused > accepted` read the row as
  healthy. The predicate is now `>=` — the tie breaks toward the finding — and there is a vector for it
  (`refused-in-the-same-millisecond-as-the-last-acceptance-is-refused`). A three-decimal timestamp and a
  coarse deployment clock make this reachable in production, not only in a fixture.
- **The append-only trigger had to be re-created, not extended.** SQLite cannot amend a trigger, so
  migration 7 drops and rewrites `envelopes_insert_must_extend_the_chain` with exactly one alternative
  predicate, and puts the same envelope-must-exist guard on `stream_resumes` that step 5 put on
  `manifests` and `gate_decisions`. This is the only widening of what the storage layer will accept
  since step 4 closed it, and it deserves the review §09 asks for.
- **No CLI mints a resume yet.** The kernel accepts one; an operator assembles it the way they assemble
  any other gated effect. That is a real gap in the product and it is recorded in
  `docs/spec-debt.md` row 3 rather than implied to be finished.
- **An ADR is owed.** The normative text came from `docs/proposals/DEF-2-mandate-continuity.md` plus a
  product-owner decision on the grace rule. Neither is a decision record, and the grace rule is exactly
  the kind of decision a later reader will want the reasoning for.
- **One reported failure was self-inflicted and is worth recording rather than quietly re-running.**
  `test_gateway_e2e.py::test_the_gate` failed once, because a `git stash` was run in the same worktree
  to measure the baseline vector count *while the suite was executing* — the source was briefly not
  there. A clean re-run is green. The lesson is the same one the venv note carries: a suite that reads
  a moving tree is not evidence about anything.
- **A process note that cost real time:** this worktree had no `gateway/.venv`, and the shared one
  carries an editable install pointing at the *main* checkout's `gateway/src`. Runs were shadowed with
  `PYTHONPATH` and later re-verified against a worktree-local venv with the `.pth` re-pointed; the
  numbers above are from the second. A suite that imports another branch's source is green about
  nothing.

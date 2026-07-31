# ADR-0013: v0.2 outcomes — what the parity gate proved, and what it did not

**Status:** Accepted · **Date:** 2026-07-31 · **Arises from** the v0.2 enforcement release
(`3d63f2a`) · **Corrects** ADR-0006 §1 · **Feeds** the v0.9 spec catch-up

v0.2 closed 21 confirmed defects across the kernel, the gateway and the deployment. The defect list
is in the release commit; this ADR records the three things that outlived it.

---

## 1. The gate is the vectors, not the fixes

The release gate is a new `parity` vector kind — 16 vectors encoding five confirmed
kernel↔gateway divergences, consumed by **both** test suites, with both harnesses panicking on an
unknown kind rather than skipping it.

**This was deliberate and it is the durable part.** Every divergence existed because the same
normative algorithm was implemented twice and the corpus did not reach the disagreement. The S0
gate was green *because* the vectors did not go there, not because the implementations agreed.
Fixing the five would have left the sixth free to appear.

Root cause worth naming: the v0.1 security work was split **by directory**, so cross-implementation
consistency was in nobody's slice. Both agents shipped green. **When two components implement one
algorithm, "these must agree" needs an owner, or a vector.** A vector is better, because it does not
depend on anyone remembering.

Corpus: 161 → 177 vectors, 351 → 397 assertions. The original 161 are byte-identical.

## 2. A guard no test binds is a guard a future edit deletes

K1 (aggregate count integrity) shipped in three parts: an `i128` fold, a 1024-entry cardinality
bound, and `[profile.release] overflow-checks = true`.

Mutation testing each part in isolation found that **two of the three do not bind**:

| mutation | result |
|---|---|
| `i128` fold → `i64` | nothing failed, debug **and** release |
| remove `[profile.release] overflow-checks` | nothing failed |
| remove the cardinality bound | test fails |
| remove the negative-count check | test fails |
| narrow the accumulator to a lossy `i32` | test fails |

**This is a consequence of the fix, not a hole in it.** With cardinality capped at 1024 and negative
counts refused, the maximum sum is 1024 × MAX_SAFE_INTEGER < `i64::MAX`, so `i64` cannot overflow at
that site any more. Sum *exactness* is still bound (the `i32` mutation is caught); the specific
choice of `i128` is not, and cannot be without contorting the design.

`overflow-checks` keeps its value at the **class** level — every other arithmetic site, including
ones not yet written. That is why it stays. But an unbound guard is exactly how this defect class
stayed invisible to 153 tests in the first place, so the manifest line is now pinned by a test that
reads `kernel/Cargo.toml` and asserts the setting (`the_release_profile_still_traps_arithmetic_overflow`),
verified to fail both when the line is commented out and when the section is deleted.

**The general rule: if a safety property is not attached to a failing test, it is a comment.**

## 3. ADR-0006 §1 asserted a conformance that did not exist

Corrected in place. ADR-0006 §1 recorded the signature-before-schema decision **and** stated
"Implementation follows the spec." The ingest path did; `stozher-core::chain::verify_chain` — the
function an external auditor calls — did not, for the whole of v0.1.

It was found by writing a vector, not by re-reading the ADR. **An ADR may record what was decided on
its own authority; a claim about what the code does belongs in a test, with the ADR pointing at it.**

---

## Carried to v0.9 (spec catch-up)

1. `spec/02 §4` permits "any other IANA media type"; K3 narrowed what the kernel will *serve* to a
   12-entry allowlist, because it is reflected as `Content-Type` from an origin the console shares.
   §02 §4 should be amended to match.
2. `spec/02 §7` needs a `by-action` cardinality bound and a non-negativity rule.
   `x-aggregate-cardinality` and `x-aggregate-count-negative` are candidates for §02 §9.1.
3. `spec/04 §4` names no code for a supplied range that begins elsewhere —
   `x-checkpoint-range-mismatch`.
4. `spec/06 §5` should state whether an approver whose subject the deployment cannot name is
   permitted. Currently vector-defined (`approver-whose-subject-the-deployment-cannot-name`) rather
   than normative — encoded from the kernel's shipped reading, because the alternative breaks any
   deployment that does not model subjects.
5. `gate-approver-unresolvable` (minted in the gateway) needs a §06 entry; over-deep JSON nesting
   needs §01 text.
6. Two residual kernel↔gateway divergences, same family, not yet vectored: a missing
   `decision.request-hash` and a missing `decision.decision` produce different codes on each side.
7. The local `x-` register grew 11 → 15.

## Deferred with a reason (ADR-shaped, not release-shaped)

**K2 residual.** Mandate walks are capped at 1024 and the ancestry query and revocation fetch are
hoisted out of the per-request loop, but each request still re-verifies every mandate signature —
so ~1024× signature amplification remains on a maximally-sized aggregate. Closing it needs a
"verify once, match many" entry point in `stozher-core::mandate`, and `walk`'s check ordering is
**spec-observable** (the vectors assert which code fires first). That is a design change with a
conformance consequence, not a release-week edit.

## Process notes, recorded because they cost real time

- **Mutation-test in an isolated worktree**, never a shared checkout. Two agents mutated the same
  file concurrently and *both* produced contaminated results — each seeing a failure the other had
  caused. `git worktree add <tmp> HEAD --detach` costs seconds and makes the result trustworthy.
  Both parties independently reached this conclusion after wasting a round.
- **File ownership is not sufficient; task ownership must agree with it.** An agent claimed tasks by
  setting `owner` to another live agent's name, believing it was its own identifier. Work sat
  `in_progress` under an agent that never touched it — the failure mode is not a collision but
  **silent non-performance**, which reports nothing.

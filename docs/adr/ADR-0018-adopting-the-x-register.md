# ADR-0018: the `x-` register is adopted, and the records chained under the old names keep them

**Status:** Accepted · **Date:** 2026-07-31 · **Arises from** `docs/product-completion-design.md`
§3 (v0.9) · **Follows** ADR-0017 · **Amends** ADR-0006 §9 (which created the register)

Since v0.1 this implementation has quarantined, under an `x-` prefix, the reason codes for conditions
the specification states as a MUST while naming no code for the refusal. The alternative would have
been to skip the check — trading a documented gap for an undocumented hole — so the checks were
implemented and their names were marked as not part of the wire contract. Every one of them carried a
comment naming the clause it enforces and saying it was a candidate for the next revision.

v0.9 is that revision. Sixteen are adopted.

---

## 1. What was adopted, and where each one landed

| Code (was `x-…`) | Clause it enforces |
|---|---|
| `policy-offline-allows-gated` | §05 §7 — the default profile MUST NOT allow `consequential` while a gate rule applies |
| `policy-change-target-mismatch` | §05 §5.1 — `execution.target` identifies the new version |
| `policy-change-document-unbound` | §05 §5.3 — `args-hash` binds the exact policy bytes |
| `aggregate-window-too-long` | §02 §7.5 — a window closes within `aggregate-max-window` |
| `aggregate-window-inverted` | §02 §7.2 — a window that runs backwards |
| `aggregate-count-negative` | §02 §7.3 — the sum was satisfiable by cancellation |
| `aggregate-cardinality` | §02 §7 — the samples were bounded and the actions were not |
| `payload-media-type-not-allowed` | §02 §4 — a type the kernel will not serve back |
| `checkpoint-stream-unknown` | §04 §4 — a checkpoint naming a stream the store has never seen |
| `checkpoint-range-mismatch` | §04 §4 — verified against a range it does not begin at |
| `manifest-malformed` | §08 §1 — a document that is not a well-formed manifest at all |
| `root-enrollment-malformed` | §03 §6 — an enrolment whose evidence identifies no key |
| `gate-decision-already-recorded` | §06 §5 — one request, one answer |
| `gate-rate-limited` | §09 §7 — the kernel rate-limits gate requests per subject |
| `notify-failed` | §06 §4.3 — a notification that could not be delivered |
| `budget-exceeded-applied` | §05 §3 step 2 — an effect reported as applied past an exhausted cap |

Each is now stated next to the rule rather than in a table of its own, which is how the specification
already names every other code. §02's structural table gained the five that belong to envelope
validation.

## 2. What the register means now

Not "codes the specification forgot" — those are gone. `codes::REGISTER` is now the set of codes that
**refuse nothing**: a store that could not answer, a caller that presented no credential, a schema
newer than this build, a component that would not speak the conformance protocol. None of them says
"what you sent is invalid"; each reports a condition of the *kernel*. They keep the `x-` prefix
because that is exactly what it is for, and putting them in a wire contract about objects would be a
category error rather than a courtesy.

That also repairs something: the register's own comment claimed to be complete while five codes added
during v0.3 and v0.4 sat outside it. They are in it now, and the boundary is a rule rather than a
habit.

`budget-exceeded-applied` moved across that boundary while this work was in progress, and the move is
the rule working. It is a `policy_violation` marker on an accepted envelope rather than a refusal, so
it started in the local set — and then ADR-0019's catch-up named it in §05 §3 step 2 alongside
`prohibited-applied`, which is normative and never carried a prefix. A code the specification names
is adopted, whatever shape of condition it reports.
→ `no_adopted_code_still_claims_to_be_local` is the half a rename forgets: a code the specification
names, still carrying `x-`, tells a reader of a rejection record the opposite of the truth.
`the_two_sets_are_disjoint_and_have_no_duplicates` stops a code being claimed by both.

## 3. Renaming does not rewrite a chained past

This is the part that needed a rule rather than a search-and-replace. The store is append-only and
its rejection records are chained: a refusal recorded in June under `x-manifest-malformed` still says
that, and it always will. There is no migration available and none should be wanted — an audit log
that could be brought into line with today's vocabulary is an audit log that can be brought into line
with anything.

So `spec/00 §1` now says three things:

- an implementation MUST emit only the adopted name;
- an implementation **reading** historical records MUST treat `x-<name>` and `<name>` as the same
  condition, for any adopted `<name>`;
- an implementation MUST NOT rewrite, re-sign or re-emit a historical record to carry the new name.

The list of what was adopted lives here rather than in `spec/`, because it is a fact about one
transition and not a rule that keeps applying. A future revision that adopts more codes writes its
own ADR; §00 §1's three sentences do not change.

## 4. What this does not do

It does not add a check, remove one, or change what any of them reports. Every condition was already
being detected and reported; what changed is whether the name is part of the contract an independent
implementation has to match. That was the point: v0.9's gate is an implementation written from
`spec/` alone passing the corpus, and sixteen conditions whose names it could not have known were
sixteen ways to fail that gate for no reason.

## Related

`spec/00 §1` · `spec/02 §9.1` · ADR-0006 §9 (which created the register) · ADR-0009 §(e) and ADR-0013
§4 (which asked for exactly this) · ADR-0010 (which grew the register to 11 and said so) ·
ADR-0017 (the other v0.9 spec work)

# ADR-0017: three clauses nobody had a vector for, and what the two implementations did with them

**Status:** Accepted · **Date:** 2026-07-31 · **Arises from** `docs/product-completion-design.md`
§3 (v0.9) · **Follows** ADR-0016 · **Adds** `spec/02 §2.1`, `spec/05 §3.1`, a normative constraint to
`spec/10 §3`

v0.9's gate is "an independent implementation, written from `spec/` alone by someone who has not read
our code, passes the vector corpus". The first work toward it was the design note's smallest item —
one table in `spec/02 §1` — and pulling on it produced three under-specified clauses and eleven
concrete disagreements between the Rust kernel and the Python gateway. All of it passed the
208-vector corpus, from both sides. Per ADR-0013's rule, every claim below names the test that fails if it stops being true.

---

## 1. One shape of defect, three instances

Each of the three began as a sentence that reads like a rule and decides nothing:

| Clause | What it said | What it left open |
|---|---|---|
| §02 §1 | "Members not listed above MUST be rejected" | a flat list of every member across all nine kinds — so, read literally, `cost` on a mandate and `trigger` on a checkpoint |
| §05 §3 step 1 | "`reclassify` entries matching (subject, action, resource) win, most specific first" | what a pattern is, what "most specific" measures, how ties break |
| §10 §3 | the tier order | that a tier the kernel cannot see must not come out weaker than the kernel's own answer |

An implementer meeting any of them has to invent an answer, and two implementers invent two. That is
not a hypothetical: they did, and neither test suite could see it, because a question the
specification does not pose is a question the corpus does not ask.

## 2. §02 §2.1 — where each member may appear

Eleven placements differed. The kernel permitted `policy-version` on a `cognition` envelope and the
gateway refused it; the gateway permitted `trigger` and `memory-ref` on every kind and the kernel on
almost none; the gateway permitted `commitment-ref` on a `policy-change` and the kernel did not.

The resolution rule, stated because it will be needed again:

- **Where the disagreement is about a member with no semantics, adopt the permissive reading.**
  `memory-ref` and `correlation-ref` are stored and never interpreted and carry no authority; there
  is no kind they can be *wrong* on. Permitting them everywhere is also the only resolution that
  cannot invalidate an envelope somebody has already chained, which matters more than tidiness in a
  store that cannot be rewritten.
- **Where the member's meaning does not exist on the kind, adopt the narrow one.** §07 §4 makes
  `trigger` a link from an effect to the signal that caused it; a checkpoint has no effect to link,
  so the member would be decoration — and a decorative member on a signed, chained record is a place
  to hide something. Same for `commitment-ref` on a policy change, and for `policy-version` on a
  `cognition` envelope, which carries no `classification` and no `execution` and would be claiming a
  governance that did not apply to it.

§02 §1 also gained the eight members it never listed — `mandate`, `revokes`, `revoked-at`, `reason`,
`decision-of`, `decision`, `signal`, `checkpoint` — which is the design note's original item: a
literal implementer was rejecting the required members of five of the nine kinds.
→ `every_kind_accepts_exactly_the_optional_members_the_matrix_grants_it` probes every kind against
every member the matrix decides; 42 new `envelope-shape` vectors ask a third implementation the same
questions, and four of the nine kinds had no vector of any sort before them.

## 3. §05 §3.1 — how a `reclassify` entry matches

This one is the dangerous one, and it was broken in three places at once:

- **The gateway supported no patterns.** It compared `subject`, `action` and `resource` for string
  equality, so a policy reclassifying `github.*` was *silently ignored by the emitter and honoured by
  the kernel*. That combination is the worst available: the gateway applies an effect believing it is
  `read`, and the kernel refuses the record of it (`policy-component-override-attempt`). The action
  happens in the world and the audit does not have it.
- **The kernel weighted the three dimensions unequally** — resource 8, action 4, subject 2 — so an
  entry naming one exact resource beat an entry naming an exact subject *and* an exact action. There
  is no deployment-independent sense in which naming a resource is narrower than naming an action, so
  the weights are now equal and specificity counts **how many dimensions you named**, which is what
  the person writing the policy means. Ties go to the earliest entry.
- **The kernel's "an absent dimension is a wildcard" branch was unreachable**, because its own
  validator requires `subject` and `action` on every entry. §05 §3.1 now states that: those two MUST
  be present and `*` is how you say "any", while `resource` MAY be omitted. The asymmetry is
  deliberate — a reclassification silent about *who* or *what* is more often a mistake than an
  intention — and §1's worked entry omits `resource`, so requiring it would have invalidated the
  specification's own example.

Nothing exercised any of it. The shipped baseline profile ships `"reclassify": []`, every test
fixture ships `[]`, and no vector had ever contained an entry. A normative clause with zero coverage
in two implementations and one corpus is not a rule; it is a comment.

There is also a trap worth naming rather than fixing: §03 §4.1's segment separator is `.`, so
`agent:*` is not a prefix pattern and matches nothing but a subject literally named that. Extending
the pattern dialect to `:` is a design change no design partner has asked for; saying so in the
specification is not.
→ `every_policy_evaluation_vector_matches_this_implementation` and the 14 `policy-evaluation`
vectors, a new corpus kind. §05, §07 and §08 had no vectors at all before this.

## 4. §10 §3 — the emitter's extra conservatism was real, and was being over-applied

The gateway takes the **stronger** of its own catalog's class and `default-unknown` when org policy
has said nothing. That is correct and load-bearing: the kernel evaluates §05 §3 step 1 with the
registered manifest as the only proposal available to it, so a catalog that quietly downgraded an
action would produce exactly the unrecordable effect described above. Taking the stronger class makes
the two evaluations agree by construction.

Two things were wrong with it. It existed only as a comment in `policy.py`, so an independent
implementer had no way to know; it is now a normative constraint in §10 §3. And it was applied to
**Tier A as well** — a registered manifest's declared class was being strengthened along with a
catalog guess, which is not caution but a disagreement with §05 §3, since the kernel can see that
manifest and evaluates it as declared. `Policy.classify` now takes the two as separate parameters,
and the caller decides which slot a proposal belongs in from the tier that produced it.
→ `manifest-proposal-beats-default-unknown` in the corpus, run by both implementations.

## 5. What this cost, and the habit that would have caught it

Three normative clauses, eleven concrete divergences, one of them capable of putting an effect in the
world with nothing in the audit — and a green build on both sides throughout: 208 vectors, 269
kernel tests, 115 gateway tests, all passing.

The habit is small: **a clause that no vector exercises is a clause two implementations will
disagree about.** Not may — will, eventually, because each one is a place where an implementer had to
choose and nothing checked the choice. The corpus is not a regression suite for behaviour we already
have; it is the only mechanism by which the specification is the source of truth rather than
whichever implementation someone read last.

This is the third release in a row whose most valuable finding came from reading a clause rather than
from a failing test (ADR-0015 §1, ADR-0016 §1, and now three at once). All three were visible to
anyone who compared the text with the code. None were visible to the tests.

## 6. What v0.9 still has open

- **The external crypto and security review.** Not substitutable by internal work, and the largest
  item in the release.
- **The rest of the spec catch-up.** ADRs 0006–0017 hold further normative text not in `spec/`.
- **The remaining vector kinds** — `trigger`, `checkpoint`, `manifest`. §07, §04 §4 and §08 still have
  no vectors of their own; `policy-evaluation` closed §05. The corpus is 264 vectors across 15 files.
- **The `x-` register.** Implementation-local codes are still quarantined, and adopting any of them
  needs a stated rule for rejection records already chained under the old name.

## Related

`spec/02 §1`, `§2.1` (new) · `spec/05 §3.1` (new) · `spec/10 §3` · `docs/product-completion-design.md`
§3 (v0.9) · ADR-0013 (an ADR points at a test) · ADR-0016 (the previous "already-settled" clause)

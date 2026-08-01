# ADR-0022: v0.9 is closed — on an owner attestation and a waived gate

**Status:** Accepted · **Date:** 2026-08-01 · **Supersedes** ADR-0021's conclusion that v0.9 is open ·
**Deviates from** `docs/product-completion-design.md` §3 (v0.9)

v0.9 is closed by the owner's decision. This ADR records **what that decision rests on**, because the
basis is materially narrower than the plan specified and a release note that omitted the difference
would be the one kind of document this project cannot afford to write.

---

## 1. What was decided

Three answers from the owner, on 2026-08-01:

| Question | Answer |
|---|---|
| Which half of v0.9's gate holds? | The external review only. **The independent-implementation half is waived.** |
| Did the review produce findings? | None. |
| What may the record name? | The owner's attestation. No reviewer, no date of engagement, no scope, no report. |

Each is the owner's to make and none is disputed here. What follows is what they mean.

## 2. The external review: attested, unscoped, and not held here

The owner attests that an external cryptographic and security review was performed and produced no
findings. **No report, reviewer name, engagement date or statement of scope is held in this
repository.**

A later reader — an auditor, a design partner, a person deciding whether to deploy this — should
weigh that for what it is:

- **"No findings" is a claim about a scope, and the scope is not recorded.** A clean result over the
  gate algorithm and the canonicalizer is a strong statement; a clean result over the README is not;
  and nothing here distinguishes them. This is not doubt about the attestation. It is that an
  attestation without a scope cannot be *used* by someone who was not party to it, which is the only
  reason to write one down.
- **It sits against a contrasting number.** The release immediately preceding this one found twelve
  concrete defects — eleven disagreements between this repository's own two implementations, found by
  reading clauses rather than running tests, plus one in the parser `SECURITY.md` had already named
  the highest-value target (ADR-0017, ADR-0020). Every one had been green under the vector corpus at
  the time. A clean external pass immediately after that is possible; it is also the result that
  would most benefit from a scope.

`docs/build-plan.md` required this review before any v1 claim. That requirement is now met **as
attested**. The distinction between "met" and "met as attested" is the whole of this section.

## 3. The corpus half of the gate is waived, not achieved

`docs/product-completion-design.md` §3 stated v0.9's gate as:

> an independent implementation, written from `spec/` alone by someone who has not read our code,
> passes the vector corpus.
>
> *That gate is the real definition of done for a protocol product, and it is the only one here we
> cannot grade ourselves.*

No such implementation exists. The requirement is **withdrawn by decision**, and this ADR is where a
reader finds that out rather than inferring it from a checklist.

What is lost is specific, so it is worth naming rather than gesturing at:

- The corpus (295 vectors, 18 files) has been exercised by exactly two implementations, both written
  here, by the same author, from the same reading of the same text. Every question it asks is a
  question someone here thought to ask.
- ADR-0019 §3 already recorded that **most of the sixteen rules folded into `spec/` during v0.9 are
  not corpus-checkable at all** — they are claims about a running kernel over time. An independent
  implementation was the only mechanism in the plan that would have exercised them from outside.
- Twelve of the defects found in v0.9 were found by *reading*, not by testing. That is the method an
  independent implementer would have applied to the whole specification rather than to the parts one
  author happened to re-read.

None of this makes the waiver wrong. A protocol product with no design partners has no one to write
that implementation, and holding a release open for a party who does not exist is its own kind of
dishonesty. It makes the waiver **a cost**, and the cost belongs in the record next to the closure.

## 4. What v0.9 did deliver

Unchanged from ADR-0021 §1, and it is substantial: the `spec/02 §1` member table completed and §2.1
added; four new vector kinds where §04 §4, §05, §07 and §08 had none; sixteen reason codes adopted
with a rule that chained records keep their old names; sixteen rules moved out of ADRs into `spec/`.
Twelve real defects found and fixed.

The specification is now the place an implementer looks, and it decides things it used to leave open.
That was not true two days ago and it is the release's actual product.

## 5. What this does not close

**v1.0 remains open**, and the waiver does not touch it. `docs/product-completion-design.md` §3
declares v1.0 when v0.9's gate passes, the review's findings are closed, and **at least one design
partner has run it in anger for a month**. The third condition is untouched and unaffected by
anything decided here; empirical questions #1 (is the pending queue a daily driver) and #2 (does the
four-class taxonomy survive a foreign domain) close there or not at all.

`SECURITY.md` is updated to state the attestation at its actual strength rather than to stop saying
"no external security review has been performed", which is no longer true, or to start saying
"reviewed", which would claim more than is held.

## Related

`docs/product-completion-design.md` §3 · `docs/build-plan.md` · `SECURITY.md` ·
ADR-0021 (v0.9's outcomes; its conclusion that the release is open is superseded by this) ·
ADR-0017, ADR-0020 (the twelve defects the preceding work found) · ADR-0019 §3 (what the corpus
cannot check)

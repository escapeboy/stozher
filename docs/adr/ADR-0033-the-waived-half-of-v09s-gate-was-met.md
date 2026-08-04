# ADR-0033: The waived half of v0.9's gate was met — by an agent, blind, 307/307

**Status:** Accepted · **Date:** 2026-08-04 · **Amends** ADR-0022 §3 ("the corpus half of the gate is
waived, not achieved") · **Follows** ADR-0024 (v1.0, declared on a waived field condition)

ADR-0022 closed v0.9 on an owner attestation with one half of the gate explicitly waived:

> Which half of v0.9's gate holds? — **The external review only. The independent-implementation half
> is waived.**

That half is no longer waived. It was run on 2026-08-04 and it passed. This ADR records what it
rests on, in the same spirit as the two before it: **the basis is narrower than the phrase "the gate
passed" suggests, and this is the one project that cannot afford the release note that smooths that
over.**

---

## 1. What was decided

| Question | Answer |
|---|---|
| Was an independent implementation written from `spec/` alone? | **Yes.** 12 Python modules and a conformance runner. |
| Did it pass the corpus? | **Yes. 307 of 307 `primitive` vectors**, all 18 files. The seven `kernel`-role files were declined **by name**, which `spec/vectors/README.md` requires instead of silent omission. |
| Does an agent count as "someone who has not read our code"? | **Yes — the owner's decision, 2026-08-04.** The gate's wording says "someone"; whether that admits a language model was not a question the plan anticipated, and it is a judgement rather than a fact. |
| Is v0.9's gate closed? | **Yes**, by the owner's decision on that basis. |

## 2. What the blindness actually was

Structural, not promised. The implementer was given a directory containing **only**:

- `spec/*.md` — 11 files, ~3,200 lines, the normative text;
- `spec/vectors/*.json` — the corpus and its README.

Absent from it: `kernel/`, `gateway/`, `console/`, `docs/`, every ADR, and the repository itself.

**`spec/vectors/generate_vectors.py` was withheld deliberately**, and that is the detail most likely
to be skipped by someone reproducing this. Its own README calls it *"an independent implementation of
spec §01–§06"* — but written by the same author as the other two. An implementer who read it would
learn what the author meant rather than what the text says, which is precisely the substitution this
gate exists to prevent.

Reading the vectors' **expected outputs** was permitted and intended. They are the test. The corpus
is designed to be consumed exactly this way (`README.md` §1: every vector carries its own expected
output, and a consuming suite MUST read expected values from these files).

## 3. The result was verified, not accepted

The runner was executed by the orchestrator rather than reported by the implementer, and then
mutation-tested — a conformance runner that passes everything is indistinguishable from one that
asserts nothing:

- **Unmutated:** 307/307.
- **Member ordering reversed** in the implementation's JCS canonicalizer (`sorted(..., reverse=True)`):
  **206/307**, 101 failures spread across many files, `object-hash` at 0/3.
- **Restored:** 307/307.

So the implementation computes rather than recognises, and the runner bites.

## 4. What this does not establish

Four things, and they are the reason this ADR exists rather than a line in a changelog.

**An agent's blindness is a property of a fresh context, not of an independent mind.** A human
outsider brings different priors, different habits, and different misreadings. A model reading a
specification written in this house's prose may fill a silence the same way its author would, for
reasons that have nothing to do with the text being sufficient. Where a gap is filled by shared
convention rather than by the words, this exercise cannot see it and a human might have.

**Passing is evidence about the corpus, not only about the text.** The corpus was written by the
same author as the specification. A rule that both the text and the corpus omit is invisible to
this gate by construction — which is exactly the class of gap an outside implementer is hired to
find.

**Amended 2026-08-04, the same day: the rerun produced the report, and it found four real gaps.**
The paragraph below stands as written about the *first* run. A second agent, fresh sandbox, same
blindness, was briefed with the priority inverted — `FINDINGS.md` written *during* the work, every
one of the eleven spec files required to appear even if only as "nothing to report", and the
implementation named as the instrument rather than the product. It returned 416 lines of findings
**and** 307/307, with an explicit "no" on the sandbox question.

Its four gaps are in `docs/spec-debt.md` §1a as rows B1–B4, **each verified against this repository
before being recorded**. B1 is the one that matters: `policy-stale-offline` is a required wire value
present in the corpus and in *both* reference implementations, and `grep` over all eleven spec files
returns **zero hits**. Eight days of inside work did not surface it. The full report is preserved at
`docs/validation/blind-sufficiency-audit-2026-08-04.md`.

The auditor's own account of the shape is the finding worth carrying: *"every area where the
specification records its own past failure is excellent. The gaps are all in places nobody has yet
been bitten — which is precisely what a blind reader is for."*

**What follows was true of the first run and is kept because the lesson in it is about the brief.**

**The report was never produced, and this did not change.** The implementation was the means; the
deliverable was an account of where `spec/` was ambiguous, silent, wrong, or learnable *only* from
the vectors. It was requested three times, twice in writing after the code was finished. No
`REPORT.md` was written and no file in the sandbox was touched afterwards. **The gaps this exercise
was run to surface are unsurfaced, and this is now the recorded outcome rather than a pending item.**

The artifact carries no substitute: 1,985 lines across 12 modules, and **not one comment marking a
place where the specification was insufficient** — no "spec does not say", no assumption noted, no
TODO. Searched for, absent.

**And the failure is at least half mine.** The brief asked for an implementation *and* a report, and
said the report was the deliverable. Only one of the two was measurable — the corpus grades the code
and nothing grades the prose — so the measurable one is what came back. A gate that scores the easy
half will be answered by the easy half, which is the same lesson this repository has been writing
down all week about tests and about ledgers, arriving here from a new direction. **A rerun should
demand the findings first and the passing implementation second.**

**The sandbox attestation was never given.** The implementer was asked, plainly, whether it read
anything outside its directory. It did not answer. The blindness above is what was *constructed* —
it is not what was *confirmed*, and on the present evidence it cannot be.

## 5. What may be said, and what may not

**May be said:** an implementation written from this specification and its corpus, with no access to
either reference implementation or to the corpus generator, passes all 307 primitive conformance
vectors, and that result was independently executed and mutation-checked.

**May not be said:** that `spec/` has been shown sufficient for a human implementer; that the gaps
in it are known — **they are not, and no report was produced to name them**; or that the exercise was
audited. The first is unfalsified rather than established,
the second awaits the report, and the third has not happened.

ADR-0022's other half — the external crypto and security review — remains as that record left it: an
owner attestation naming no reviewer, no date, no scope and no report. **Nothing here touches it.**

## 6. What now fails if this stops being true

The implementation and its runner live outside the repository, in a scratch directory, and are not
preserved by any test here. **This claim has no executable evidence inside this repository**, which
is stated rather than papered over: it is an event that happened and was witnessed, in the same
class as ADR-0022's attestation, and it is recorded with its numbers so a reader can judge it rather
than take it.

Preserving the blind implementation as a third conformance consumer in CI was **considered and not
done**: once it lives here it stops being blind, every later change to it is made by someone who has
read the code, and a third implementation maintained by this author is not what the gate asks for.

## Related

`docs/product-completion-design.md` §3 (v0.9's gate) · ADR-0022 (which waived this half) ·
ADR-0024 (v1.0, on a waived field condition) · `spec/vectors/README.md` §1

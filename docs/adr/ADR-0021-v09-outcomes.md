# ADR-0021: v0.9's engineering is complete; v0.9 is not

**Status:** Accepted · **Date:** 2026-08-01 · **Arises from** `docs/product-completion-design.md`
§3 (v0.9) · **Follows** ADR-0020 · **Does not declare** v0.9 met

v0.9 is "it can be disbelieved and still verified". Its gate is stated in the design note and it is
the only gate in the plan the project cannot grade itself:

> an independent implementation, written from `spec/` alone by someone who has not read our code,
> passes the vector corpus.

Four of the five items are engineering and are done. The fifth is the external cryptographic and
security review, and it is not work — it is a relationship with someone who does not have our
assumptions. **This ADR exists to record that distinction rather than let a full checklist read as a
met gate.**

---

## 1. The four that are done

| Item | Outcome |
|---|---|
| `spec/02 §1` member table | §02 §1 completed and §2.1 added. A literal implementer had been rejecting the required members of five of the nine kinds (ADR-0017 §2) |
| Vector coverage | `policy-evaluation`, `trigger`, `checkpoint`, `manifest` added; §04 §4, §05, §07 and §08 had none. 295 vectors across 18 files, each file carrying a `role` (ADR-0017, and the kinds commit) |
| `x-` register adoption | Sixteen codes adopted, with `spec/00 §1`'s rule that chained records keep the old names (ADR-0018) |
| Spec catch-up | Sixteen rules moved from ADRs into `spec/`; one deliberately deferred (ADR-0019) |

What the work actually produced is not the checklist. It is **eleven concrete disagreements between
this repository's own two implementations**, every one of them found by reading a clause rather than
by running a test, and every one of them green under a 208-vector corpus at the time (ADR-0017).
Then a twelfth, in the place `SECURITY.md` had already named the highest-value target, found by
attacking the rejection side of a parser whose acceptance side was exhaustively tested (ADR-0020).

The pattern is worth more than the fixes: **a clause the specification does not decide will be
decided differently by two implementations, and neither test suite can see it.** Three times the
reasoning for a wrong answer cited this project's own code as though it were the specification.

## 2. The one that is not done, and cannot be done here

The external review is mandatory per `docs/build-plan.md` and cannot be substituted by internal work.
ADR-0020 records an internal review — six surfaces attacked, one real cross-implementation defect
found and fixed, two smaller ones, and a list of what held. It is a better starting point for the
real review and it is not the real review. The property that makes the requirement worth having is
the reviewer's independence, and an internal pass has none of it.

The same shape applies to the gate itself. No independent implementation has been written from
`spec/` alone. The corpus is what one would be measured against, and this release was largely spent
making the corpus able to catch things — but a corpus is a floor, not a proof: ADR-0019 §3 states
plainly that most of the sixteen rules folded in this release are claims about a *running kernel over
time* and are not corpus-checkable at all.

**Therefore v0.9 is open.** Every item under it that can be built has been built; the release closes
when someone else has tried to break it and someone else has implemented it.

## 3. What an operator should take from this today

- The specification is now the place an implementer looks, and it decides the things it used to
  leave open. That was not true a week ago.
- The reviewer's map in `SECURITY.md` is accurate — it previously pointed at gaps that had been
  closed in v0.3 and v0.4, which is worse than no map.
- **Nothing here changes the deployment advice.** `SECURITY.md`'s first line still applies: do not
  deploy this to protect anything you cannot afford to have wrong. Twelve divergences found in one
  release by reading is a good sign about the method and a bad sign about the remaining count.

## 4. What is left in the plan

- **v0.9:** the external crypto and security review, and an independent implementation passing the
  corpus. Neither is executable from inside this repository.
- **v1.0:** no new engineering. It is declared when v0.9's gate passes, the review's findings are
  closed, and at least one design partner has run it in anger for a month. Empirical questions #1
  (is the pending queue a daily driver) and #2 (does the four-class taxonomy survive a foreign
  domain) close there or not at all.
- **Deferred on evidence, not forgotten:** export streaming, per the design note's own condition —
  "only if a design partner's log makes the in-memory body impractical". No design partner, no
  evidence, no change.

## Related

`docs/product-completion-design.md` §3 · `docs/build-plan.md` (the external review requirement) ·
`SECURITY.md` · ADR-0013, ADR-0014, ADR-0015 (the v0.2–v0.4 outcome records this follows) ·
ADR-0017, ADR-0018, ADR-0019, ADR-0020 (v0.9's four engineering items)

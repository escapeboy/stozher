# Four design partners, four foreign domains, one day — 2026-08-04

`docs/product-completion-design.md` §6 lists two things no amount of engineering closes, and both of
them turn on someone who is not us running this against work we did not choose:

> **Empirical question #1** — is the pending queue a daily driver?
> **Empirical question #2** — does the four-class taxonomy survive a foreign domain?

v1.0 was declared on 2026-08-02 with the design-partner condition **waived, not met** (ADR-0024).
This is the first evidence against either question. Four agents were each given a domain, the
repository, and the documented install path, and told to get work done and report where they got
stuck. None had read this code. None was told what the others found.

**They are not human design partners.** The same caveat ADR-0033 §4 states about the blind
implementer applies here and matters more: a fresh context is not an independent mind, an agent
does not get bored or angry, and nobody's job depended on the outcome. What this exercise produces
is *reproducible operational evidence*, not market signal. Question #4 — whether anyone wants it —
is untouched by all four reports together.

| Domain | Report | Would they run it? |
|---|---|---|
| Litigation firm, AI paralegal, court filings and privileged material | [`legal.md`](legal.md) | **No** — the documented path crashes on every tool the firm has |
| E-commerce revenue ops, ~200k orders/month, refunds and pricing | [`commerce.md`](commerce.md) | **No** — the amount is the one thing the system cannot see |
| Platform SRE, 300 services, unattended 03:00 automation | [`sre.md`](sre.md) | **No** — a routine mandate revocation permanently removes a component |
| Clinical research, 30 trials, consent withdrawal and audit | [`clinical.md`](clinical.md) | **No** — the first withdrawal wedges the component that was processing them |

**Four for four, and none of them for the reason we would have guessed.** Nobody said the
cryptography was weak, the audit trail was untrustworthy, or the gate could be bypassed from
outside. Two of them volunteered that the audit artifact was the best part of the product — one
wrote ~90 lines of their own Python against `spec/01` and verified an export end to end with no
Stozher code, then broke it deliberately by one byte and got two independent failures.

## What four independent runs agreed on

**The release gate was red at HEAD, and all four hit the same line.** `deploy/gate/clean-install.sh`
— the path `README.md` headlines — failed with `'NoneType' object is not subscriptable`. A first call
to an unclassified tool parks *two* requests; `bin/stozher-approve` answers one; the retry crashed
with no refusal document and no audit record. Fixed 2026-08-04; the reproduction is
`gateway/tests/test_seed_without_a_decision.py`. **Four independent reproductions of a defect eight
days of inside testing never saw, because we only ever ran it on tools we had already classified.**

**Approval does not survive contact with volume.** The commerce partner measured it rather than
asserting it: 233 calls in one simulated morning, 27 parked and **66 refused `gate-rate-limited`
with `retryable: false`** — lost work, not deferred. They wrote a batch script at the second queue
entry, ~35 minutes after first contact, and then approved ten refunds in seven seconds, one of which
was €50,000. The audit of that approval is perfect and the control was zero. The clinical partner
independently hit approval fatigue at 22 requests. **Answer to question #1: no, and the failure mode
is not that the queue is ignored — it is that it is answered correctly and meaninglessly.**

**One enum decides four unrelated things.** Every partner reached this from a different direction.
`classification` fixes the gate *and* retention *and* offline behaviour *and* record granularity.
The clinical partner: `read_chart` as `read` folds into an aggregate, so the trail cannot say whose
chart was read, and the only class that keeps a per-disclosure record is `benign` — which cannot be
written in a regulatory submission. The legal partner published privileged-material access as
`benign` for the same reason and said so. The SRE: "restart a service" is benign on a stateless
worker and consequential on a primary, same action name, and `execution.target` can only ever be
`mcp:<server>`. **Answer to question #2: the axis is right and the resolution is wrong.** Not one of
the four asked for a fifth class. All four asked for a second dimension.

## What each found alone, and what it cost

| Finding | Found by | Status |
|---|---|---|
| Quick-start crash on unclassified tools | all four | **fixed** 2026-08-04 |
| A wedged stream has no exit — `clear_wedge` unreachable | SRE, confirmed by clinical | **fixed** 2026-08-04 |
| `clean-install.sh` clobbers the *host's* image tags | clinical | **fixed** 2026-08-04 — it happened, to a live deployment |
| Money is invisible: budgets accrue `requests`, never `money-eur` | commerce | open |
| Rate limit drops consequential work instead of queueing it | commerce | open |
| A single-root deployment can never un-wedge (`gate-self-approval`) | clinical, SRE | open |
| Offline, a refusal claims `parked` for a hash the kernel 404s | commerce | open |
| `/v1/payloads/<hash>` cannot distinguish "decayed" from "never existed" | clinical | open |
| Seeded class weaker than `default-unknown` is silently discarded | clinical, SRE | open |
| No per-action approver, no quorum, no matter/case dimension | legal | open |

The open rows are in `docs/open-defects.md` and `docs/spec-debt.md`. They are recorded rather than
fixed because several of them are **design questions, not defects** — a per-amount gate rule and a
second scope dimension both change the wire contract, and neither should be decided in the same day
they were reported.

## The sentence worth keeping

From the commerce report, about the €50,000 refund it batch-approved in seven seconds:

> The audit is perfect and the control was zero.

That is the shape of every finding above. What this system claims — that nothing happens without a
record, and no record can be forged — held under four hostile evaluations in four domains. What it
does not yet do is make the human in the loop *able* to be the control the design assumes they are.

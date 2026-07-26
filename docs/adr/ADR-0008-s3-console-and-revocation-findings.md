# ADR-0008: Findings from the S3 console and revocation work

**Status:** Accepted · **Date:** 2026-07-26 · **Arises from** S3 (`feature/s3-console`)
**Closes** ADR-0007 §1 · **Amends** `spec/02`, `spec/03`, `spec/04`, `spec/05`, `spec/06`

---

## ADR-0007 §1 is CLOSED — revocation is now preventive

The gateway resolves the revocation set **before** the mandate walk and therefore before anything is
forwarded. `GET /v1/revocations` returns `{revocation-epoch, count, revocations[]}` with an
`ETag` over the sorted revocation ids; the gateway polls conditionally on the policy interval (no
new config knob), verifies each object's signature itself, and caches the set persistently so it is
enforced while offline. `revoke-cached` is now acted on rather than merely parsed.

**Prevention is proven by an out-of-process witness, not by the gateway's own claim.** The downstream
server records every invocation to a file; the end-to-end test captures the call list before and
after a revocation and asserts equality:

> `"the downstream server was invoked after the mandate was revoked: … — this is detection, not prevention"`

A counterfactual (`test_the_same_call_proceeds_when_nothing_is_revoked`) prevents the assertion
passing vacuously on a gateway that refuses everything. "Refused" is the gateway's claim about
itself; "never asked" is a fact recorded by a different process. Twelve revocation tests total.

---

## A. `spec/06 §4.3` assigns an obligation to the party that cannot observe the event

**This is the one S3 demo bullet not fully met, and the reason is structural, not effort.**

§06 §4.3 says the kernel MUST record a parked request and expose it in the console pending queue.
But the party that knows a request parked is the **emitting component**, and `spec/02 §2`'s `kind`
vocabulary is closed with **no member for a parked request** — so there is no legal envelope by
which a component can tell the kernel it parked something, and `spec/10` never requires it to try.

**Consequence today:** the console pending page can only list what the kernel actually holds —
effect envelopes with `outcome: blocked` (awaiting a human) and `denied` (already answered). The
park itself is real and asserted at the MCP boundary (`result: parked`, `reason-code: gate-parked`,
`classification-tier: heuristic`, downstream never invoked), but the kernel cannot see it.

**Handled correctly:** the page states its own blind spot in prose, citing `spec/06 §4.3` and this
ADR, rather than rendering a partial queue that reads as complete. An incomplete audit surface that
looks complete is worse than one that declares its limit — this is the console equivalent of the
`[unknown]` vs `[clean]` distinction.

**Resolution required in S4:** either `spec/02` gains a `park-request` kind (or `spec/06` defines a
request-submission route), or §06 §4.3 is restated as an obligation of the kernel-native gate only.
**S4 must close this** — the definition of done requires an approver to see the park in the console
and approve it there.

## B. A revocation-caused refusal cannot itself be recorded as an envelope

`spec/03 §7` makes a mandate revoked at `T` invalid for every effect with `emitted-at ≥ T`. A
component's own record of *"I refused this because the mandate was revoked"* is an effect emitted
after `T` citing that mandate — so the kernel MUST refuse it, and correctly does.

The only kernel-side record is therefore the rejection record of `spec/04 §7`. Nothing is lost —
`/console/rejections` shows `mandate-revoked` and the rejection chain itself verifies `VALID` — but
"the refusal is audited" resolves to the **rejection stream, not the effect chain**, and no spec
text says so.

This compounds ADR-0007 §6: that refusal also wedges the emitting stream, so a revoked caller's
stream is stuck until an operator intervenes. `spec/03 §7` or `spec/04 §7` should state both facts.

## C. A component can check a revocation's signature but not its authorization

`spec/03 §7` makes a revocation valid iff signed by the mandate's grantor, an **ancestor's**
grantor, or an enrolled root. A gateway holds only its leaf mandate, so the ancestor case is
undecidable for it.

**Implemented:** accept any signature-valid object from the authenticated feed. This is deliberately
the safe direction — over-accepting a revocation costs availability, under-accepting costs
prevention, and prevention is the security property. But it means feed integrity rests on the
kernel's authenticated channel rather than on the component's own verification. **The spec should
name which party is normative for revocation authorization on the pull path.**

## D. `revoke-cached` has no discharge rule

`spec/05 §6` says re-pull before the next consequential action; it never says when the duty ends, so
a literal implementation re-pulls forever. **Implemented:** discharged once a pull *reaches* the
kernel for that policy version — a `304` counts, because it confirms the held set is current. Worth
one sentence in §05 §6.

## E. The revocation feed itself was unspecified

`spec/03 §5` lets verification caches key on a `revocation-epoch`, but nothing defined the epoch or
an endpoint, and `spec/05 §2.2` gives an ETag only to policy. The shape implemented above should
become normative in `spec/03 §7` or `spec/05 §2`.

## F. Minor — resolved

ADR-0007 §1 noted the missing `kind` filter on `GET /v1/envelopes`. Added, along with `action`.

---

## Scope discipline held

`docs/design/console.md` fences v1 and names what is explicitly out. Nothing outside that fence was
built — no dashboards-for-dashboards, no agent chat UI, no workflow editor, no theming.

Three v1 surfaces were **deliberately deferred with reasons**, not forgotten:

- **Notification adapter** — `docs/build-plan.md` places it at S4.
- **Servanda view** — the build plan places the Servanda bridge after S5.
- **Budgets** — deferred for the honest reason: **the store has no spend accounting.** Mandates
  carry `budget` and cognition envelopes carry `cost`, but nothing accumulates per-dimension spend,
  so a "spend against caps" page **would have had to invent its numbers**. Refusing to ship a page
  that fabricates figures is the right call for an audit product. Needs a kernel-side budget
  projection first (related: ADR-0006 deferred budget *consumption* accounting at S1).

## Other deferred items

- **Console browser ergonomics** — the console uses only the kernel's Bearer credential (per the
  "do not invent a second auth scheme" constraint), which in a browser needs a header-injecting
  reverse proxy today. A console session scheme is an explicit S5 packaging decision.
- **Pagination** — the audit explorer caps at the store row limit (default 200, clamped 10 000), no
  cursor paging. Fine at S3 volumes; needed before a design partner's real log.
- **Revocation feed pruning** — revocations are permanent facts, so the set only grows; wants a
  `since`/window parameter at scale. The epoch/`304` design already keeps polling cost flat.

## Read-only is structural

`Store::append` remains `pub(crate)`, reachable only from `Ingest::submit`. Every console route is
`GET`; a test asserts POST/PUT/PATCH/DELETE return 405 on all ten paths. An "approve" here would
have to be a signature travelling through `POST /v1/ingest` like everything else — which is exactly
what S4 builds. `spec/06 §2` names an administrative append as a conformance failure and the S1
suite actively attempts one.

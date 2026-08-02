# Design: completing Stozher as a product

**Status:** Superseded as a status report; still current as a definition · **Date:** 2026-07-31 ·
**Input to** a `/sc:implement` pass, not an implementation itself

> **Read this before §3.** Every release below is closed, **v1.0 included**. v0.2, v0.3 and v0.4
> delivered as planned (ADR-0013, ADR-0014, ADR-0015); **v0.9 was closed on 2026-08-01 by owner
> decision** — the external review attested without a recorded scope, and the
> independent-implementation half of its gate **waived, not achieved** (ADR-0022); **v1.0 was
> declared on 2026-08-02**, likewise by decision, with §3's design-partner condition **waived, not
> met** (ADR-0024). Both empirical questions in §6 below are therefore still open, and ADR-0024 §2
> says what that costs.
>
> §3's tables are what each release *was defined to deliver*, not a list of outstanding work. A
> reader who takes them as a to-do list re-does finished work — which has happened, which is why
> this paragraph is here rather than in a commit message.

This is a design document. It defines what "product" means for *this* project, sequences the
remaining work into releases with executable gates, and specifies the three items that need a real
design decision before anyone writes code. It deliberately does not write that code.

---

## 1. What "product" means here — the definition this plan is measured against

Stozher's own positioning fixes the target more tightly than "make it good":

- **Single-tenant, self-hosted, per organization.** Not a SaaS that supports self-hosting — the
  inverse. Deployment is `docker compose` on the customer's infrastructure.
- **Sold on provable auditability** to a CISO or auditor, championed by a Head of AI.
- **Orchestrator-agnostic.** It governs effects; it does not schedule work.

Three concrete consequences for this plan:

1. **The buyer will run a pen test.** Every defect that turns prevention into detection is a
   product defect, not a polish item.
2. **The operator is on their own.** No SRE of ours is on call. Anything that fails silently, or
   that requires knowledge not in the repo, is a product defect.
3. **The auditor must be able to disbelieve us and still verify.** Anything that requires trusting
   our console rather than the signed bytes is a product defect.

**A feature is not "product-complete" here because it exists. It is complete when it fails
correctly.**

## 2. The inclusion test — applied, not restated

ADR-0002 fixes the filter:

> **Stozher governs effects; it does not provide capabilities.** Inclusion test: does it strengthen
> the audit/gate/mandate story? If it merely makes Stozher "do more," it stays out.

Applying it to everything currently on the table:

| Candidate | Verdict | Why |
|---|---|---|
| Fix aggregate-count integrity | **In** | The count *is* the audit claim for `read` |
| Gateway/kernel enforcement parity | **In** | Prevention vs detection on the governed path |
| Upgrade + schema migration | **In** | An audit trail you cannot carry forward is not an audit trail |
| Budget accounting | **In** | Mandate scope is already normative; unenforced scope is a false claim |
| Conformance harness (`spec/08`) | **In** | It is the mechanism that makes third-party emitters trustworthy |
| Spec catch-up + vectors | **In** | Two implementations cannot verify each other without it |
| CI | **In** | The product's thesis is "provable, not asserted"; unverifiable claims contradict it |
| Multi-tenancy | **Out** | Maxim 4, by construction |
| Workflow/DAG editor | **Out** | That is an orchestrator (ADR-0002) |
| Agent chat UI, dashboards, theming, marketplace | **Out** | `docs/design/console.md` names them out |
| Alerting/SIEM integration | **Out for v1** | The export is the integration point; a connector is capability, not governance |
| Drift learning (policy tier 3) | **Out until ~1000 approvals** | No data to learn from; the trigger is already recorded |

## 3. Release sequence

Each release carries **one executable gate**, in the discipline the build already uses. A release is
not done until its gate passes as an automated check, and no gate may be weakened to pass.

### v0.2 — "it enforces what it claims"
*Correctness. Everything here is a known, confirmed defect.*

| Item | Source | Design note |
|---|---|---|
| Aggregate count integrity | audit H1 | `checked_add` (or fold in `i128`), **plus** a cardinality bound on `by-action`, **plus** `[profile.release] overflow-checks = true`. The profile setting is the load-bearing half: without it this defect class stays structurally invisible to a suite that runs in debug |
| Gateway enforcement parity | audit M1–M3, spec-drift 3.1–3.2 | The gateway must run the same eleven steps the kernel does: subject-level self-approval, timestamp shape validation before comparison, `single-use` coercion matching Rust's safe default |
| Approver resolution refuses | audit H3 | An unresolvable approver subject must refuse, not widen to "any root" |
| Unbounded mandate walk | audit H2 | Falls out of the `by-action` bound |
| Payload content-type | audit H4 | Allowlist media types at ingest; serve with `nosniff` + `Content-Disposition: attachment` |
| Install collisions | ops HIGH-2/3/4 | `bootstrap` must preserve operator-set `.env` keys across its rewrite; `stozher-approve` must resolve the network like its two siblings; the "already bootstrapped" guard must distinguish a real install from a stray `docker compose up` |
| Restore ordering | ops HIGH-5 | Verify before installing, or roll back on failure — a refused restore must not leave a kernel serving the chain it rejected |

**Gate:** a new `parity` vector kind that both implementations consume, covering every divergence
above, plus the existing suites. *The gate is not "the bug is fixed" but "the two implementations
cannot diverge here again without a test failing."*

**Why this ordering:** every item is a confirmed defect where the product does something other than
what it says. Nothing else matters until this is true.

### v0.3 — "an operator can live with it"
*Operability. The gap between a demo and something you run for a year.*

| Item | Design note |
|---|---|
| Schema migration | See §4.1 — the one genuinely new mechanism |
| Upgrade path | Documented procedure + a version-compatibility statement. Today `store.rs:258` claims to "migrate" and there is no migration mechanism |
| Decay scheduling | The endpoint works and nothing calls it. Either the kernel owns the timer (as it already does for checkpoints) or the docs make it an explicit operator duty — silence is the defect |
| Audit explorer pagination | Cursor-based; the current row cap silently truncates a real log |
| Export streaming | Only if a design partner's log makes the in-memory body impractical — the bound is recorded, revisit on evidence |
| Downstream health | A declared-but-unreachable MCP server must be visible to the operator and recorded, not silently absent from `tools/list` |
| Resource limits, log rotation, read-only rootfs | Compose-level; the posture is otherwise good |

**Gate:** an install upgraded across a schema change retains and re-verifies its full chain.

### v0.4 — "a third party can extend it"
*The extension contract, which is the product's growth story.*

| Item | Design note |
|---|---|
| Conformance harness | See §4.3 — `spec/08 §3.3` exists as text with no implementation |
| Tier-A manifest loading | The classifier supports it; nothing loads one |
| `kernel.register_component` | Registration is the gated action the harness unlocks |
| Budget accounting | See §4.2 |

**Gate:** a component not written by us registers through the documented path, its manifest governs
its classification, and its budget is enforced at spend time.

### v0.9 — "it can be disbelieved and still verified"
*Trust. Mostly not engineering.*

| Item | Design note |
|---|---|
| **External crypto + security review** | Mandatory per the build plan. `SECURITY.md` already hands a reviewer a ranked map. **Cannot be substituted by internal work** |
| Spec catch-up | ADRs 0006–0012 hold normative text not in `spec/`; ~20 items, 16 mechanical, 4 needing decisions |
| `x-` register adoption | With a stated rule for historical rejection records — renaming does not rewrite a chained past |
| Vector coverage | New kinds: `policy-evaluation`, `trigger`, `checkpoint`, `manifest`. §05, §07, §08 and checkpoints currently have **zero** |
| `spec/§02 §1` member table | One table; today a literal implementer rejects five of nine envelope kinds |

**Gate:** an independent implementation, written from `spec/` alone by someone who has not read our
code, passes the vector corpus.

*That gate is the real definition of done for a protocol product, and it is the only one here we
cannot grade ourselves.*

### v1.0 — "someone else runs it"
No new engineering. v1.0 is declared when: v0.9's gate passes, the external review's findings are
closed, and **at least one design partner has run it in anger for a month**. Empirical questions #1
and #2 close here or not at all.

## 4. The three items that need real design, not just implementation

### 4.1 Schema migration

**Problem.** `store.rs` re-applies `CREATE TABLE IF NOT EXISTS` on every open. There is no
`user_version`, no migration table, no `ALTER TABLE` anywhere. Forward-compatible by accident: the
first additive column ships with no mechanism to reach an existing store.

**Constraint that makes this unusual.** The store is **append-only, hash-chained, and enforced by
database triggers**. A conventional migration that rewrites rows is not merely discouraged here — it
would invalidate the chain and destroy the product's only claim.

**Design.**
- `PRAGMA user_version` as the schema version; a migration registry of forward-only steps.
- **Additive-only for chain-bearing tables.** New columns must be nullable or defaulted; no
  backfill that touches `canonical_json`, `id`, `prev_hash`, or `seq`. If a change cannot be
  expressed additively, it is a new stream or a new envelope kind — not a rewrite.
- **Projections are rebuildable; the chain is not.** Non-chain projection tables (`roots`, catalog,
  metrics) may be dropped and recomputed from the envelope stream. State this distinction in the
  schema itself so it is not folklore.
- Migration runs inside the same `BEGIN IMMEDIATE` discipline, and **verifies the chain after
  applying** before reporting success.
- The triggers must be re-established after any change, and a test must attempt an `UPDATE` on each
  chain-bearing table post-migration — the existing "actively attempt the bypass" pattern.

**Gate:** a store created at version N, migrated to N+1, verifies identically and refuses mutation.

### 4.2 Budget accounting

**Problem.** Mandates carry budget dimensions; cognition envelopes carry cost; `budget_within`
enforces narrowing at *grant* time. **Nothing accumulates spend**, so a budget is a declaration the
system never checks. The console's budgets page was correctly not built rather than invent numbers.

**Design.**
- A **spend projection** folded from the envelope stream, keyed by `(mandate-ref, dimension)`.
  Rebuildable from the chain — it is a fold, not a source of truth (maxim 9).
- Spend accrues to the mandate **and to every ancestor**, since a delegated mandate's budget is
  bounded by its parent's. This is the same ancestry walk `mandate.rs` already does; reuse it rather
  than inventing a second traversal.
- **Enforcement point is ingest**, alongside the existing policy step: an effect whose accrual would
  exceed any budget in its chain is refused with a named code. Deciding at ingest means the refusal
  is chained and auditable — which is the entire point.
- **Monetary comparison must be decimal, not `f64`.** `budget_within` currently parses money with
  `s.parse::<f64>()`, reintroducing binary64 exactly where `spec/01 §2.5` removed it. Fix as part
  of this work and **specify the comparison semantics in `spec/03 §4.3`, which today defines none.**
- Vectors for `mandate-budget-exceeds-parent` and for boundary comparison — currently absent, so two
  implementations can disagree at the limit with nothing catching it.

**Open decision for the owner:** whether exhausting a budget **blocks** or **gates**. Blocking is
simpler and matches `prohibited`; gating turns a cap into an approval prompt and is probably what an
organization actually wants. This is a product decision, not a technical one.

### 4.3 Conformance harness

**Problem.** `spec/08 §3.3` requires "no green conformance run, no registration". The check exists
(`store.rs`), and the thing it checks for — an actual harness that exercises a component — does not.

**Design.**
- A harness binary that, given a manifest and a component endpoint, drives **every declared action
  type** and asserts: envelope schema conformance, signature validity, mandate handling, aggregation
  behaviour for `read`, and — for declared durable objects — that a replayed transition sequence
  folds correctly with the right signing authority per transition.
- **It must attempt the negative cases**, in the pattern the kernel suite already uses: an
  unsigned envelope, an expired mandate, a gated action without authorization. A harness that only
  proves the happy path certifies nothing.
- Output is itself an envelope (`kernel.conformance_run`), which per ADR-0012 is root-approved — so
  the harness produces evidence, and a human still signs the registration.
- **The harness is the product's trust boundary for third-party code.** It deserves the same
  adversarial treatment as the gate: it should be mutation-tested against a deliberately
  non-conformant component.

## 5. What this plan deliberately does not do

- **No new outbound channels.** Stozher owns exactly one (the approver ping). Everything else the
  organization sends is a governed effect through the gateway (ADR-0002, inverted-outbound).
- **No alerting/SIEM connector.** The NDJSON export is the integration point. A connector is
  capability.
- **No multi-tenancy, ever.** Maxim 4.
- **No UI beyond the five v1 surfaces.** The console fence stands.
- **No drift learning until the data exists.** The trigger (~1000 approval events) is already
  recorded; building the learner first would be building a model with no training set.

## 6. What no amount of engineering closes

Stated because a completion plan that implies otherwise is dishonest:

1. **The external security review.** It is not a task we can execute; it is a task we can only
   prepare for and then submit to. `SECURITY.md` is that preparation.
2. **Empirical question #1** — is the pending queue a daily driver? Only dogfooding answers it. If
   the answer is no, v1 scope is wrong and the console thesis needs rethinking *before* an external
   user sees it.
3. **Empirical question #2** — does the four-class taxonomy survive a foreign domain? Only a
   component we did not write answers it. S2b's skip means this run produced *less* evidence than
   planned, not more.
4. **Whether anyone wants it.** Two to three design partners, per the positioning doc. No amount of
   correctness substitutes for that signal.

## 7. Suggested first move

v0.2 is the only release whose items are all confirmed defects with known fixes, and its gate — a
shared `parity` vector kind — is also the structural fix for how the divergences arose: work split
by directory left cross-implementation consistency in nobody's slice. Closing it with vectors rather
than with two careful edits is what stops it recurring.

Everything else can wait behind evidence. That one cannot, because the product currently claims
enforcement it does not perform.

## Related

`docs/adr/ADR-0002` (the inclusion test) · `docs/adr/ADR-0004`–`ADR-0012` (deviation record) ·
`docs/build-plan.md` (the S0–S5 discipline this sequence continues) · `SECURITY.md` (reviewer map) ·
`docs/open-questions.md` (the two empirical questions)

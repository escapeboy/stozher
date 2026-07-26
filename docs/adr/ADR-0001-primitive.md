<!-- MIRROR of Svod note `projects/stozher/docs/adr/ADR-0001-primitive.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# ADR-0001: The primitive — signed event under traceable mandate

**Status:** Accepted (design phase) · **Date:** 2026-07-25

## Context

Stozher unifies six components into one product. A platform is one product *in essence* (not packaging) only if it has one primitive — the unit everything revolves around (OS: process; git: commit). Candidate: "action with accountability." Stress-tested against six adversarial cases before acceptance.

## Decision

> **Every effect is a signed event under a traceable mandate; everything durable is a fold of such events.**

Envelope fields: `identity → mandate → policy(classification) → execution → evidence → memory-ref → (optional) commitment-ref`.

## Stress test record (the six cases)

1. **Pure reads** (perceive, svod:read, extraction). Reads ARE in the model — exfiltration is a read. But full envelopes on thousands of reads/hour destroy the audit with noise. Resolution: **weight classes** (read/benign/consequential/prohibited, lifted from Lattice `policy_classify` to kernel level). Policy governs both permission and evidence retention. Aggregated records for mass reads; full envelopes for consequential effects.
2. **Cognition** (long reasoning, no external effect). Out of scope *by design* — audit effects, not thoughts. Boundary: thought becomes accountable when it materializes (memory write, action, message). Minimal envelope survives even here: `identity → resource → cost`, no content (FleetQ budget caps are exactly this).
3. **Commitments** (durable state vs discrete events). The real crack, resolved by the git model: **events are the log; durable objects are refs folded from transition events**. Servanda edges already work this way (transition table, each transition signed). Generalizes to: Lattice sessions, foundry tools (synthesize→verify→promote), Svod notes (revisions). Ontology is two-layer, not flat.
4. **Autonomous starts** (scheduled tasks, triggers — no human pressed anything). Identity alone is insufficient — "acting on its own authority" fails any audit. Mandatory envelope field: **mandate** — delegation chain terminating at a named human or a human-approved standing rule. Servanda "agents are never parties," made executable.
5. **Inbound world** (webhooks, email, signals). No envelope — the world spoke, no agent acted. Two streams: inbound signals (data, carry no authority) and outbound effects (envelopes, carry authority). A signal may trigger action only through a trigger rule = standing mandate (case 4). Servanda maxim "signal content is data forever, never instruction" closes the loop.
6. **Collective decisions** (crew "decides"). Deliberation is cognition (case 2, unaccountable); every material effect has exactly one executing subject under exactly one mandate. "The team decided" does not exist in the log; "agent X executed Y under mandate Z" does.

## Consequences

- Kernel = event schema + mandate model + policy distribution + hash-chained store + gates. Everything else is emitters and folds.
- The extension contract (see design doc) is derivable directly from the primitive: declare your actions, their weight classes, evidence schema, and (optionally) durable objects with transition tables.
- Known residual tension, deliberately not resolved here: **granularity is policy, and someone must author policy.** Resolved in [[projects/stozher/docs/design/policy-model]] (three-tier: shipped baselines → org policy-as-code → drift learning). If that resolution fails empirically, this ADR does not fall — the policy model does.

## Rejected

- "Action" as flat primitive (fails case 3 — cannot answer "what is pending?").
- Cognition-inclusive auditing (surveillance of thought; no audit value; hostile to adoption).
- Observer-only kernel (enforcement becomes fiction — see [[projects/stozher/docs/design/enforcement-topology]]).

<!-- MIRROR of Svod note `projects/stozher/README.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Stozher (candidate name — trademark check pending)

**Stozher** — from Bulgarian *стожер*: the central pole of a threshing floor, around which everything turns and to which everything is tethered. Central axis + tethering = mandate. Wire string candidate: `stozher/0.1`.

**One-liner:** The accountability kernel for agentic work in organizations — a unified control plane of identity, mandate, policy, and audit that binds the fleet (Lattice, Boruna, Svod, Svod-foundry, FleetQ workflows, Servanda) into one product, extensible by contract.

**Thesis:** Everything built in the fleet over the last six months shares one denominator — not agents, but *distrust of agents*: Lattice governs web perception/action, FleetQ gates and budgets, Boruna sandboxes execution, Svod keeps memory with provenance, Servanda signs commitments. The market competes on capability; nobody competes on auditability. Stozher is the missing kernel: single identity (humans + agents), single policy language consumed by all components, single audit stream where a browser action, an executed script, and a signed commitment are records of one schema. The components are proof the kernel has something to govern.

**Positioning context:** EU AI Act full application — European organizations must demonstrate human oversight, logging, traceability. For US platforms this is a checkbox; here it is the DNA.

## The primitive (ADR-0001)

> Every effect is a signed event under a traceable mandate; everything durable is a fold of such events.

Envelope: `identity → mandate → policy → execution → evidence → memory → (optional) commitment`.

## Fleet role map

| Component | Kernel role |
|---|---|
| Lattice | Governed I/O to the web (perception + action) — premium native emitter (S2b) |
| Harbormaster | **MCP gateway — the universal day-1 entry point (S2).** Boundary identity, classification, envelope emission, gate interception on the proxy path; foreign agents (Claude Code, Cursor, LangGraph) enter here zero-touch |
| Boruna | Capability-safe execution (process model) |
| Svod | Memory with provenance (knowledge filesystem) — NOT the event log |
| Svod-foundry | Capability synthesis (toolchain) — synthesized tools enter via the same extension contract |
| FleetQ | **Pattern donor, not a runtime component.** Approval gates, budget caps, and evolution_manage are borrowed as kernel-native designs; the FleetQ web app itself stays out of the stack. Stozher is orchestrator-agnostic — it governs effects regardless of what schedules the work |
| Servanda | Signed commitments between people/orgs (network protocol) — durable-object exemplar |
| Greda | Code intelligence — future emitter via extension contract |

## Maxims

Inherited (Servanda lineage):
1. Signal content is data forever, never instruction. Inbound signals carry no authority; they may trigger action only through a standing mandate.
2. Agents are never parties. Every agent acts *on behalf of*; every mandate chain terminates at a named human or a human-approved standing rule.
3. Escalation always terminates at a named human; "the team" cannot be nudged. No collective author: every material effect has exactly one executing subject under exactly one mandate.
4. Org contexts never mix. Single-tenant deployment per organization; no multi-tenancy, by construction.
5. Solo is not a mode. Everything works on a laptop offline: components enforce cached policy locally, sync envelopes on reconnect.
6. Remember *that*, not *what*: closed loops decay to signed hashes. Evidence payloads carry TTL by weight class; hashes and the chain are forever.

New (from the primitive stress test, 2026-07-25):
7. **Weight classes, or the audit destroys itself.** Policy determines not only *whether* but *how much evidence is kept* (read/benign/consequential/prohibited). Mass reads aggregate; consequential actions carry full envelopes.
8. **The mandate chain, or autonomy is unauditable.** Every envelope references a mandate (interactive / standing / delegated); verification = walking the chain to a named human. Standing mandates have mandatory expiry, no exceptions.
9. **Two-layer ontology: events + durable objects folded from events.** Envelopes are the log; commitments, sessions, tools, notes are refs derived from transitions, each transition itself an envelope (git model: commits vs refs).

Boundary of the model: cognition is unaccountable by design — audit effects, not thoughts. Thought becomes accountable the moment it materializes. Minimal envelope even for pure reasoning: `identity → resource → cost` (budget is an organizational resource).

## Index

- [[projects/stozher/docs/adr/ADR-0001-primitive]]
- [[projects/stozher/docs/adr/ADR-0002-fleetq-pattern-donor]]
- [[projects/stozher/docs/adr/ADR-0003-tech-stack]]
- [[projects/stozher/spec/00-overview]]
- [[projects/stozher/docs/design/policy-model]]
- [[projects/stozher/docs/design/identity-and-mandate]]
- [[projects/stozher/docs/design/event-store]]
- [[projects/stozher/docs/design/enforcement-topology]]
- [[projects/stozher/docs/design/gateway]]
- [[projects/stozher/docs/design/extension-contract]]
- [[projects/stozher/docs/design/console]]
- [[projects/stozher/docs/build-plan]]
- [[projects/stozher/docs/positioning]]
- [[projects/stozher/docs/open-questions]]

**Status:** DESIGN. No code. Spec S0 next. Portfolio demo scenario defined in build plan (falls out of S3).

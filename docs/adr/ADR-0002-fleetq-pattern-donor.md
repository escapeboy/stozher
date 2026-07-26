<!-- MIRROR of Svod note `projects/stozher/docs/adr/ADR-0002-fleetq-pattern-donor.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# ADR-0002: FleetQ is a pattern donor, not a runtime component

**Status:** Accepted · **Date:** 2026-07-26

## Context

FleetQ (agent-fleet-o, AGPLv3) contains battle-tested governance machinery that anticipates Stozher. Question: include the app (or subsystems) in the Stozher stack, or harvest designs only. Evidence reviewed: README, docs/capabilities.md (45 domains, 675+ MCP tools, 424 migrations), security-review-2026-03-31.md, API_AUDIT_REPORT.md (2026-04-02), Real-World Action Governance implementation.

## Decision

**FleetQ does not enter the Stozher stack — not whole, not as subsystems.** Designs are harvested; code is not. FleetQ remains an independent dev/power-user tool and idea proving ground.

Grounds (each sufficient alone):
1. **Security posture is disqualifying for our pitch.** Own review: 2 HIGH (IDOR on `knowledge_base_id` via MCP tools; mass assignment on system-computed fields) + systemic missing-authorization pattern across Livewire save methods and MCP tools, acknowledged as pre-existing; 16k-line phpstan baseline; warm-build-as-root finding from the spinout evaluation. Auditing 45 domains to a sellable bar costs more than building the kernel. We sell accountability to CISOs; the box must survive their pen test.
2. **Contradicts orchestrator-agnostic positioning** (README fleet map): re-importing subsystems drags MariaDB+Redis+Reverb+queues back into the single-tenant deploy and reintroduces vendor lock-in at the procurement table.
3. **Surplus is toxic, not neutral.** Crews, evolution, ROCS, voice, GPU templates, screenpipe — each is a security-questionnaire line the customer must accept even unused.

## Governing principle (applies to all future inclusion questions)

> **Stozher governs effects; it does not provide capabilities.** Inclusion test: does it strengthen the audit/gate/mandate story? If it merely makes Stozher "do more," it stays out.

## Disposition of specific FleetQ subsystems

| Subsystem | Decision | Rationale / where the value lands |
|---|---|---|
| Workflows (visual DAG) | **Out.** | Workflows ARE the orchestrator; including them makes us another agent platform. `correlation-ref` (spec 02) is the whole integration. Possible future separate product on the kernel; trigger: design-partner demand. |
| Signals (inbound, 27 drivers) | **Concept already in kernel (spec 07); connectors out.** | Signals = data without authority; action only via standing mandate. Every inbound source exists as an MCP server and enters via the gateway. Driver list harvested as Tier B catalog requirements. |
| Outbound (15 channels) | **Out, inverted.** | Sending a message is a *governed consequential effect* (client's own tools via gateway), not infrastructure we provide. Stozher owns exactly one outbound: the approver ping (minimal notification adapter, Slack/email/webhook) — console dependency, nothing more. |
| Knowledge base / Memory | **Out — seat is taken by Svod** (adoption ladder rung 4: governed memory with provenance). Two memory layers in one product is architectural absurdity. | **Harvested pattern:** memory-proposal queue = the promotion-through-gate mechanism (messy→curated) for the shared-memory layer; enters Svod-rung design when we get there. |
| Crews, evolution UI, ROCS, voice, GPU templates, chatbots, marketplace | **Out.** | Capability surplus; fails the inclusion test. (evolution_manage *pattern* already harvested — policy tier 3 drift learning.) |

## Harvested designs (proven in battle, ported as design not code)

- **Proposal → approve → auto-execute** state machine: `ActionProposal` polymorphic targets, approval event → queued **idempotent** execution job. → kernel gates (S4).
- **Chokepoint / decorator gating**: one `IntegrationActionGate` covering 50+ drivers; `GatedGitClient` decorator inherited transparently by 27 tools. → gateway proxy-path interceptor: one chokepoint, not per-tool logic.
- **Per-tier risk policy** `{low,medium,high}→auto|ask|reject`, read/write/destructive mapping: independent validation of the four-class taxonomy (theirs lacks `prohibited`). Their heuristic verb classifier = prototype of gateway Tier C classification.
- **Unified approvals inbox** UX → console pending queue.
- **Credit ledger with pessimistic locking + auto-pause** → budget dimensions implementation reference.
- **Connector catalog** (inbound + integrations) → requirements list for the shipped Tier B classification catalog.

## The anti-lesson (recorded so it is never repeated)

FleetQ bypasses gates during approved-proposal re-execution via **container bindings** (`app('integration_gate.bypass')`, try/finally). This is exactly how a gate must NOT be circumvented: an ambient, unauditable side channel any code can flip. In Stozher, re-execution after approval carries **the approval's signature in the envelope** — the permission travels with the effect, cryptographically, or the effect does not happen. No DI holes.

## Consequences

- Console gains one small dependency: notification adapter for approver pings (2–3 channels max).
- FleetQ product line: remains dev tool / polygon; not sold to organizations; maintained as long as useful. Stozher is the enterprise product. (Owner's strategic call, recorded, revisitable.)
- Any future "shouldn't we also take X from FleetQ" question is answered by the governing principle above before it is answered by enthusiasm.

## Links

[[projects/stozher/docs/design/gateway]] · [[projects/stozher/docs/design/policy-model]] · [[projects/stozher/docs/design/console]] · [[projects/stozher/docs/build-plan]] · [[projects/stozher/docs/adr/ADR-0001-primitive]]

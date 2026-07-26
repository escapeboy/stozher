<!-- MIRROR of Svod note `projects/stozher/docs/design/gateway.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Gateway — Harbormaster as the universal entry point

**Decision (2026-07-26):** the MCP gateway is an **evolution of Harbormaster**, not a new component. Harbormaster stays what it is (MCP aggregator, v2.x GA, battle-tested against 45+ projects); Stozher adds an enforcement/emission layer to its proxy path. Mature code is redirected, not rewritten.

## Why this is the real day-1 product

Organizations do not have Lattice/Boruna. They have Claude Code, Cursor, Copilot, LangGraph scripts — all speaking MCP to their tools. The universal integration point is therefore the MCP boundary: the employee's agent points its MCP config at the gateway instead of directly at servers, and the kernel sees every tool call at the border. **Zero-touch for the agent.** Fleet components (Lattice, Boruna) remain premium first-class citizens with rich native envelopes; the foreign world enters through the gateway from day 1.

## What gets added to Harbormaster's proxy path

1. **Caller identity + mandate.** Each connecting agent authenticates as a derived subject; its session carries a mandate ref (interactive by default; standing for scheduled/headless callers). Unauthenticated passthrough mode exists only for local dev, off by default in org deployments.
2. **Classification at the boundary.** Every proxied tool call gets a weight class before forwarding.
3. **Envelope emission.** Forwarded call + result → envelope (aggregated for `read` class) pushed async to the event store; policy version stamped.
4. **Gate interception.** `consequential` under a gate rule: the call parks, human approves in console, then forwards. Deny returns a structured refusal to the agent. Blocking semantics per enforcement-topology.

## The manifest gap — foreign tools have no Stozher manifest

The honest hard problem, named now, not at production time:

- **Tier A — manifested:** fleet components and contract-conformant servers declare action→class maps. Full fidelity.
- **Tier B — known catalog:** shipped classification catalog for the popular MCP servers (GitHub, Gmail, Slack, Stripe, filesystems...) — curated `tool → class` maps, versioned with the product. This catalog is real product content and a moat: nobody else is curating "what is `create_refund` allowed to mean."
- **Tier C — unknown tools:** conservative default — name/schema heuristics (read-ish → `read`, everything mutating or opaque → `consequential`) + first-call gating: the first invocation of an unknown tool always parks, the approver's decision seeds the org's local catalog entry. Unknown ≠ ungoverned; unknown = expensive until classified. Drift learning (policy tier 3) later automates the boring reclassifications.

## Consequences

- Build plan reordered: gateway is **S2** (the sellable citizen), Lattice native emitter becomes **S2b** (the premium citizen). Demo gains a second variant: "bring your own agent" — a design partner's Claude Code shows up in the audit trail in 15 minutes.
- Harbormaster's existing surfaces (delegation, project ops) are untouched; the enforcement layer wraps the proxy path only. Version boundary: Harbormaster remains an independent tool; the Stozher layer ships as its enforcement mode/plugin, so dev users without a kernel lose nothing.
- Latency budget: classification + emission must be O(ms) on the hot path; only gate-parked calls block. Aggregation for `read` happens gateway-side (the kernel never sees the firehose — event-store doc holds).

## Links

[[projects/stozher/docs/design/extension-contract]] · [[projects/stozher/docs/design/enforcement-topology]] · [[projects/stozher/docs/design/policy-model]] · [[projects/stozher/docs/build-plan]]

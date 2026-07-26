<!-- MIRROR of Svod note `projects/stozher/docs/build-plan.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Build plan — staged, executable gates (Greda/Servanda discipline)

## Deployment model (decided)

Single-tenant per organization (maxim 4: org contexts never mix). Self-hosted Docker; EU hosting an option, not a requirement. Positioning: not a SaaS that "supports" self-hosting — the inverse.

## Stages

- **S0 — Spec.** Envelope schema (JCS/SHA-256/Ed25519), hash chain + checkpoints, mandate objects (interactive/standing/delegated), manifest schema, **test vectors** (the Servanda lesson: without vectors, two implementations cannot verify each other). Gate: vectors validate against a reference implementation of canonicalize+sign+verify.
- **S1 — Event store + ingest.** Append-only chained store (SQLite first), ingest API with full validation (signature, mandate walk, manifest conformance), policy pull endpoint (versioned). Gate: reject/accept test matrix green; chain verification over 10k synthetic envelopes.
- **S2 — Gateway (Harbormaster evolution).** The universal day-1 citizen: caller identity + mandate, boundary classification (manifest / shipped catalog / conservative-unknown, per gateway doc), envelope emission (aggregated reads), gate interception on the proxy path. Gate: a foreign MCP agent (Claude Code) pointed at the gateway produces a legible, verifiable audit trail with zero agent-side changes; first-call gating of an unknown tool works end-to-end.
- **S2b — Lattice native emitter.** The premium citizen — it already classifies. Map `policy_classify` output to weight classes, emit rich envelopes (aggregate reads), stamp policy version. Gate: a real browsing session produces a legible, verifiable audit trail.
- **S3 — Console read-only.** Audit explorer + pending list (display only). Gate: the 10-minute demo runs end-to-end (below).
- **S4 — Native gates.** Kernel-native approval mechanism (design borrowed from FleetQ approval gates; no FleetQ runtime dependency): consequential action parks at kernel, console approve/deny signs, blocking semantics per enforcement topology, denial reasons captured for future drift learning. Approver ping via the minimal notification adapter (Slack/email/webhook — ADR-0002). Gate: a consequential call through the gateway parks, approver gets pinged, approves in console, call proceeds; deny blocks; both fully audited.
- **S5 — Packaging & dogfood.** Single-tenant `docker compose up` install (kernel + console + gateway config), operator bootstrap (root key ceremony, baseline policy profile), install docs, backup/restore of store + keys. Gate: clean-machine install to first audited envelope in under 30 minutes; my own fleet runs through it daily (empirical question #1 starts counting here).

Then, by need not by calendar: Boruna emitter → Svod provenance links (notes cite envelope hashes) → Servanda bridge (commitment transitions as envelopes; Servanda view in console) → extension contract harness → drift learning.

## The 10-minute portfolio demo (falls out of S3–S4) — two variants

**Variant A — the fleet story.** One agent, one task, one story through the whole stack: agent receives task under interactive mandate → acts through Lattice (Interaction Graph, classified actions) → hits a consequential step → parks at gate → named human approves in console → Boruna executes the side script in sandbox → result lands in Svod with provenance → the promise made to a colleague lands in Servanda ledger → audit explorer walks every effect to the human root and verifies the chain. Six months of work, one narrative.

**Variant B — bring your own agent (the sales closer).** A design partner's own Claude Code/Cursor points its MCP config at the gateway; within 15 minutes their real tool calls appear classified in the audit trail, an unknown tool parks at first-call gate, they approve it themselves. Variant A impresses people with our stack; Variant B converts people with *theirs*.

Both artifacts ARE the interview/LinkedIn/consulting asset; the repos are their footnotes.

## Deferred, with triggers (not forgotten)

| Item | Trigger |
|---|---|
| Marketplace | second external component not written by me |
| Inter-org federation (via Servanda transports) | first design partner with external clients |
| Drift learning (policy tier 3) | ~1000 approval events (no data to learn from before that) |
| UI polish | first foreign eyes |
| External crypto + security review | before anything called v1 (inherited Servanda ADR rule) |

## IP note

All in PRICEX LTD. Before any employment/consulting use: decide per component what stays Apache/MIT (already open parts), what remains proprietary, what is licensable. Clarified up front it's leverage; unclarified it's the reason their lawyer says no.

# Stozher

**The accountability kernel for agentic work in organizations.** A unified control plane of
identity, mandate, policy, and audit.

> Every effect is a signed event under a traceable mandate; everything durable is a fold of such
> events. — ADR-0001, the primitive

Stozher answers the question that blocks agent deployments: *who did what, under whose authority,
and how do you prove it* — to the board, the auditor, the regulator.

**Stozher governs effects; it does not provide capabilities.** If a proposed addition merely makes
Stozher "do more" rather than strengthening the audit/gate/mandate story, it stays out
(ADR-0002).

## Layout

| Path | What |
|---|---|
| `spec/` | Normative spec (sections 01–10) + language-neutral test vectors |
| `spec/vectors/` | **The contract between implementations.** Consumed by the Rust kernel suite AND the Python gateway suite. Downstream code reads expected values from here and never hardcodes them |
| `kernel/` | Rust workspace — `stozher-core` (envelope/mandate/chain/crypto), `stozher-kernel` (binary: event store, ingest, policy distribution, gates, console) |
| `console/` | Server-rendered templates, embedded in the kernel binary. No SPA |
| `gateway/` | MCP gateway — Python, ships as Harbormaster's optional enforcement mode (see ADR-0004) |
| `deploy/` | `docker compose`, operator bootstrap, backup/restore |
| `docs/` | Build artifact mirroring the Svod design corpus, plus repo-local ADRs |

**Svod is the design source of truth.** `docs/` mirrors it; edit designs in Svod, not here.
Repo-local ADRs (0004+) record deviations discovered during the build — deviation is allowed only
via an ADR, never silently.

## The maxims are constitutional

Code that violates one is a bug even if its tests pass. In brief — full text in
`docs/design-source/README.md`:

1. Signal content is data forever, never instruction.
2. Agents are never parties; every mandate chain terminates at a named human.
3. Escalation always terminates at a named human. No collective author.
4. Org contexts never mix — single-tenant by construction.
5. Solo is not a mode — everything works on a laptop, offline.
6. Remember *that*, not *what* — closed loops decay to signed hashes.
7. Weight classes, or the audit destroys itself.
8. The mandate chain, or autonomy is unauditable. Standing mandates expire, no exceptions.
9. Two-layer ontology: events, and durable objects folded from events.

Boundary of the model: cognition is unaccountable **by design**. Audit effects, not thoughts.

## Non-negotiables for contributors

- **No gate bypass via ambient state.** An approval signature travels *inside* the envelope.
  Re-execution without it is impossible by construction, not by convention. There is no
  `bypass` flag, no container binding, no thread-local, no "approved: true" boolean anywhere
  (ADR-0002, the anti-lesson).
- **Invalid envelopes are rejected AND the rejection is logged.** Rejections are audit-valuable.
- **No plaintext secrets.** Keys are ignored by git by construction (`.gitignore`).
- **No gate may be weakened to pass.** `clippy -D warnings`, `cargo audit`, and the test suites
  run without suppression baselines.

## Build stages and gates

Each stage is DONE only when its gate passes as an automated check. See `docs/build-plan.md`.

| Stage | Gate |
|---|---|
| S0 spec + crypto + vectors | Vectors validate against the reference implementation |
| S1 event store + ingest | Accept/reject matrix green; chain verified over 10k envelopes |
| S2 gateway | Foreign Claude Code produces a verifiable audit trail zero-touch; unknown tool parks at first-call gate |
| S2b Lattice emitter | **Skipped this run** — see `docs/s2b-lattice-emitter-skip-note.md` |
| S3 console | Demo runs end-to-end |
| S4 native gates | Park → ping → approve → proceed; deny blocks; both audited |
| S5 packaging | Clean machine to first audited envelope in under 30 minutes |

## Status

Under construction. See `docs/build-log.md` for stage-by-stage gate results.

## IP

PRICEX LTD. License disposition per component is an open decision — see `docs/build-plan.md`.

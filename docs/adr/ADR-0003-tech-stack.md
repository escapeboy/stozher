<!-- MIRROR of Svod note `projects/stozher/docs/adr/ADR-0003-tech-stack.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# ADR-0003: Tech stack

**Status:** Accepted (revisitable at S0 gate if reference implementation contradicts it) · **Date:** 2026-07-26

## Decision

- **Kernel (event store + ingest + policy distribution + gates) — Rust.** Single static binary, axum HTTP, sqlx/SQLite (schema forward-compatible with Postgres), ed25519-dalek + RFC 8785 JCS canonicalization. Rationale: crypto-heavy hot path, single-binary deploy weight (docker compose stays two services), Greda precedent proves the Rust-via-Claude-Code workflow works.
- **Console — server-rendered from the kernel binary** (askama/maud templates + minimal JS; no SPA framework). Rationale: the console is queues and tables, not an app; every dependency is a security-questionnaire line; one binary serves API + UI. Revisit trigger: first design-partner UX feedback demanding interactivity beyond htmx-grade.
- **Gateway — Harbormaster evolution, in Harbormaster's native language.** The enforcement layer lives on its existing MCP proxy path (chokepoint interceptor per ADR-0002 harvest); talks to kernel via HTTP ingest + policy pull. Ships as an optional enforcement mode — Harbormaster without a kernel loses nothing.
- **Test vectors — language-neutral JSON** under `spec/vectors/`, consumed by kernel tests AND gateway tests (the Servanda lesson, enforced structurally).
- **Notification adapter — in-kernel, trait-based**, Slack webhook + SMTP + generic webhook. Nothing more (ADR-0002).

## Repo layout

Monorepo `stozher/`: `spec/` (normative + vectors), `kernel/` (Rust workspace: `stozher-core` lib with envelope/mandate/chain types, `stozher-kernel` bin), `console/` (templates, embedded), `gateway/` (Harbormaster patch/plugin or submodule reference), `deploy/` (compose, bootstrap scripts), `docs/` (mirrors Svod decisions; Svod stays the design source of truth, repo docs are the build artifact).

## Rejected

- Laravel for kernel/console: strongest personal stack, but drags PHP-FPM+DB+Redis into a product whose pitch is minimal auditable surface; contradicts ADR-0002 grounds №2/№3.
- SPA console (React/Livewire): dependency surface + build chain for v1 tables/queues.
- Kotlin/JVM kernel (Svod precedent): JVM deploy weight vs single binary; Svod stays where it is, unaffected.

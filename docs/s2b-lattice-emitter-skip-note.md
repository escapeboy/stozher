# S2b (Lattice native emitter) — SKIPPED for this build run

**Date:** 2026-07-26 · **Decision:** skip, do not block · **Authority:** build run ground rule 7
("attempt only if the Lattice repo is locally reachable; otherwise record a skip note and
continue, it does not block the demo")

## Why

Lattice is not locally reachable as source. Verified before S2 planning:

- No directory matching `*lattice*` exists under `~` to depth 3 (searched, excluding `~/Library`).
- `~/htdocs/` contains `servanda`, `servanda-protocol`, `svod`, `svod-ui-macos` — no Lattice.
- Lattice is configured in `~/.claude.json` as a **remote HTTP MCP server only**:
  `{"type": "http", "url": "http://127.0.0.1:8765/mcp"}`. A running endpoint, not a codebase.

A native emitter per `docs/design/gateway.md` requires editing Lattice's own action path to map
`policy_classify` output onto kernel weight classes, emit rich envelopes, and stamp the policy
version. That is source-level work on a codebase this machine does not have.

## What was NOT done

- No mapping of Lattice `policy_classify` → `read|benign|consequential|prohibited`.
- No rich-envelope emission from Lattice sessions, no aggregation of Lattice reads.
- No policy-version stamping inside Lattice.
- S2b's gate ("a real browsing session produces a legible, verifiable audit trail") is **not
  claimed and not met.**

## Why this does not block the definition of done

The build plan makes the gateway (S2) "the universal day-1 entry point" and the sellable citizen;
S2b is explicitly "the premium citizen." The required end-to-end proof for this run is **Demo
Variant B — bring your own agent**, which routes a foreign Claude Code instance through the
gateway and never touches Lattice. Variant A (the fleet story, which does use Lattice) is out of
scope for this run by ground rule 7.

## Non-blocking, but note the coverage consequence

Skipping S2b means the four-class taxonomy is exercised in this build only through the gateway's
boundary classification (tiers A/B/C), not through a component that classifies natively. Open
question #2 in `docs/open-questions.md` — "does the four-class taxonomy survive a foreign
domain?" — therefore gets **less** evidence from this run than a build including S2b would have
produced. Recorded so it is not mistaken for validated.

## Trigger to revisit

Lattice source becomes locally reachable (clone, or the machine that hosts it). At that point S2b
is a self-contained stage against an already-green S1 ingest and S2 catalog: nothing built in this
run needs revision to accommodate it — the extension contract (`spec/08`) is the seam.

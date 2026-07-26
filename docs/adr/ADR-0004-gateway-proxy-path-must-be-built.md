# ADR-0004: The gateway proxy path must be built, not extended

**Status:** Accepted · **Date:** 2026-07-26 · **Supersedes a premise of** `docs/design/gateway.md`

## Context

`docs/design/gateway.md` (Svod, 2026-07-26) decides that the MCP gateway is "an evolution of
Harbormaster, not a new component," on the stated premise:

> Harbormaster stays what it is (MCP aggregator, v2.x GA, battle-tested against 45+ projects);
> Stozher adds an enforcement/emission layer to **its proxy path**. Mature code is redirected,
> not rewritten.

ADR-0002 reinforces this by harvesting FleetQ's chokepoint-interceptor pattern "→ gateway
proxy-path interceptor: one chokepoint, not per-tool logic."

That premise was verified against the actual Harbormaster codebase at `~/htdocs/harbormaster`
(v27.1.3, `main` @ 4f07955) before any S2 code was written. It does not hold.

**Observed:** Harbormaster is a FastMCP **server** that exposes its own tool surface
(`ask_project`, `delegate_task`, `fan_out_ask`, `recall_qa`, `await_*`, project/host ops) and
satisfies calls by spawning per-project Claude Code / Codex subprocesses (`backends/claude.py`,
`backends/codex.py`, `jobs/worker.py`). Across all 80 files in `src/harbormaster/` there is:

- no MCP **client** anywhere — no `ClientSession`, no `stdio_client`, no `sse_client`, no
  `streamablehttp_client`;
- no downstream/upstream MCP server registry, connection pool, or tool-namespacing layer;
- no code path on which a foreign agent's call to a *third-party* tool transits Harbormaster.

The "45+ projects" in ADR-0002 and the gateway doc are **delegation targets** (directories it can
ask a question about), not aggregated MCP servers. `plugins.py` is entry-point discovery for
in-process `register(mcp, config)` callables — it loads additional Harbormaster-native tools; it
does not proxy foreign ones.

**There is therefore no proxy path to intercept.** An enforcement layer "wrapping the proxy path"
has nothing to wrap.

## Decision

Build the MCP proxy path as new code, in Harbormaster's native language (Python), shipped as
Harbormaster's **optional enforcement mode**. Specifically:

1. **New component** `gateway/` in this monorepo: a FastMCP server that is also an MCP *client*,
   fronting a configured set of downstream MCP servers. It namespaces and re-exports their tools,
   and every proxied call transits one chokepoint (`enforce()`), where classification, envelope
   emission, and gate interception happen. This is the chokepoint ADR-0002 asked for; it is
   authored rather than inherited.
2. **Distribution unchanged in intent.** It ships as a Harbormaster plugin
   (`harbormaster.tools` entry point) plus a standalone `stozher-gateway` binary entry, gated
   behind explicit config. Harbormaster with `enforcement.enabled = false`, or with no kernel
   reachable, behaves exactly as v27.1.3 does today — the ADR-0003 requirement that
   "Harbormaster without a kernel loses nothing" is preserved and tested.
3. **No fork, no patch of Harbormaster's own surface.** Its existing tools, UI, and job system are
   untouched. We add; we do not redirect.

## What changed vs. the design doc, precisely

| Design doc says | Reality | This ADR |
|---|---|---|
| Extend an existing proxy path | No proxy path exists | Author the proxy path |
| "Mature code is redirected, not rewritten" | Nothing to redirect | Nothing is rewritten either — new module alongside |
| Enforcement layer wraps proxy | — | Enforcement layer *is* the proxy's single chokepoint |
| Harbormaster loses nothing without kernel | Still achievable | Preserved, and covered by an automated test |

Everything else in `docs/design/gateway.md` survives unchanged and is binding: the three
classification tiers (A manifested / B shipped catalog / C conservative-unknown + first-call
gating), zero-touch for the calling agent, gateway-side read aggregation, structured refusal on
deny, and O(ms) hot path with only gate-parked calls blocking.

## Consequences

- **S2 is larger than the build plan implies.** It includes an MCP client layer, downstream server
  lifecycle, and tool-name namespacing that the plan assumed was already paid for. Estimated cost
  is materially higher; the S2 gate itself is unchanged and remains reachable.
- **Upside:** authoring the chokepoint means it is designed for enforcement from the first line
  rather than retrofitted onto code with other concerns. No inherited bypass surface — which
  matters directly for the ADR-0002 anti-lesson (no ambient `bypass` side channel can exist in a
  path that never had one).
- **Risk retired early.** Had this been discovered at S2 implementation time with S0/S1 built
  against the assumption, the gateway contract might have been shaped by a nonexistent host.

## Related

`docs/design/gateway.md` · `docs/adr/ADR-0002-fleetq-pattern-donor.md` ·
`docs/adr/ADR-0003-tech-stack.md` · `docs/build-plan.md`

# stozher-gateway

Stozher enforcement mode for Harbormaster: an MCP gateway that classifies, mandates, gates and
records every proxied tool call — with **zero changes to the calling agent**. Point Claude Code,
Cursor or any MCP client at Harbormaster as usual; the tools it discovers are the downstream
servers' own tools, and every call now transits one chokepoint.

Normative behaviour is `spec/10-gateway-protocol.md`. Why the configuration lives here and not in
`harbormaster.toml` is `docs/adr/ADR-0005-*.md`. Why the proxy path is authored rather than extended
is `docs/adr/ADR-0004-*.md`.

## What the operator configures

Two files, deliberately (ADR-0005). Harbormaster's config models are `extra="forbid"`, so an
`[enforcement]` section there would be a hard boot failure for anyone running vanilla Harbormaster.

**`harbormaster.toml`** — only keys Harbormaster already ships:

```toml
[plugins]
enabled = true
allow = ["stozher-gateway"]
```

Uninstall the distribution and this stays valid: `load_plugins` logs a WARNING and skips.

**`stozher-gateway.toml`** — resolved from `--config`, then `$STOZHER_GATEWAY_CONFIG`, then
`./.stozher-gateway.toml`, then `${XDG_CONFIG_HOME:-~/.config}/stozher/gateway.toml`. See
`stozher-gateway.example.toml`.

Environment variables are all `STOZHER_*`, never `HARBORMASTER_*`:

| Variable | Meaning |
|---|---|
| `STOZHER_GATEWAY_CONFIG` | configuration file |
| `STOZHER_GATEWAY_DB` | local durable chain + parked requests (default `~/.stozher/gateway.db`) |
| `STOZHER_GATEWAY_SEED` | the SLIP-0010 seed every subject key is derived from, mode 0600 |
| `STOZHER_GATEWAY_CALLER` | which configured caller this connection is |
| `STOZHER_GATEWAY_CALLER_TOKEN` | that caller's bearer credential |
| `STOZHER_KERNEL_TOKEN` | the kernel bearer token (name it in `[kernel] token_env`) |

## Operator commands

```
stozher-gateway config check            # actionable findings, exit 1 if any
stozher-gateway catalog policy-fragment # the by-action map to publish in org policy
stozher-gateway pending                 # parked requests awaiting a human
stozher-gateway approve --request <hash> --key <seed> --subject human:ivan [--classify read]
stozher-gateway deny    --request <hash> --key <seed> --subject human:ivan --reason "..."
stozher-gateway keygen  --out keys/gateway.seed
```

`approve` is not a bypass. It builds a `gate-decision` object and signs it with a named human's key;
the gateway then runs all eleven steps of `spec/06` §2 over it before forwarding anything. S4
replaces the *transport* (a kernel-native pending queue and notification path), not the
cryptography.

## Classification, and the one thing to know about it

Order is Tier A manifest → Tier B shipped catalog → Tier B′ org-seeded → Tier C heuristic, with org
policy reclassification on top (`spec/10` §3).

**The kernel cannot see the gateway's catalog.** It evaluates `spec/05` §3 with the org policy and
the emitting component's manifest, so a catalog class only becomes authoritative once the
organization publishes it. Until then the gateway takes the *stronger* of (catalog class,
`default-unknown`) so the two evaluations always agree — which means an uncatalogued `read` is
treated as `consequential` and gated. `stozher-gateway catalog policy-fragment` prints exactly what
to publish to fix that, for the servers this deployment fronts.

## Running the tests

```
uv venv --python 3.11
uv pip install -e '.[dev]'
uv run ruff check src/ tests/
uv run mypy --strict src/stozher_gateway/
uv run pytest tests/ -q
```

`harbormaster` must be importable. The parity and end-to-end tests run against the local checkout
(`~/htdocs/harbormaster`, v27.1.3) rather than the PyPI build, so that the reconnaissance this
implementation was written against and the code under test are the same thing; put its `src/` on the
venv path or install the distribution.

`tests/test_gateway_e2e.py` builds and runs the real kernel binary (`cargo build` in `kernel/`) and
spawns a real `harbormaster-mcp` process driven by a stock `mcp.ClientSession`.

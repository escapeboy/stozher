# ADR-0005: The gateway owns its own config; Harbormaster core stays untouched

**Status:** Accepted · **Date:** 2026-07-26 · **Depends on** ADR-0004 · **Refines** `docs/design/gateway.md`

## Context

ADR-0003 and `docs/design/gateway.md` require that the Stozher enforcement layer ship as
Harbormaster's optional enforcement mode, with a hard constraint:

> Harbormaster remains an independent tool; the Stozher layer ships as its enforcement
> mode/plugin, **so dev users without a kernel lose nothing.**

Reconnaissance of `~/htdocs/harbormaster` @ `4f07955` (v27.1.3) found a mechanism that makes the
obvious reading of that impossible.

**Observed:** `src/harbormaster/config.py:21` defines `_FORBID_EXTRA = ConfigDict(extra="forbid")`
and *every* model applies it — including `HarbormasterConfig` itself (`config.py:449`). Config is
loaded by `load_config()` (`config.py:495-507`) via `HarbormasterConfig.model_validate(data)`.

Verified empirically by the recon agent: a `config.toml` containing only

```toml
[enforcement]
enabled = true
```

fails validation with `enforcement — Extra inputs are not permitted [type=extra_forbidden]`.

**Consequence:** if the gateway expects operators to add an `[enforcement]` section to
`harbormaster.toml`, then any Harbormaster that does *not* carry a matching `EnforcementConfig`
field in core `config.py` **fails to boot entirely**. Uninstall the plugin, downgrade
Harbormaster, or hand the config to a colleague running vanilla v27.1.3 — the tool dies at
startup. That is not "loses nothing"; it is strictly worse than not shipping at all.

The two available options were:

**(a) Land `EnforcementConfig` in core `src/harbormaster/config.py`.** Requires patching
Harbormaster's own surface, and drags in four coupled gates that all fail the build otherwise:
`scripts/check_config_doc_parity.py` (pre-commit), `tests/unit/test_config_doc_reference.py`
(two separate tests), and `harbormaster-mcp config check` against `examples/harbormaster.toml`.
Every new field must be documented in `docs/operator-config-reference.md` in the same commit.
It also contradicts ADR-0004's "No fork, no patch of Harbormaster's own surface."

**(b) The gateway never reads `harbormaster.toml`.** It owns its own config file and env vars.

## Decision

**Option (b). The gateway reads its configuration exclusively from its own sources, never from
`harbormaster.toml`.**

1. **Config file:** `stozher-gateway.toml`, resolved in this order — `--config` flag, then
   `$STOZHER_GATEWAY_CONFIG`, then `./.stozher-gateway.toml`, then
   `${XDG_CONFIG_HOME:-~/.config}/stozher/gateway.toml`. First match wins, mirroring
   Harbormaster's own `_config_search_paths()` semantics (`config.py:487-492`) so operators meet
   one convention, not two.
2. **No new section in `harbormaster.toml`. No field added to `HarbormasterConfig`. No file in
   `src/harbormaster/` modified.** Harbormaster core is read-only to this project.
3. **Plugin activation uses Harbormaster's existing, already-declared config only** — the
   `[plugins]` section that ships in v27.1.3 today:
   ```toml
   [plugins]
   enabled = true
   allow = ["stozher-gateway"]
   ```
   These keys already exist (`PluginsConfig`, `config.py:258-266`), so a config that enables the
   gateway remains valid input to vanilla Harbormaster. An operator who uninstalls the gateway
   distribution sees the allowlist entry warned about and skipped (`plugins.py:153-161`) — a
   `WARNING` line, not a boot failure.
4. **Env vars are prefixed `STOZHER_*`**, never `HARBORMASTER_*`, to guarantee no collision with
   the nine `HARBORMASTER_*` vars in use. Secrets are referenced by env-var *name* in config
   (`..._env` field convention, per `FleetQConfig.api_token_env`, `config.py:141`), never inlined.

## Why this is better, not merely cheaper

- **"Loses nothing" becomes true by construction rather than by discipline.** There is no config
  state in which vanilla Harbormaster rejects a file the gateway produced. This is testable, and
  S2 must carry a test asserting that a gateway-enabled config still validates under
  `HarbormasterConfig`.
- **Separation of ownership matches separation of product.** Harbormaster is MIT and independent;
  Stozher is PRICEX proprietary (per build plan IP note). Not interleaving their config surfaces
  keeps that boundary clean at the file level, which matters for the licensing decision that is
  still open.
- **No inherited gate obligations.** We do not take on doc-parity coupling for a config surface we
  do not own.

## Consequences

- Operators configure two files when running enforcement. Accepted cost; the alternative is a
  boot-failure footgun. The gateway's `config check` subcommand must therefore be good, and must
  report actionable findings (kernel unreachable, token env unset) in the style of
  `config_cli.py:75-178`.
- Because the gateway can't read `harbormaster.toml`, it cannot auto-derive downstream MCP servers
  from Harbormaster's own settings. Downstream servers are declared explicitly in
  `stozher-gateway.toml`. This is desirable anyway — an audit boundary should be declared, not
  inferred.

## Related

ADR-0004 · `docs/design/gateway.md` · `docs/gateway-integration-constraints.md` (the full recon
brief, including the async/threading and stdio constraints that shape the proxy implementation)

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
| `STOZHER_GATEWAY_BUNDLE` | a root-signed policy bundle to bootstrap from with no kernel reachable |
| `STOZHER_KERNEL_TOKEN` | the kernel bearer token (name it in `[kernel] token_env`) |

**`[gateway] enabled` is honoured by both entry points, and differently.** The MCP plugin registers
nothing when it is false — a Harbormaster with the distribution installed but enforcement off is
exactly vanilla Harbormaster. A `Governor` **refuses to be built**, because on that path "off" has no
safe meaning: the caller has already wrapped functions that apply effects, so the only other reading
is "call them ungoverned", which is a gate disabled by editing a config key. It used to be read by
`plugin.register` alone, and a `Governor` built from `enabled = false` opened a session and gated
every call anyway.

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

## Running an agent suite in CI, with no kernel

A fresh container has never reached a kernel, so it has no verified policy, and until v0.10 that
meant it could not open a session at all — `policy-not-published`, raised inside `Governor.__enter__`
before a single call was classified. The offline profile (`spec/05` §7) was implemented and worked;
what was missing was a way *in* from cold. That is what a **policy bundle** is.

**1. Export a bundle, once, wherever the kernel is.** Offline, on the operator's own machine, with
the root key that machine already holds:

```sh
stozher-kernel anchor --url https://kernel.example --token-env STOZHER_KERNEL_TOKEN > anchor.json

# --policy is genesis's `policy-document.json`, or whatever `policy-sign --out` last wrote: the
# document actually in force, signature intact, never a stripped draft.
# --revocations is optional and takes a JSON array of what `revoke` printed. Omitted, the bundle
# carries an explicit empty set — "nothing is revoked" signed by a root, not a member left out.
stozher-kernel policy export-bundle \
    --policy  out/policy-document.json \
    --anchor  anchor.json \
    --key     keys/root.seed --role 0 \
    --max-age P7D \
    --out     ci/policy-bundle.json
```

The bundle is one signed object carrying the policy, the revocation set and the anchor. `--max-age`
is **inside** the signature, so nobody downstream can extend it, and a component whose bundle has
expired refuses to start rather than warning. Commit `ci/policy-bundle.json` — it holds no secret,
only public documents and a root's signature over them — and re-export it before it expires.

**2. Point the container at it.** Either `[gateway] policy_bundle = "ci/policy-bundle.json"` or:

```sh
export STOZHER_GATEWAY_BUNDLE=ci/policy-bundle.json
```

The gateway verifies it against `[org] roots` before a byte reaches the cache, then enforces the
policy and the revocations offline. `read` and `benign` proceed and queue their envelopes locally;
`consequential` is refused — parked while the seeded policy is inside `max-staleness-seconds`,
`policy-stale-offline` after that. Either way the body does not run.

**3. A `consequential` call under test needs a fixture-signed approval, not an offline mode.**
`spec/05` §7 is explicit: an action requiring a human signature cannot acquire one offline. So no
bundle, no flag and no mode will make such a call succeed in CI. What makes it succeed is a signature
— from a **fixture root** enrolled in that deployment's `[org] roots` and existing nowhere else:

```sh
stozher-gateway keygen --out ci/fixture-root.seed   # enrol its key id under [[org.roots]]
# the suite runs; the call parks
stozher-gateway pending
stozher-gateway approve --request <hash> --key ci/fixture-root.seed --subject human:ci-fixture
# re-run the call: the gate finds the decision and forwards
```

Two passes, not one, and that is not an accident: the approval names the request's hash, which
carries a fresh nonce per park (`spec/06` §1.1), so it cannot be signed before the call exists. The
decision is **single-use** (`spec/06` §1.2), so each governed consequential call under test needs its
own. A suite that wants many of them is better served by classifying those actions in the policy the
bundle carries — which is the organization saying, in a document a human signed, that they do not
need a gate.

**What CI must not do** is enrol its fixture root in the production `[org] roots`. The fixture key
signs approvals that are valid for any deployment that trusts it, and a key that lives in a CI runner
is a key that lives wherever the runner's logs and images go.

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

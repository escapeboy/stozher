<!-- MIRROR of Svod note `projects/stozher/docs/design/extension-contract.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Extension contract — how the platform grows

New capability = MCP server + **Stozher manifest** + green conformance run. Everything that fulfills the contract plugs in: Greda tomorrow, a foreign connector the day after, a foundry-synthesized tool the same hour it's promoted.

## Manifest (draft fields → schema in spec S0)

- `name`, `version`, `subject-class` (what kind of agent/tool this is)
- `actions[]`: action type → weight class (`read|benign|consequential|prohibited`) — the component's proposed baseline; org policy may reclassify, never the reverse silently
- `evidence-schema` per action type (what the envelope's evidence field contains; enables typed audit queries)
- `budget-dimensions` (tokens, requests, money, wall-clock)
- optional `durable-objects[]`: object type + transition table + who-may-sign-which-transition (Servanda edge model generalized; foundry tools declare synthesize→verify→promote here)

## Conformance harness

Foundry's `verify` pattern, generalized:
- Deterministic self-test: emit sample envelopes for every declared action type → kernel validates schema, signatures, mandate handling, aggregation behavior for `read` class.
- Durable-object declarations: replay a transition sequence → kernel checks fold correctness and signature authority per transition.
- **No green run, no registration.** Foundry-synthesized tools pass the identical path — self-growth with a governed perimeter, by construction.

## Why this falls out of ADR-0001 rather than being designed separately

The primitive says: effects are signed events; durable things are folds. The manifest is exactly "declare your effects and your folds." If a capability cannot express itself in the manifest, that's the earliest possible signal it doesn't belong in the system — or (empirical question #2) that the taxonomy needs a fifth class. Either answer is cheap at manifest time and ruinous at production time.

# 08 — Extension manifest & conformance harness

Normative. New capability = MCP server + Stozher manifest + green conformance run. The manifest is
exactly "declare your effects and your folds" — it falls out of the primitive rather than being
designed separately (extension-contract design doc).

## 1. Manifest object

A manifest is a signed object (§01 §5), signed by the component's own key, submitted at registration.

```json
{
  "v": "stozher/0.1",
  "kind": "manifest",
  "name": "github",
  "version": "1.4.0",
  "subject-class": "tool-proxy",
  "description": "GitHub REST/GraphQL operations proxied through the gateway",
  "actions": [
    {
      "action": "github.get_file",
      "class": "read",
      "evidence-schema": "github.get_file.v1",
      "aggregate": { "sampling": "first-and-last", "max-samples": 8 },
      "idempotent": true,
      "target-kind": "repo-path"
    },
    {
      "action": "github.create_issue",
      "class": "consequential",
      "evidence-schema": "github.create_issue.v1",
      "idempotent": false,
      "target-kind": "repo",
      "degrade": null
    },
    {
      "action": "github.delete_repo",
      "class": "prohibited",
      "evidence-schema": "github.delete_repo.v1",
      "idempotent": false,
      "target-kind": "repo"
    }
  ],
  "evidence-schemas": {
    "github.create_issue.v1": {
      "type": "object",
      "required": ["title", "body-length", "labels"],
      "properties": {
        "title":       { "type": "string" },
        "body-length": { "type": "integer" },
        "labels":      { "type": "array", "items": { "type": "string" } }
      },
      "additionalProperties": false
    }
  },
  "budget-dimensions": ["requests", "wall-clock-seconds"],
  "durable-objects": [],
  "conformance": { "self-test": "github.selftest", "vectors-version": "stozher/0.1" },
  "sig": { "alg": "ed25519", "key": "ed25519:<component key>", "value": "…" }
}
```

### 1.1 Members

| Member | Required | Notes |
|---|---|---|
| `name` | MUST | organization-unique component name, `^[a-z][a-z0-9-]{1,31}$` |
| `version` | MUST | semver of the component |
| `subject-class` | MUST | `tool-proxy` \| `browser-agent` \| `executor` \| `memory` \| `orchestrator-bridge` \| `kernel` |
| `actions[]` | MUST | non-empty; §1.2 |
| `evidence-schemas` | MUST | map schema-id → JSON Schema (draft 2020-12) with `additionalProperties: false` |
| `budget-dimensions[]` | MUST | subset of the dimension names in §03 §4.3 |
| `durable-objects[]` | MUST (may be empty) | §2 |
| `conformance` | MUST | §4 |
| `sig` | MUST | component key |

### 1.2 Action declarations

- `action` (MUST): `^<name>\.[a-z][a-z0-9_]{0,63}$` where `<name>` is the manifest's `name`. A
  component MUST NOT declare actions in another component's namespace
  (`manifest-action-namespace`).
- `class` (MUST): the component's **proposed baseline** class. Org policy may reclassify in either
  direction (§05 §3). A component MUST NOT apply a class weaker than the effective policy's
  (`policy-component-override-attempt`); the manifest is a proposal, not a claim of authority.
- `evidence-schema` (MUST): a key of `evidence-schemas`. Every declared action MUST have one
  (`manifest-evidence-schema-missing`), so every audit record is typed and queryable.
- `aggregate` (MUST for `class: "read"`, MUST NOT otherwise): the sampling rule and
  `max-samples` (≤ 16) used to build aggregation records (§02 §7). Declaring the rule up front is
  what makes an aggregate auditable.
- `idempotent` (MUST): whether re-applying the action is safe. Governs retry after an approved-but-
  failed application (§06 §3).
- `target-kind` (MUST): the namespace of `execution.target` values.
- `degrade` (MAY): declaration of the reduced form used when policy says `degrade` offline (§05 §7).
  `null` means the action has no reduced form and MUST be blocked instead.
- No action may declare `class: "prohibited"` and a `degrade` form simultaneously
  (`manifest-prohibited-degrade`).

## 2. Durable objects

```json
"durable-objects": [
  {
    "object-type": "foundry.tool",
    "id-kind": "tool-name",
    "transitions": [
      { "transition": "synthesized", "from": [],              "to": "provisional", "signers": ["agent"] },
      { "transition": "verified",    "from": ["provisional"], "to": "verified",    "signers": ["agent"] },
      { "transition": "promoted",    "from": ["verified"],    "to": "active",      "signers": ["human"] },
      { "transition": "revoked",     "from": ["active","verified","provisional"], "to": "revoked", "signers": ["human"] }
    ]
  }
]
```

- `transitions[]` is the transition table; `from: []` marks creation transitions.
- `signers` (MUST) is a non-empty subset of `["human","agent"]` and states *who may sign that
  transition*. A transition whose `signers` is `["human"]` MUST NOT be accepted from an agent key
  (`durable-transition-not-permitted`), regardless of the agent's mandate — this is how "promotion
  requires a person" becomes structural rather than procedural.
- The object's state is the fold of its transition envelopes in chain order (§02 §8); a transition
  whose `from` does not contain the current folded state MUST be rejected
  (`durable-transition-illegal`).
- `durable-objects` MAY be empty. Most components have none.

## 3. Registration

1. Registration is an effect: `kind: "effect"`, `action: "kernel.register_component"`, classification
   `consequential`, gated (§06). A component cannot register itself into the system without a human
   signature over the exact manifest hash (`execution.args-hash` = `object-hash(manifest)`).
2. The kernel MUST reject a manifest that fails schema validation, declares actions outside its
   namespace, omits an evidence schema, or reuses a `name` bound to a different key
   (`manifest-name-key-conflict`).
3. **No green conformance run, no registration** (`manifest-conformance-not-green`). Foundry-
   synthesized tools pass the identical path; self-growth with a governed perimeter is achieved by
   there being exactly one door.
4. A manifest version bump follows the same path. Adding an action, or weakening a class, requires a
   fresh human signature. Removing an action does not invalidate historical envelopes citing it.
5. The kernel MUST retain every registered manifest version forever: an envelope from 2027 citing
   `github.create_issue` must remain interpretable in 2032 (`manifest-version-retained`).

## 4. Conformance harness requirements

The harness is the foundry `verify` pattern generalized. A component's conformance run MUST be
deterministic and MUST be re-runnable by the kernel operator with no component-side state.

The harness MUST verify, for the component under test:

1. **Vectors.** The component reproduces every expected value in `spec/vectors/` for the primitives it
   uses (canonicalization, hashing, signing, envelope hashing, chain construction). A component that
   cannot canonicalize identically cannot be audited identically.
2. **Per-action emission.** For every declared action type, the component emits a sample envelope that
   passes ingest: valid signature, resolvable mandate, declared `evidence-schema` satisfied by the
   sample payload, `payload-hash` matching, `classification` equal to the effective policy's class.
3. **Aggregation.** For every `read` action, driving N > `max-samples` calls produces aggregation
   records that satisfy §02 §7 (count arithmetic, sample bounds, window bound, single identity /
   mandate / policy-version).
4. **Negative cases — these MUST fail, and the harness MUST fail the component if they succeed:**
   - a gated action applied with no `authorization` → rejected `gate-authorization-missing`;
   - a gated action applied with an `authorization` whose `request` names a different `target` or
     `args-hash` → rejected `gate-authorization-action-mismatch`;
   - the same `authorization` submitted twice → second rejected `gate-authorization-replayed`;
   - an envelope under an expired mandate → rejected `mandate-expired`;
   - an envelope under a delegated chain not terminating at a human root → rejected
     `mandate-root-grantor-not-human` or `mandate-delegation-depth-exceeded`;
   - a `prohibited` action → not applied, and emitted with `outcome: "attempted"`;
   - a `cognition` envelope carrying `evidence` → rejected `cognition-envelope-has-effect-fields`;
   - **an attempt to append a gated envelope through any administrative or internal path without
     `authorization`** → rejected. The harness MUST attempt this explicitly (§06 §2).
5. **Offline behaviour.** With the kernel unreachable: cached policy is enforced, envelopes queue
   locally and chain locally, `consequential` under a gate rule is blocked (not applied), and on
   reconnect the queued chain is accepted without renumbering (§04 §3).
6. **Durable objects** (if declared): replaying a transition sequence folds to the expected state; an
   illegal transition is rejected; a `human`-only transition signed by an agent key is rejected.
7. **Decay independence.** After deleting every payload the component's sample envelopes referenced,
   chain verification still succeeds and produces the same head hash (§04 §5.1).

The harness MUST emit its result as an envelope (`action: "kernel.conformance_run"`, evidence = the
full result), so "it passed conformance" is itself an audited claim with a date and a manifest hash,
not a sentence in a README.

## 5. Classification catalog entries (Tier B)

For foreign MCP servers with no manifest, the shipped catalog (§10 §3) uses a reduced entry:

```json
{ "server": "github-mcp", "tool": "create_issue", "action": "github.create_issue",
  "class": "consequential", "curated-at": "2026-07-20", "source": "vendor-docs" }
```

Catalog entries are versioned with the product and MUST be signed by the vendor's (our) release key.
An org-local entry created by first-call gating (§10 §4) MUST be distinguishable from a shipped one
(`origin: "org-seeded"` vs `"shipped"`), because a class chosen once by a hurried approver at 18:40 on
a Friday deserves less trust than a curated one, and an auditor is entitled to see which is which.

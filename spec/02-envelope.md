# 02 — Envelope

Normative. The envelope is the unit of the system: *every effect is a signed event under a
traceable mandate.* Everything else in Stozher is an emitter of envelopes, a validator of
envelopes, or a fold of envelopes.

## 1. Common structure

An envelope is a signed object (§01 §5). Top-level members:

| Member | Type | Required | Notes |
|---|---|---|---|
| `v` | string | MUST | exactly `"stozher/0.1"` |
| `kind` | string | MUST | see §2 |
| `emitted-at` | timestamp | MUST | when the emitter sealed the envelope |
| `stream` | string | MUST | append-only chain this envelope belongs to (§04) |
| `seq` | integer ≥ 0 | MUST | position in `stream`, strictly increasing by 1 |
| `prev-hash` | string \| null | MUST | `null` iff `seq == 0`, else `id()` of `seq - 1` (§04) |
| `identity` | object | MUST | §3 |
| `mandate-ref` | string(64 hex) | MUST for effect kinds | `id()` of the governing mandate (§03) |
| `policy-version` | string | MUST for effect kinds | which policy governed this effect (§05) |
| `classification` | string | see §2 | one of `read`, `benign`, `consequential`, `prohibited` |
| `execution` | object | see §2 | §4 |
| `evidence` | object | MAY | §5 — never contains the payload itself |
| `authorization` | object | conditional | §06; MUST be present when a gate rule applies |
| `trigger` | object | MAY | §07 §4 — links an effect to the signal that triggered it |
| `resource` | object | see §2 | §6 — cognition only |
| `cost` | object | see §2 | §6 — cognition only |
| `window`, `counts`, `sample-hashes` | see §7 | see §2 | aggregation record only |
| `memory-ref` | string | MAY | Svod note reference (opaque to the kernel beyond storage) |
| `commitment-ref` | object | MAY | durable-object reference, §8 |
| `correlation-ref` | string | MAY | §10 — **stored and indexed, never interpreted** |
| `sig` | object | MUST | §01 §5 |

The **envelope hash** is `id(envelope)` = `object-hash` over the complete signed envelope (§01 §5).
It is the value referenced by `prev-hash`, by checkpoints, and by every audit citation.

Members not listed above MUST be rejected at ingest with `schema-unknown-member` (§9).

## 2. Envelope kinds

| `kind` | Meaning | `classification` | `execution` | Extra required |
|---|---|---|---|---|
| `effect` | an effect was applied to the world | MUST | MUST | — |
| `cognition` | resource was consumed with no external effect | MUST NOT | MUST NOT | `resource`, `cost` |
| `aggregate` | folded record for mass `read` (§7) | MUST be `read` | MUST NOT | `window`, `counts` |
| `mandate` | a mandate was granted (§03) | MUST NOT | MUST NOT | `mandate` |
| `revocation` | a mandate was revoked (§03 §7) | MUST NOT | MUST NOT | `revokes` |
| `policy-change` | a policy version was published (§05 §5) | MUST be `consequential` | MUST | `authorization` |
| `gate-decision` | an approval or denial was recorded (§06 §5) | MUST NOT | MUST NOT | `decision-of` |
| `signal` | an inbound signal was received (§07) | MUST NOT | MUST NOT | `signal` |
| `checkpoint` | signed chain checkpoint (§04 §4) | MUST NOT | MUST NOT | `checkpoint` |

An unknown `kind` MUST be rejected (`envelope-unknown-kind`). "Effect kinds" in this document means
`effect`, `policy-change`, and `aggregate`.

Rationale for `mandate`, `revocation`, `policy-change`, `gate-decision` and `checkpoint` being
envelope kinds rather than side tables: everything that changes what the system will permit is
itself an audited, chained, signed event. There is no privileged channel through which authority
changes silently.

## 3. `identity`

```json
{
  "subject":   "agent:claude-code/ivan-mbp",
  "key":       "ed25519:<64 hex>",
  "component": "gateway"
}
```

- `subject` (MUST): stable organization-local identifier of the acting subject. Format
  `<class>:<name>` where `class` is `human` or `agent`. It is a label for humans reading the audit;
  authority derives from `key` and the mandate chain, never from this string.
- `key` (MUST): the key identifier that signed this envelope. MUST equal `sig.key`
  (`identity-key-sig-mismatch`).
- `component` (MUST): the component that emitted the envelope (`lattice`, `boruna`, `gateway`,
  `kernel`, or a registered extension name, §08).

There is deliberately **no** `on-behalf-of` member. "On whose behalf" has exactly one answer and it
is computed, not asserted: walk the mandate chain to its human root (§03 §5). A denormalized copy
would be a second source of truth for the only question the product exists to answer.

Exactly one subject signs any one envelope. There is no multi-subject envelope and no collective
author (maxim 3).

## 4. `execution`

```json
{
  "action":      "github.create_issue",
  "target":      "repo:acme/backend",
  "args-hash":   "<64 hex>",
  "outcome":     "applied",
  "started-at":  "2026-07-26T09:15:00.000Z",
  "finished-at": "2026-07-26T09:15:01.250Z"
}
```

- `action` (MUST): the component-declared action type. For manifested components it MUST be one of
  the action types in the manifest (§08). Format `<component-scope>.<action>`.
- `target` (MUST): identifier of the thing acted upon, in the emitting component's namespace.
  `"-"` if the action has no target.
- `args-hash` (MUST): `object-hash` of the canonical arguments object of the call. Arguments
  themselves are evidence payload (§5), not envelope content — they may be large and may contain
  personal data, and both are reasons they must be able to decay (§04 §5). The hash is what the
  approval signature binds to (§06 §2), so it is mandatory even when the payload is never stored.
- `outcome` (MUST): one of `applied`, `failed`, `denied`, `blocked`, `attempted`.
  `denied` = a gate denied it; `blocked` = policy or an expired/absent mandate stopped it;
  `attempted` = a `prohibited`-class action was tried. An emitter MUST emit an envelope for
  `denied`, `blocked` and `attempted` outcomes: refusals are the most audit-valuable records in the
  system, and an audit that only records successes is an advertisement, not an audit.
- `started-at`, `finished-at` (MUST): `finished-at` MUST NOT precede `started-at`
  (`execution-time-inverted`).

## 5. `evidence`

```json
{
  "schema":       "github.create_issue.v1",
  "media-type":   "application/json",
  "payload-hash": "<64 hex>",
  "retain-until": "2027-07-26T00:00:00.000Z"
}
```

**The envelope never contains the payload.** This is the structural core of the GDPR answer
(§04 §5): the signed bytes commit to a hash, so deleting the payload cannot alter, and cannot be
detected by, the chain.

- `schema` (MUST): identifier of the evidence schema, declared per action type in the component
  manifest (§08). Enables typed audit queries.
- `media-type` (MUST): `application/json` (payload is a JSON value; `payload-hash` =
  `object-hash(payload)`), or any other IANA media type (payload is an octet string;
  `payload-hash` = hex(SHA-256(bytes))).
- `payload-hash` (MUST): 64 hex. If a component genuinely has no evidence for an action, it MUST
  omit `evidence` entirely rather than hash an empty object.
- `retain-until` (MUST): the deletion deadline the emitter computed from the policy TTL for this
  classification (§05 §4). The kernel re-derives it from its own policy and MUST reject an
  envelope whose `retain-until` exceeds the policy maximum for its class
  (`evidence-retention-too-long`) — an emitter cannot buy itself a longer retention than the org
  allows.

Payload transport and the payload store are specified in §04 §5.

## 6. Cognition envelope (the minimal envelope)

Cognition is unaccountable by design: Stozher audits effects, not thoughts. But budget is an
organizational resource, so consumption is recorded — content is not.

```json
{
  "v": "stozher/0.1", "kind": "cognition",
  "emitted-at": "...", "stream": "...", "seq": 7, "prev-hash": "...",
  "identity": { "subject": "agent:planner", "key": "ed25519:...", "component": "boruna" },
  "mandate-ref": "<64 hex>",
  "resource": { "kind": "model", "name": "claude-opus-5" },
  "cost":     { "tokens-in": 18422, "tokens-out": 1200, "money-eur": "0.41", "wall-clock-ms": 9310 },
  "sig": { ... }
}
```

- A `cognition` envelope MUST NOT contain `execution`, `evidence`, `classification`,
  `authorization` or `commitment-ref` (`cognition-envelope-has-effect-fields`). There is no field
  in which a prompt, a completion, a summary of reasoning, or a tool argument could be recorded.
  This is not an oversight to be fixed by an extension: an implementation that adds one is
  non-conformant.
- `mandate-ref` is REQUIRED — spend is attributed to a mandate so budgets are enforceable (§03 §4).
- `cost` members MUST be integers, except monetary members which MUST be decimal strings (§01 §2.5).
- The moment reasoning materializes — a memory write, a message, a tool call — that is an `effect`
  envelope, fully classified and fully evidenced. The boundary is materialization, not intent.

## 7. Aggregation record (class `read`)

Mass reads are folded **at the emitter** into aggregation records. The kernel never receives the
firehose; a fleet browsing session or a repository scan must not be able to bury the two
consequential actions of the day under fifty thousand `read` envelopes.

```json
{
  "v": "stozher/0.1", "kind": "aggregate", "classification": "read",
  "emitted-at": "...", "stream": "...", "seq": 108, "prev-hash": "...",
  "identity": { "subject": "agent:claude-code/ivan-mbp", "key": "ed25519:...", "component": "gateway" },
  "mandate-ref": "<64 hex>", "policy-version": "2026.07.1",
  "window": { "from": "2026-07-26T09:00:00.000Z", "to": "2026-07-26T09:05:00.000Z" },
  "counts": { "total": 412, "by-action": { "github.get_file": 380, "github.list_issues": 32 } },
  "sample-hashes": [ "<64 hex>", "<64 hex>" ],
  "sig": { ... }
}
```

Rules:

1. `classification` MUST be `read`. Only class `read` may be aggregated
   (`aggregate-class-not-read`). An emitter MUST NOT aggregate `benign`, MUST NOT aggregate
   `consequential`, and MUST NOT aggregate `prohibited` — attempts are precisely what must stay
   itemized.
2. All aggregated actions MUST share one `identity`, one `mandate-ref` and one `policy-version`.
   If any of them changes, the window MUST be closed and a new record started.
3. `counts.total` MUST equal the sum of `counts.by-action` values (`aggregate-count-mismatch`).
4. `sample-hashes` MUST contain the `args-hash` of at least one and at most 16 sampled calls from
   the window; the sampling rule MUST be declared in the manifest. Samples let an auditor spot-check
   that the aggregate describes what it claims.
5. A window MUST be closed and emitted within the policy's `aggregate-max-window` (default 5
   minutes) even if the count is small: an aggregate that is still open is an effect that is not
   yet in the audit.
6. Aggregation MUST NOT be used to hide an exfiltration: policy MAY reclassify a read action as
   `consequential` (bulk export, credential read), and a `consequential` action is never
   aggregated. See §09 for what this does and does not defend against.

## 8. Durable objects and folds (`commitment-ref`)

Two-layer ontology (maxim 9, ADR-0001 case 3), the git model: **envelopes are the log; durable
objects are refs folded from transition envelopes.**

```json
"commitment-ref": { "object-type": "servanda.commitment", "object-id": "<opaque>", "transition": "accepted" }
```

- `object-type` MUST be a durable-object type declared in a registered manifest (§08).
- `transition` MUST be a transition declared for that type, and the emitting subject MUST be
  permitted to sign it by the manifest's transition table (`durable-transition-not-permitted`).
- The current state of a durable object is **defined** as the fold of its transition envelopes in
  chain order. An implementation MUST NOT accept a state assertion that is not derivable from
  envelopes: there is no "current state" table that can be written directly. A materialized
  projection is a cache and MUST be rebuildable from the log alone.

## 9. Strictness and unknown members

1. Ingest MUST reject an envelope containing an unknown top-level member
   (`schema-unknown-member`), an unknown member inside `identity`, `execution`, `evidence`,
   `authorization`, `sig`, `resource`, `cost`, `window` or `counts`, or a member of the wrong JSON
   type (`schema-type-mismatch`).

### 9.1 Structural error codes

Normative codes for structural validation, in addition to the encoding codes of §01 §2:

| Code | Condition |
|---|---|
| `envelope-version-unsupported` | `v` is not `"stozher/0.1"` |
| `envelope-unknown-kind` | `kind` is not one of §2 |
| `envelope-classification-unknown` | `classification` is not one of the four classes |
| `envelope-outcome-unknown` | `execution.outcome` is not one of the five outcomes (§4) |
| `schema-unknown-member` | a member not defined for this `kind`, at any of the levels listed above |
| `schema-missing-member` | a REQUIRED member is absent |
| `schema-type-mismatch` | a member has the wrong JSON type |
| `identity-key-sig-mismatch` | `identity.key` ≠ `sig.key` |
| `execution-time-inverted` | `finished-at` precedes `started-at` |
| `correlation-ref-too-long` | `correlation-ref` exceeds 512 octets |
| `cognition-envelope-has-effect-fields` | a `cognition` envelope carries `execution`, `evidence`, `classification`, `authorization` or `commitment-ref` |
| `signal-envelope-has-effect-fields` | a `signal` envelope carries `mandate-ref`, `classification`, `execution`, `evidence`, `authorization` or `commitment-ref` |
| `aggregate-class-not-read` | an `aggregate` envelope whose `classification` is not `read` |
| `aggregate-count-mismatch` | `counts.total` ≠ sum of `counts.by-action` |
| `aggregate-sample-bounds` | `sample-hashes` is empty or holds more than 16 entries |
| `encoding-integer-out-of-range` | an integer outside [-(2^53 - 1), 2^53 - 1] (§01 §2.5) |
| `chain-genesis-prev-not-null` | `seq` is 0 and `prev-hash` is not `null` |
| `chain-prev-hash-missing` | `seq` > 0 and `prev-hash` is `null` |
2. Verification of `sig` nevertheless canonicalizes the object **as received** (§01 §5.6). Order of
   operations at ingest MUST be: parse strictly → verify signature over received bytes → validate
   schema → validate mandate → validate authorization → append. A schema check that runs before
   signature verification lets an attacker probe schemas with unsigned objects; a schema check that
   runs after append lets junk into the chain.
3. Rejections MUST themselves be recorded (§04 §7), with the rejection reason code and the hash of
   the rejected bytes. A rejected envelope MUST NOT be appended to any subject chain.

## 10. `correlation-ref` — stored, indexed, never interpreted

Stozher is orchestrator-agnostic. `correlation-ref` is the entire integration surface for external
orchestrators (Temporal, LangGraph, Airflow, cron, a shell script, FleetQ workflows).

```json
"correlation-ref": "temporal:wf/imports-2026-07/run/9f2c/step/3"
```

Normative:

1. `correlation-ref` MUST be treated as an **opaque string**. Length MUST be ≤ 512 octets
   (`correlation-ref-too-long`); content is otherwise unconstrained.
2. The kernel MUST store it verbatim and MUST index it for exact-match and prefix queries — an
   auditor must be able to ask "show me every effect of workflow run 9f2c".
3. The kernel MUST NOT parse it, split it, resolve it, dereference it (never as a URL), or attach
   meaning to any part of it.
4. `correlation-ref` MUST NOT be an input to: classification, mandate verification, gate decisions,
   retention, budget accounting, or any other decision. An implementation in which a
   `correlation-ref` value can change what is permitted is non-conformant — that would be exactly
   the ambient side channel §00 §4 forbids, wearing a different hat.
5. It carries no authority. A `correlation-ref` naming a workflow that "was approved" means nothing;
   see §06.
6. It is not trusted for grouping in enforcement, only for display and query. Two envelopes sharing
   a `correlation-ref` are two independent effects, each with its own mandate and its own gate
   outcome.

## 11. Worked example (effect, gated)

```json
{
  "v": "stozher/0.1",
  "kind": "effect",
  "emitted-at": "2026-07-26T09:15:01.300Z",
  "stream": "gw:ivan-mbp:0001",
  "seq": 12,
  "prev-hash": "3b1f...",
  "identity": { "subject": "agent:claude-code/ivan-mbp", "key": "ed25519:aa..", "component": "gateway" },
  "mandate-ref": "7c4e...",
  "policy-version": "2026.07.1",
  "classification": "consequential",
  "execution": {
    "action": "github.create_issue", "target": "repo:acme/backend",
    "args-hash": "91d0...", "outcome": "applied",
    "started-at": "2026-07-26T09:15:00.000Z", "finished-at": "2026-07-26T09:15:01.250Z"
  },
  "evidence": {
    "schema": "github.create_issue.v1", "media-type": "application/json",
    "payload-hash": "5f2a...", "retain-until": "2027-07-26T00:00:00.000Z"
  },
  "authorization": { "request": { ... }, "decision": { ... } },
  "correlation-ref": "claude-code:session/8f31",
  "sig": { "alg": "ed25519", "key": "ed25519:aa..", "value": "…128 hex…" }
}
```

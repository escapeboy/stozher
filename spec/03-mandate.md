# 03 — Mandate objects

Normative. *The mandate chain, or autonomy is unauditable* (maxim 8). A signature proves **who**
acted; a mandate proves **on whose authority**. An agent key with no valid mandate chain signs
nothing the kernel accepts.

## 1. Object

A mandate is a signed object (§01 §5) carried in an envelope of `kind: "mandate"` under the member
`mandate`. Its identifier is:

```
mandate-id = object-hash( the mandate object, including its sig )
```

`mandate-ref` in every envelope (§02) holds a `mandate-id`.

```json
{
  "v": "stozher/0.1",
  "kind": "mandate",
  "mandate-kind": "standing",
  "grantor": { "subject": "human:ivan", "key": "ed25519:<64 hex>", "role": "human" },
  "grantee": { "subject": "agent:nightly-importer", "key": "ed25519:<64 hex>" },
  "issued-at":  "2026-07-26T08:00:00.000Z",
  "not-before": "2026-07-26T08:00:00.000Z",
  "not-after":  "2026-10-24T08:00:00.000Z",
  "parent": null,
  "max-depth": 1,
  "scope": {
    "components": ["gateway"],
    "actions":    ["github.*", "slack.post_message"],
    "classes":    ["read", "benign", "consequential"],
    "resources":  ["repo:acme/backend"]
  },
  "budget": { "requests": 5000, "tokens": 2000000, "money-eur": "25.00", "wall-clock-seconds": 3600 },
  "nonce": "<32 hex>",
  "sig": { "alg": "ed25519", "key": "ed25519:<grantor key>", "value": "<128 hex>" }
}
```

| Member | Required | Notes |
|---|---|---|
| `v`, `kind` | MUST | `kind` = `"mandate"` |
| `mandate-kind` | MUST | `interactive` \| `standing` \| `delegated` |
| `grantor` | MUST | `subject`, `key`, `role` (`human` \| `agent`) |
| `grantee` | MUST | `subject`, `key` |
| `issued-at` | MUST | |
| `not-before` | MUST | MUST NOT precede `issued-at` |
| `not-after` | MUST | **for all three kinds** — see §3 |
| `parent` | MUST | `mandate-id`, or `null` for non-delegated |
| `max-depth` | MUST | integer ≥ 0: further delegated links permitted below this mandate |
| `scope` | MUST | §4 |
| `budget` | MAY | §4.3 |
| `nonce` | MUST | 32 hex, unique per grantor; makes otherwise-identical grants distinct objects |
| `sig` | MUST | MUST be signed by `grantor.key` (`mandate-signer-not-grantor`) |

`grantor.key` MUST NOT equal `grantee.key` (`mandate-self-grant`). Authority is never self-issued.

## 2. Kinds

| Kind | Grantor → grantee | Lifetime | Use |
|---|---|---|---|
| `interactive` | human → agent | dies with the session; `not-after` REQUIRED | "do this now, under my eyes" |
| `standing` | human → agent (a rule) | **mandatory expiry, no exceptions** | scheduled tasks, triggers, autonomy |
| `delegated` | agent → agent | bounded depth, window inside parent's | crew fan-out, sub-tasking |

- `interactive` and `standing` are **root mandates**: `parent` MUST be `null` and `grantor.role`
  MUST be `human` (`mandate-root-grantor-not-human`).
- `delegated`: `parent` MUST NOT be null (`mandate-delegated-without-parent`) and `grantor.role`
  MUST be `agent`.
- An `interactive` mandate SHOULD additionally be bound to a session by including the session
  identifier in `grantee.subject`; the kernel MAY revoke it when the session ends.

## 3. Expiry is mandatory

`not-after` is REQUIRED on every mandate, of every kind (`mandate-missing-expiry`). There is no
representation of a mandate that never expires. An implementation MUST NOT provide one, MUST NOT
treat a distant date as a sentinel with special meaning, and MUST NOT accept `null`.

Additionally:

- `not-after` MUST be strictly after `not-before` (`mandate-window-inverted`).
- For `standing`, `not-after - issued-at` MUST NOT exceed the policy's
  `delegation.max-standing-lifetime` (default `P90D`) — `mandate-standing-lifetime-exceeded`.
- The console MUST surface standing mandates approaching expiry; that list is the heartbeat of
  organizational autonomy (design doc: console).

Rationale, recorded so nobody softens it later: an autonomy grant that does not expire is
indistinguishable, six months later, from a compromise nobody noticed.

## 4. Scope

### 4.1 Members

```json
{ "components": ["gateway"], "actions": ["github.*"], "classes": ["read","benign","consequential"], "resources": ["repo:acme/backend"] }
```

All four members are REQUIRED. Each is an array of patterns; an empty array means *nothing is
permitted* (`[]` is a valid, useless mandate — never a wildcard).

Pattern matching is exact string equality, except that a pattern MAY end with `.*` (for `actions`)
or be exactly `"*"`, which matches everything in that dimension. Prefix matching applies to the
dot-separated segments only: `github.*` matches `github.create_issue`, does not match `github`
itself, and does not match `githubx.foo`. No other wildcards, no regular expressions
(`scope-bad-pattern`). Rationale: a scope language that needs a regex engine is a scope language
whose decisions cannot be reviewed by the human signing it.

`classes` MUST be a subset of `["read","benign","consequential","prohibited"]`. Including
`prohibited` in a scope is permitted but never sufficient: a `prohibited` action is hard-blocked by
policy independently of any mandate (§05 §3). A mandate cannot grant what policy forbids.

### 4.2 Request matching

A *request* (the tuple the verifier checks a mandate against) is:

```json
{ "component": "gateway", "action": "github.create_issue", "classification": "consequential", "resource": "repo:acme/backend" }
```

`scope_permits(scope, request)` is true iff `component`, `action`, `classification` and `resource`
each match at least one pattern in the corresponding array. Otherwise
`mandate-scope-not-permitted`.

### 4.3 Budget

`budget` members are OPTIONAL; each present member is a cap on the total consumed under **this
mandate and everything delegated beneath it**. Integer members: `requests`, `tokens`,
`tokens-in`, `tokens-out`, `wall-clock-seconds`. Monetary members MUST be decimal strings and MUST
be named `money-<iso4217 lowercase>` (`money-eur`). A delegated mandate's budget MUST NOT exceed
its parent's for any dimension present in the parent (`mandate-budget-exceeds-parent`).

**Comparison of monetary values.** A monetary value MUST match the grammar

```
money = 1*DIGIT [ "." 1*DIGIT ]
```

and MUST be at most 32 characters. Anything else — a sign, an exponent, surrounding whitespace, a
digit separator, a bare `.5` or `5.`, a non-ASCII digit — MUST be refused
(`schema-type-mismatch`); a budget is a cap on spend, so a negative one is not a narrower budget and
is not given a meaning.

Values MUST be compared **exactly, by value**, and an implementation MUST NOT convert them to a
binary floating-point number to do so. Scale carries no meaning: `"25"`, `"25.0"` and `"025.00"` are
one amount and compare equal. Concretely, compare the integer parts with leading zeros removed —
longer first, then digit by digit — and on equality compare the fractional digits position by
position, treating a missing digit as zero.

*Rationale.* §01 §2.5 places monetary quantities out of the reach of binary64 by making them
strings; parsing them back into a `double` to compare them puts them straight back in, at the one
place that decides whether delegated authority narrows. `9007199254740993` and `9007199254740992`
are one apart and the same binary64, so a child budget one unit above its parent's compares equal.
The grammar is narrow for a second reason: two implementations' number parsers do not accept the
same strings, so an unconstrained one admits a mandate on one side of a deployment that the other
side refuses. Both failures are covered by `spec/vectors/money-compare.json`.

Budget enforcement is the kernel's; accounting inputs are `cost` in cognition envelopes (§02 §6)
and the emitter's declared budget dimensions (§08). Exhausted budget blocks like an expired
mandate: `outcome: "blocked"`, envelope still emitted.

## 5. Verification algorithm

This is the algorithm the phrase "walk the chain to a named human" denotes. It is normative;
implementations MUST produce the same accept/reject decision and the same error code.

**Inputs:** `mandate-ref`, the request tuple (§4.2), the evaluation instant `at` (the envelope's
`emitted-at`), the signing key of the envelope `subject-key`, the organization's `roots` (§6), the
revocation set, and the policy's `delegation.max-depth` (default 3).

```
verify_mandate_chain(mandate-ref, request, at, subject-key, roots, revocations, max_depth):

  m := resolve(mandate-ref)                     ; else mandate-unresolved
  require m.grantee.key == subject-key          ; else mandate-grantee-key-mismatch
  depth := 0

  loop:
    verify_signed_object(m)                     ; else sig-invalid
    require m.sig.key == m.grantor.key           ; else mandate-signer-not-grantor
    require m.grantor.key != m.grantee.key       ; else mandate-self-grant
    require m.not-after present                  ; else mandate-missing-expiry
    require m.not-before <= at <= m.not-after    ; else mandate-expired / mandate-not-yet-valid
    require id(m) not revoked at or before at    ; else mandate-revoked
    require scope_permits(m.scope, request)      ; else mandate-scope-not-permitted

    if m.mandate-kind in { interactive, standing }:
        require m.parent == null                 ; else mandate-root-has-parent
        require m.grantor.role == "human"        ; else mandate-root-grantor-not-human
        require m.grantor.key in roots           ; else mandate-root-not-enrolled
        return ACCEPT { human-root: m.grantor.subject, root-key: m.grantor.key, depth: depth }

    ; m.mandate-kind == delegated
    require m.parent != null                     ; else mandate-delegated-without-parent
    require m.grantor.role == "agent"            ; else mandate-delegated-grantor-not-agent
    p := resolve(m.parent)                       ; else mandate-unresolved
    require m.grantor.key == p.grantee.key       ; else mandate-delegation-not-held
    require p.max-depth >= 1                     ; else mandate-delegation-depth-exceeded
    require m.max-depth <= p.max-depth - 1       ; else mandate-delegation-depth-exceeded
    require scope_subset(m.scope, p.scope)        ; else mandate-scope-widened
    require p.not-before <= m.not-before
        and m.not-after <= p.not-after            ; else mandate-window-outside-parent
    require budget_within(m.budget, p.budget)     ; else mandate-budget-exceeds-parent
    depth := depth + 1
    require depth <= max_depth                    ; else mandate-delegation-depth-exceeded
    m := p
```

Notes:

- **Termination at a human is structural, not conventional.** The loop only returns ACCEPT from the
  `interactive`/`standing` branch, which requires an enrolled human root key. A cycle in `parent`
  links, or a chain that runs out of parents, cannot reach ACCEPT; `max_depth` bounds the walk so a
  malicious cycle terminates with `mandate-delegation-depth-exceeded` rather than looping.
- `scope_subset(child, parent)` is true iff for each dimension, every pattern in the child is
  matched by (i.e. is equal to, or is covered by) at least one pattern in the parent. A child MUST
  NOT introduce a `.*` pattern broader than the parent's, and MUST NOT introduce a class the parent
  lacks. Scope may only narrow along the chain (`mandate-scope-widened`).
- `depth` is the number of delegated links traversed. `max-depth` on each mandate is a hop budget
  that decreases by at least 1 per delegation, making the bound locally checkable at grant time,
  before any effect exists.
- **Every check is on the walk to the root, not only on the leaf.** An expired or revoked mandate
  anywhere in the chain invalidates every mandate beneath it, retroactively for effects emitted
  after the invalidating instant.
- Verification is a pure function of the objects and `at`. Implementations MAY cache results keyed
  by `(mandate-ref, request, at-bucket, policy-version, revocation-epoch)` but MUST invalidate on
  any revocation.

## 6. The root set (who counts as a named human)

`roots` is the set of enrolled human root keys of the organization. It is established by the
operator bootstrap ceremony (build plan S5) and changed only by an envelope of
`kind: "effect"`, `action: "kernel.enroll_root"` / `kernel.retire_root`, classification
`consequential`, which MUST itself be gated and MUST be signed by an existing root. Its evidence
MUST identify a well-formed key to enrol or retire (`root-enrollment-malformed`).

**A named human acting directly still acts under a mandate.** Effect kinds require `mandate-ref`,
and §1 forbids self-grant, so a human's own effect cites a mandate **another** human granted. The
consequence is deliberate and is stated here rather than discovered during an incident: **changing
the root set requires at least two enrolled roots.** That makes the most privileged action in the
system a two-person operation, which is the right posture for it — but an organization that enrols
one root and expects to retire it later will find it cannot, and it should find that out while
reading this rather than at the moment it needs to. The first root
is the ceremony's trust anchor: it is self-asserted at initialization and MUST be recorded as
`seq: 0` of the kernel's own stream.

- A key MUST NOT be both a human root and an agent grantee (`root-key-used-as-agent`).
- `grantor.role == "human"` is a claim; membership in `roots` is the fact. The verifier MUST check
  membership; the role member exists only so that a malformed object fails early and loudly.

## 7. Revocation

Revocation is itself an envelope (`kind: "revocation"`):

```json
{
  "v": "stozher/0.1", "kind": "revocation",
  "revokes": "<mandate-id>",
  "revoked-at": "2026-08-01T10:00:00.000Z",
  "reason": "laptop lost",
  "sig": { "alg": "ed25519", "key": "ed25519:<revoker>", "value": "..." }
}
```

- A revocation is valid iff signed by (a) the mandate's `grantor.key`, (b) the `grantor.key` of any
  ancestor mandate in its chain, or (c) an enrolled human root. Otherwise
  `revocation-not-authorized`.
- Effect on validity: a mandate revoked at `T` MUST be treated as invalid for every effect whose
  `emitted-at` is ≥ `T`, and so MUST every mandate delegated beneath it. Effects already recorded
  with `emitted-at < T` remain valid — the audit records what was permitted at the time, and
  rewriting history is not a feature.
- **A revocation is preventive only once the emitter has seen it, and the kernel MUST publish it.**
  An implementation MUST expose the revocation feed for reading, with a **monotonic
  `revocation-epoch`** as its entity tag, so a component can ask "has anything changed" at the cost
  of a conditional request and no rows. §5's cache key names that epoch; without an endpoint that
  serves it, the cache key names something no component can obtain.
- **State what a revocation costs the emitter, because it is not nothing.** Between the revocation
  and the emitter's next feed pull, the emitter keeps building its local chain under a mandate the
  kernel will refuse. Every one of those envelopes is rejected, the only kernel-side record is the
  rejection record of §04 §7, and **the emitter's stream is wedged at that position until an
  operator intervenes** — §04 §3 admits no gap, so it cannot simply skip past them. Nothing is lost
  and nothing is silently accepted; but an operator who expects revocation to be free will find a
  stopped component and no explanation, and that is worth one sentence here rather than one incident.
- `revoked-at` MUST NOT be earlier than the revoked mandate's `issued-at`
  (`revocation-before-issue`). Backdating a revocation to erase a window of authority is a
  rejection, not a workflow.
- Revocation is idempotent; a second revocation of the same mandate MUST be accepted and MUST NOT
  change the effective instant (earliest valid revocation wins).

## 8. Rotation

Rotation is grant + revoke, never mutation. A mandate object is immutable; its `mandate-id` is its
content hash.

1. Emit the new mandate (new `nonce`, new `not-after`, same or narrower scope).
2. Emit a revocation of the old mandate.
3. Emitters holding the old `mandate-ref` MUST re-resolve before the next effect; an effect citing a
   revoked mandate is `mandate-revoked` even if the new mandate would have permitted it. Authority
   is cited, not inferred.

Key rotation for a *subject* follows the same shape: the new key needs its own mandate; envelopes
already signed by the old key remain valid forever (that is the point of an audit log). Retiring a
key MUST NOT invalidate historical envelopes (`root-retirement-is-not-retroactive`).

## 9. What a mandate is not

- It is not a capability token presented to a third party: nothing outside the organization
  verifies it, and it grants nothing on its own — the effect must still pass policy (§05) and, if
  gated, carry an approval signature (§06).
- It is not an approval. A mandate says "this class of action is within your authority"; a gate
  decision says "this specific action, now, is permitted". Both are required for a gated action;
  neither substitutes for the other.
- It is not transferable: only the `grantee.key` may sign under it (`mandate-grantee-key-mismatch`).

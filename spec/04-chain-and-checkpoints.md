# 04 — Hash chain & checkpoints

Normative. The store is append-only and hash-chained; evidence payloads decay; **chain integrity is
independent of payload presence.** That last clause is the GDPR answer and the structural edge over
"keep everything in object storage" architectures, so it is specified before anything else can
depend on it.

## 1. Streams

A **stream** is an append-only sequence of envelopes with exactly one writer.

- `stream` (§02) is an opaque string, ≤ 128 octets, matching `^[A-Za-z0-9._:-]{1,128}$`
  (`stream-id-malformed`).
- One writer per stream. An emitter instance MUST own its stream; two emitters MUST NOT append to
  the same stream (that is the only way `seq` can be assigned without coordination, and it is why
  offline operation works at all).
- An emitter that holds several keys, or runs on several devices, MUST use one stream per
  (subject-key, device) pair. Recommended form: `<component>:<device>:<instance>`.
- Streams are independent: there is no global total order and none is needed. Cross-stream ordering
  is by `emitted-at` for display, and is explicitly **not** trusted for causality (§09).
- The kernel owns two streams by convention: `kernel:core` (root enrollment, policy publication,
  gate decisions) and `kernel:checkpoints` (§4).

## 2. Chaining rule

For every envelope `E` at position `seq` in stream `S`:

```
E.seq == 0   ⇒  E.prev-hash == null
E.seq  > 0   ⇒  E.prev-hash == id(E_prev)  where E_prev is the envelope with seq == E.seq - 1 in S
                and id() is object-hash over the complete signed envelope (§01 §5)
```

- `prev-hash` MUST be JSON `null` for the genesis envelope, not an empty string and not 64 zeros
  (`chain-genesis-prev-not-null`).
- `seq` MUST increase by exactly 1 with no gaps and no reuse (`chain-seq-gap`,
  `chain-seq-duplicate`).
- `prev-hash` MUST match (`chain-prev-hash-mismatch`).
- Because `id()` covers the predecessor's `sig`, the chain commits to signatures, not just bodies.
- `emitted-at` SHOULD be non-decreasing within a stream; a decrease MUST be recorded but MUST NOT by
  itself invalidate the chain (clock adjustments happen; the chain is the ordering authority, not
  the clock). Implementations MUST NOT use `emitted-at` to determine chain order.

### 2.1 Verification

`verify_chain(records)` over a contiguous range of one stream MUST check, for each record in order:

1. `parse strictly` → `verify sig` (§01 §5) → `schema` (§02 §9);
2. `seq` continuity;
3. `prev-hash` linkage against the recomputed `id()` of the previous record;
4. same `stream` value throughout (`chain-stream-mismatch`).

It MUST return the range's **head hash** (`id()` of the highest `seq`) on success. A verifier MUST
NOT require, request, or consult any evidence payload while doing this (§5).

Verification of a range that does not start at `seq == 0` requires the caller to supply the expected
`prev-hash` of the first record, or accept it as an anchor; the returned result MUST state which
(`anchored: true|false`). An unanchored range proves internal consistency only.

## 3. Append semantics

- The store is append-only: no UPDATE and no DELETE on envelope rows, enforced at the storage layer
  (SQLite triggers / Postgres rules), not merely in application code.
- Ingest is idempotent by `id(envelope)`: re-submitting a byte-identical envelope MUST return
  success without creating a second row. Submitting a *different* envelope for an occupied
  `(stream, seq)` MUST be rejected `chain-seq-duplicate` and MUST be recorded as a rejection —
  it is either a bug or an attempted rewrite, and both are audit-relevant.
- Ordering within a stream is enforced: an envelope whose `seq` exceeds the current head + 1 MUST be
  rejected `chain-seq-gap` (an emitter must not be able to reserve future positions). Clients that
  batch MUST submit in order; the kernel MAY buffer out-of-order arrivals briefly but MUST NOT
  append out of order.
- Offline emitters chain locally with the same rule and sync later; the kernel's acceptance
  therefore never renumbers anything (§05 §6, §09 §4).

## 4. Signed checkpoints

A checkpoint is a signed attestation that a stream had a given head at a given time. It converts
"the chain is internally consistent" into "the chain is consistent *and* has not been rebuilt",
because a rebuilt chain cannot reproduce a previously published head hash.

```json
{
  "v": "stozher/0.1", "kind": "checkpoint",
  "emitted-at": "2026-07-26T10:00:00.000Z",
  "stream": "kernel:checkpoints", "seq": 41, "prev-hash": "…",
  "identity": { "subject": "agent:kernel", "key": "ed25519:<checkpoint key>", "component": "kernel" },
  "checkpoint": {
    "stream": "gw:ivan-mbp:0001",
    "from-seq": 0, "to-seq": 1200,
    "head-hash": "<64 hex>",
    "count": 1201,
    "observed-at": "2026-07-26T09:59:58.000Z"
  },
  "sig": { "alg": "ed25519", "key": "ed25519:<checkpoint key>", "value": "…" }
}
```

Rules:

1. A checkpoint MUST be signed by a key derived at role `3'` (§01 §6) and enrolled as the kernel's
   checkpoint key. A checkpoint signed by any other key is `checkpoint-signer-not-kernel`.
2. `count` MUST equal `to-seq - from-seq + 1` (`checkpoint-count-mismatch`).
3. `head-hash` MUST equal `id()` of envelope `to-seq` of `checkpoint.stream`
   (`checkpoint-head-mismatch`).
4. Checkpoints of a given stream MUST be non-overlapping and contiguous: the next checkpoint's
   `from-seq` MUST equal the previous checkpoint's `to-seq + 1` (`checkpoint-range-discontinuous`).
5. Checkpoints themselves live in a chained stream (`kernel:checkpoints`), so the checkpoint history
   is as tamper-evident as the data it attests.
6. The kernel MUST emit a checkpoint per stream at least every `policy.checkpoint-interval`
   (default `PT1H`) and MUST emit one before deleting any payload (§5.4), so the pre-deletion head
   is publicly fixed.
7. Checkpoints SHOULD be exported off-box (the console's export, an operator's email, a git commit).
   A checkpoint that only ever exists inside the box it attests proves little — stated plainly here
   rather than implied.

## 5. Decay to hash — payload lifecycle

*Remember that, not what* (maxim 6). The mechanism is not deletion-with-a-tombstone; it is that
**the payload was never in the signed object.**

### 5.1 Structural rule

An envelope commits to evidence exclusively through `evidence.payload-hash` (§02 §5). Therefore:

- Deleting a payload changes **no byte** of any envelope, so no `id()`, no `prev-hash`, no `sig` and
  no `head-hash` changes.
- Chain verification (§2.1) has no input from the payload store at all. An implementation whose
  chain verification reads payloads is non-conformant (`chain-verification-must-not-read-payloads`
  is the conformance-harness assertion, not a runtime error).
- An auditor holding only envelopes + checkpoints can prove nothing was tampered with, for records
  whose content the organization is legally required to have erased. Both properties hold
  simultaneously and neither is a compromise.

### 5.2 Payload store

Payloads live in a separate content-addressed store keyed by `payload-hash`:

```json
{ "payload-hash": "<64 hex>", "media-type": "application/json", "payload": { … } }
```

- For `media-type: application/json`, `payload-hash` MUST equal `object-hash(payload)`.
  For any other media type, `payload` MUST be a lowercase-hex octet string and `payload-hash` MUST
  equal hex(SHA-256(those octets)). Mismatch → `payload-hash-mismatch`.
- Payloads are submitted **alongside** the envelope in one ingest request:

```json
{ "envelope": { … }, "payloads": [ { "payload-hash": "…", "media-type": "…", "payload": … } ] }
```

- The kernel MUST verify every submitted payload's hash before storing it, MUST reject the request
  if any hash mismatches, and MUST accept a request with `payloads: []` — a missing payload is
  never an error at ingest. An envelope is complete without it (`payloads` is transport, not
  content).
- Deduplication is by `payload-hash`; two envelopes referencing the same payload share one stored
  copy. Deletion MUST therefore be reference-counted: a payload MUST NOT be deleted while any
  envelope with an unexpired `retain-until` references it.

### 5.3 Retention by class

TTLs come from policy (§05 §4). Defaults, from the policy-model design doc:

| Class | Envelope | Payload |
|---|---|---|
| `read` (mass) | aggregation record (§02 §7) | none stored |
| `benign` | full envelope, forever | short TTL (default `P30D`) |
| `consequential` | full envelope, forever | long TTL, org-configurable (default `P365D`) |
| `prohibited` (attempted) | full envelope, forever | long TTL (default `P3650D`) — attempts are the most audit-valuable records |

`evidence.retain-until` is the emitter's computed deadline and MUST NOT exceed the policy maximum
for the classification (`evidence-retention-too-long`, §02 §5).

### 5.4 Deletion

- The kernel MUST delete a payload once `retain-until` has passed for every referencing envelope,
  and MUST do so without writing anything to the envelope rows.
- Erasure on request (GDPR Art. 17) is the same operation performed early. It MUST be recorded as an
  envelope (`kind: "effect"`, `action: "kernel.erase_payload"`, classification `consequential`,
  gated) whose evidence identifies the erased `payload-hash` values — **not** their content. The
  erasure is itself audited; that is what makes it defensible.
- Deletion MUST be preceded by a checkpoint of every affected stream (§4.6).
- After deletion, queries MUST report the evidence as `decayed` with the `payload-hash` still
  present and resolvable as a commitment: an auditor who independently possesses the content can
  still prove it is the content that was recorded. This is the whole point of keeping the hash.
- An implementation MUST NOT provide a mode that deletes envelopes. Log retention and payload
  retention are different questions and only the second one has an answer.

## 6. Query surface (informative for S0, binding for S1)

The store MUST be able to answer, by index and not by scan:

- by subject; by `mandate-ref`, including the transitive set beneath a mandate; by classification;
  by component; by `stream` + `seq` range; by time window on `emitted-at`;
- by `commitment-ref.object-id` — all transitions of a durable object, in chain order (§02 §8);
- by `correlation-ref`, exact and prefix (§02 §10);
- attempted-`prohibited`, as a first-class view;
- chain verification over a range, returning head hash and `anchored`;
- mandate walk for a given envelope, returning the human root (§03 §5).

## 7. Rejections are records

An ingest rejection MUST be recorded with: the reason code, `object-hash` of the rejected bytes as
received, the submitting connection's authenticated subject (if any), and the timestamp. Rejections

- MUST NOT be appended to the subject's stream (they are not part of that chain);
- MUST be appended to the kernel's own rejection stream, chained and checkpointed like anything else;
- MUST be visible in the console. A component that suddenly emits invalid envelopes is either broken
  or hostile, and in both cases the audit is the place it becomes visible.

## 8. Storage schema notes (informative)

SQLite first, Postgres later, same schema (ADR-0003). Sketch:

- `envelopes(stream, seq, id, prev_hash, kind, subject, mandate_ref, policy_version,
  classification, component, action, emitted_at, correlation_ref, canonical_json)` —
  PRIMARY KEY `(stream, seq)`, UNIQUE `(id)`, INSERT-only.
- `canonical_json` stores `JCS(envelope)` verbatim. Rationale: signature verification must be
  reproducible from what is stored; re-serializing from parsed columns invites exactly the
  canonicalization drift §01 exists to prevent.
- `payloads(payload_hash PRIMARY KEY, media_type, bytes, refcount, first_seen_at)`, deletable.
- `checkpoints(stream, from_seq, to_seq, head_hash, envelope_id)`.
- `rejections(id, received_at, reason, submitted_by, object_hash, raw_bytes_optional)`.

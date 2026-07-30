# Stozher test vectors — format and consumption

Language-neutral test vectors for `stozher/0.1`. They are the mechanical conformance test for every
implementation, in any language: the Rust kernel (`kernel/stozher-core`), the Python gateway suite
(S2), and any third-party component that wants to register (§08).

**Every vector carries its own expected output. A consuming test suite MUST read expected values from
these files and MUST NOT hardcode them.** That rule is the whole reason these files exist: two
implementations that each assert against their own constants cannot discover that they disagree.

## 0. The keys in these files are public test data, not secrets

These vectors contain fields named `secret-key` and `private-key`. That is deliberate and safe, and
worth stating plainly before anyone greps this directory and reaches for the alarm:

- **Signature vectors require known keypairs.** Ed25519 is deterministic, so "both implementations
  produce byte-identical signatures" is only testable if both sign with the *same* key. A vector with
  no secret key can assert verification but never signing.
- **The `slip10-ed25519` seeds are the ones published in the SLIP-0010 specification itself**
  (`000102030405060708090a0b0c0d0e0f…`). They are the canonical interoperability vectors every
  implementation of that derivation scheme tests against.
- **Every other key is derived deterministically from a public label** —
  `sha256("stozher/0.1 test vector key: " + label)` — by `generate_vectors.py` in this directory.
  Anyone can regenerate the entire corpus; that reproducibility is the point.

**No key here is ever operational.** A real deployment mints keys from the OS CSPRNG
(`getrandom`), stores them owner-only (`0600`), and refuses to load a key file carrying group or
other permission bits. Key material is excluded by `.gitignore` and `.dockerignore`, and no seed,
`.env`, or store file appears in any commit on any branch of this repository.

## 1. Layout

```
spec/vectors/
  index.json               enumerates every vector file with its `kind`
  <name>.json              one file per kind
  generate_vectors.py      the independent generator (see §6)
  README.md                this file
```

`index.json`:

```json
{
  "v": "stozher/0.1",
  "encoding": { "binary": "lowercase-hex", … },
  "files": [ { "path": "jcs-canonicalization.json", "kind": "jcs", "count": 22, "description": "…" } ]
}
```

A harness MUST read `index.json`, dispatch on `files[].kind`, and **fail on an unrecognised kind
rather than skipping it**. Adding a vector file of a known kind therefore extends coverage with no
harness change; adding a new kind fails loudly until support is written, which is the intended
behaviour — silently skipped vectors are worse than absent ones.

Each vector file:

```json
{ "v": "stozher/0.1", "kind": "<kind>", "description": "…",
  "keys": [ … ], "roots": [ … ], "mandates": { … },   // kind-specific shared material
  "vectors": [ { "name": "…", "description": "…", … } ] }
```

`name` is unique within a file and stable; use `"<file>/<name>"` in test output so a failure names
exactly one vector.

## 2. Encoding rules (identical to spec §01 §2)

| Thing | Encoding |
|---|---|
| all octet strings | **lowercase hex**, no prefix. Base64/base64url is never used anywhere |
| digest | 64 hex chars (SHA-256) |
| Ed25519 public key | 64 hex chars |
| Ed25519 secret key | 64 hex chars — the 32-byte RFC 8032 *seed*, not an expanded key |
| Ed25519 signature | 128 hex chars |
| key identifier | `"ed25519:" + public key hex` |
| timestamp | RFC 3339 UTC, exactly 3 fractional digits, `Z` |
| money | decimal **string** (`"25.00"`), never a JSON number |
| `input-json` (JCS kinds) | raw JSON **text**, so member order, escapes and numeric literals survive |

Vector files contain no floating-point numbers except inside the JCS number vectors, where they are
the subject under test.

## 3. Kinds

| `kind` | Per-vector members | What the harness must do |
|---|---|---|
| `jcs` | `input-json`, `canonical`, `canonical-sha256` | parse the raw text, canonicalize, compare bytes to `canonical` and the digest to `canonical-sha256` |
| `jcs-invalid` | `input-json`, `error` | parsing/canonicalizing MUST fail with exactly `error` |
| `sha256` | `input-hex`, `sha256` | hash the octets |
| `ed25519` | `secret-key?`, `public-key`, `message-hex`, `signature`, `verifies` | if `secret-key` present, signing MUST reproduce `signature` byte-for-byte (Ed25519 is deterministic); in all cases **strict** verification MUST return `verifies` |
| `slip10-ed25519` | `seed`, `path`, `chain-code`, `private-key`, `public-key`, `slip10-public-key`, `key-id` | derive and compare |
| `object-hash` | `object`, `expected-jcs`, `expected-object-hash`, `expected-signing-input?`, `expected-signing-input-sha256?`, `expected-signature-valid?` | canonicalize, hash, and (when the object has `sig`) compute the signing input and verify |
| `envelope` | `envelope`, `expected.{signing-input-sha256,envelope-hash,signature-valid}` | `envelope-hash` = object-hash over the **complete signed** envelope |
| `envelope-shape` | `envelope`, `expected.{valid,error}` | structural validation only (§02 §9); signature validity is not asserted unless the error code says so |
| `chain` | `stream`, `envelopes[]`, `expected.{valid,error,head-hash,anchored,count,failed-at-seq}` | verify signatures, `seq` continuity, `prev-hash` linkage, stream identity; return the head hash. **MUST NOT read any payload** |
| `mandate-chain` | file-level `roots`, `mandates`; per-vector `leaf-ref`, `subject-key`, `request`, `at`, `max-delegation-depth`, `revocations[]`, `expected.{valid,error,human-root,root-key,depth}` | run the §03 §5 algorithm |
| `authorization` | `envelope`, `requires-gate`, `approvers[]`, `seen-request-hashes[]`, `expected.{valid,error}` | run the §06 §2 algorithm |
| `payload-binding` | `ingest.{envelope,payloads[]}`, optional `chain[]`, `expected.{valid,error,envelope-hash,decayed,chain-head-hash,chain-valid}` | verify payload hashes and reference; an empty `payloads` array is always valid |

`expected.error` is `null` on success vectors and otherwise a **normative error code** from the spec
(§00 §1). Implementations MUST report exactly that code — the codes are part of the wire contract,
because a gateway in Python and a kernel in Rust have to agree on what they are refusing.

## 4. What the vectors deliberately cover

- **JCS traps** (§01 §3): UTF-16 vs code-point key ordering (U+1F60A before U+FFE0), all five
  ECMAScript `Number::toString` branches at their boundaries, `-0`, binary64 precision loss at
  9007199254740993, `1e-7` vs `0.000001` vs `1e+21`, minimum denormal, no Unicode normalization,
  literal U+2028/U+2029 and U+007F, duplicate keys, unpaired surrogates.
- **Signed-object pattern** (§01 §5): the signing input excludes `sig`; the object id includes it;
  member insertion order is irrelevant to both.
- **Chain** (§04 §2): a valid four-envelope chain plus six specific corruptions, each producing a
  distinct error code — including a validly *re-signed* envelope with a wrong `prev-hash`, which only
  the chain rule catches.
- **Mandate chains** (§03 §5): valid interactive / standing / delegated at depth 1 and 2, expired,
  not-yet-valid, missing expiry, depth exceeded (both by hop budget and by deployment cap), root that
  is not a human, root not enrolled, self-grant, scope widened (by action and by class), delegation
  not held, window outside parent, revocation — including a revocation that does **not** invalidate an
  effect emitted before it.
- **Gate authorization** (§06 §2): all ten algorithm steps, including a genuine signature carried
  while acting on a different target, a different `args-hash`, and a different mandate; replay;
  self-approval; a signed denial.
- **Decay** (§04 §5): the same envelope with and without its payload has the **identical** envelope
  hash, and the chain verifies either way. This is the GDPR property expressed as a test rather than
  as a paragraph.

## 5. Consuming from another language

Minimum viable harness, in pseudocode:

```
index = json.load("spec/vectors/index.json")
for file in index["files"]:
    doc = json.load("spec/vectors/" + file["path"])
    assert doc["kind"] == file["kind"]
    handler = HANDLERS[doc["kind"]]        # KeyError => fail the run, do not skip
    for vec in doc["vectors"]:
        handler(doc, vec)                  # assert with "file/name" in the message
```

Notes for implementers:

1. Read `input-json` as **text**. Do not round-trip it through your language's JSON types before the
   test — that discards the member order and numeric literals the vector is testing.
2. Canonicalize the object **as received**, including members you do not model. A harness that
   deserializes into a struct and re-serializes will compute the wrong signing input and every
   signature vector will fail for the wrong reason.
3. Use *strict* Ed25519 verification (rejecting small-order public keys and non-canonical scalars).
   The `small-order-public-key` and `tampered-signature-high-bit-of-s` vectors fail on permissive
   verifiers.
4. Your number serializer must be ECMAScript-compliant, not your language's default. Rust `{}`,
   Python `repr`, Go `%v` and `strconv.FormatFloat` are all wrong for at least one vector here.

## 6. Provenance — why these values are trustworthy

`generate_vectors.py` is an **independent implementation** of spec §01–§06: hand-written JCS with its
own ECMAScript `Number::toString`, hand-written SLIP-0010, and Ed25519 from PyNaCl/libsodium. It
shares no code with `kernel/stozher-core`, which uses `ryu-js` and `ed25519-dalek`. The reference
implementation is validated against these files by `cargo test`; the files were not produced by it.
Vectors generated by the implementation they validate would prove only that the code is
self-consistent.

Two values are additionally anchored to published external sources, and the generator **asserts**
them rather than recording whatever it computed:

- Ed25519: RFC 8032 §7.1 TEST 1 and TEST 2 (secret key, public key, message, signature).
- SLIP-0010: the ed25519 test-vector-1 master chain code for seed `000102030405060708090a0b0c0d0e0f`
  (`90046a93…ca9fffb`).

If either assertion ever fails, the generator aborts rather than emitting a file — a silent drift in
the crypto layer would otherwise be baked into every downstream suite.

Regenerate with:

```
python3 spec/vectors/generate_vectors.py     # requires PyNaCl
cd kernel && cargo test                      # must stay green
```

Regeneration is deterministic: fixed seeds, fixed timestamps, no randomness, no clock reads. A
regeneration that changes a byte means either the spec changed or something is wrong; the diff is the
review.

## 7. Out of scope for the vectors

- Anything relative to *now* (`envelope-emitted-in-future`, pull intervals, staleness): not
  reproducible in a static file. Those are ingest-time checks, tested in S1 with an injected clock.
- Storage behaviour (append-only enforcement, idempotency by envelope id, reference-counted payload
  deletion): S1.
- Transport, TLS, HTTP status mapping, notification delivery: S1/S2.
- The conformance harness itself (§08 §4) consumes these vectors as its first requirement but adds
  live-component tests that cannot live in a JSON file.

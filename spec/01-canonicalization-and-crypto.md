# 01 — Canonicalization & crypto

Normative. Inherited from Servanda unchanged in substance: **no new cryptography is invented
here, deliberately.**

## 1. Cryptographic suite

`stozher/0.1` defines exactly one suite. There is no negotiation.

| Purpose | Algorithm | Tag |
|---|---|---|
| Digest | SHA-256 (FIPS 180-4) | `sha256` |
| Signature | Ed25519 (RFC 8032, pure, not `ph`) | `ed25519` |
| Canonical JSON | JCS (RFC 8785) | `jcs` |
| Key derivation | SLIP-0010 for `ed25519` (hardened only) | `slip10-ed25519` |
| MAC (inside SLIP-0010 only) | HMAC-SHA-512 (RFC 2104) | — |

An implementation MUST reject an object whose `alg` member is any value other than the tag
defined for that position (`crypto-unsupported-alg`).

## 2. Encoding rules

1. All octet strings — digests, public keys, signatures, seeds, nonces, opaque payloads — MUST be
   encoded as **lowercase hexadecimal**, with no prefix, no separators, and an even length.
   Base64 and base64url MUST NOT be used anywhere in `stozher/0.1`. An uppercase hex digit is a
   rejection (`encoding-not-lowercase-hex`).
2. A SHA-256 digest is therefore exactly 64 hex characters; an Ed25519 public key 64; an Ed25519
   signature 128.
3. Timestamps MUST be RFC 3339 date-times in UTC, with exactly three fractional-second digits and
   the literal suffix `Z`: `2026-07-26T09:15:00.000Z`. Offsets other than `Z`, absent or differing
   fractional precision, and lowercase `z` MUST be rejected (`encoding-bad-timestamp`).
   Rationale: timestamps are compared as strings in indexes and in vectors; one format only.
4. Durations MUST be ISO 8601 durations restricted to `P[nD][T[nH][nM][nS]]` (for example `P30D`,
   `PT15M`). Months and years MUST NOT be used (`encoding-bad-duration`) — their length is
   ambiguous and retention windows are legal commitments.
5. **Numbers in protocol objects.** Every JSON number appearing in a *protocol object* (envelope,
   mandate, policy, manifest, gate object, checkpoint) MUST be an integer in the closed range
   [-(2^53 - 1), 2^53 - 1] (`encoding-non-integer-number`). Fractional and monetary quantities
   MUST be expressed as decimal **strings** (`"25.00"`, `"0.000123"`). Rationale: floating-point
   round-tripping is the single most common canonicalization defect; protocol objects are placed
   permanently out of its reach. Evidence *payloads* (§04) are arbitrary JSON and MAY contain any
   JSON number; canonicalization of those numbers is fully specified in §3.4 below.

## 3. Canonicalization (JCS, RFC 8785)

`JCS(v)` denotes the canonical UTF-8 serialization of JSON value `v` per RFC 8785. An
implementation MUST implement RFC 8785 in full. The following points are called out because they
are where independent implementations diverge in practice; each has test vectors.

### 3.1 Input validity

A canonicalizer MUST reject, rather than silently repair:

- duplicate member names in the same object (`jcs-duplicate-key`);
- unpaired UTF-16 surrogates in string escapes, in values and in member names (`jcs-lone-surrogate`);
- input that is not well-formed JSON per RFC 8259 (`jcs-malformed-json`). This includes the tokens
  `NaN`, `Infinity` and `-Infinity` — RFC 8259 defines no such literals — and numeric literals whose
  value lies outside the binary64 range (`1e400`), which have no canonical form;
- a non-finite number reaching an API that canonicalizes an already-parsed in-memory value rather
  than text (`jcs-non-finite-number`). Text input can only produce this condition through the
  malformed-JSON path above; the distinct code exists because the two entry points fail at different
  layers and an implementation should not have to lie about which one it was.

### 3.2 Member ordering

Object members MUST be sorted by their name interpreted as a sequence of **UTF-16 code units**,
compared as unsigned 16-bit integers, lexicographically (shorter name that is a prefix sorts
first). This is *not* the same as sorting by Unicode code point or by UTF-8 bytes: a name
beginning with U+1F60A (UTF-16 `D83D DE0A`) sorts **before** a name beginning with U+FFE0, while
UTF-8 byte order places it after. Implementations that sort `String` values with a language's
default comparator (Rust `BTreeMap`, Go `sort.Strings`, Python `sorted`) are wrong for names
outside the BMP. Vector: `jcs-canonicalization.json` / `key-order-utf16-vs-codepoint`.

Sorting is applied at every nesting level. Array element order is **never** changed.

### 3.3 Strings

Serialization of strings follows ECMAScript `JSON.stringify`: escape `"` as `\"`, `\` as `\\`,
U+0008 as `\b`, U+0009 as `\t`, U+000A as `\n`, U+000C as `\f`, U+000D as `\r`, all other code
points below U+0020 as `\u00xx` with lowercase hex digits, and every other code point literally
as UTF-8. In particular U+007F, U+2028, and U+2029 are emitted **literally**, and non-ASCII
characters are **not** `\u`-escaped.

Unicode normalization is **not** performed. `"é"` (U+00E9) and `"é"` (U+0065 U+0301) are distinct
names and distinct values, and both are valid. Producers that care MUST normalize before signing;
the canonicalizer MUST NOT normalize on their behalf (doing so would let two different documents
share one signature).

### 3.4 Numbers

Numbers MUST be serialized exactly as ECMAScript `Number::toString` would serialize the IEEE-754
binary64 value obtained by parsing the input literal (RFC 8785 §3.2.2.3). Consequences that
implementations get wrong:

- The value, not the literal, is canonicalized: `1.0`, `1`, and `1e0` all serialize to `1`;
  `9007199254740993` serializes to `9007199254740992` (binary64 has no other choice).
- `-0` serializes to `0`.
- `1e-7` → `1e-7` (not `1e-07`); `0.000001` → `0.000001`; `1e21` → `1e+21`; `1e20` →
  `100000000000000000000`; `1e30` → `1e+30`; `5e-324` → `5e-324`.
- Exponents use `e`, always carry an explicit sign, and never have leading zeros.

The exact procedure: obtain the shortest decimal digit string `s` (length `k`) and integer `n`
such that the value equals `s × 10^(n-k)` and `s` round-trips; then

| condition | output |
|---|---|
| `k ≤ n ≤ 21` | `s` followed by `n - k` zeros |
| `0 < n ≤ 21`, `n < k` | first `n` digits of `s`, `.`, remaining digits |
| `-6 < n ≤ 0` | `0.`, `-n` zeros, `s` |
| otherwise, `k = 1` | `s`, `e`, sign of `n-1`, `abs(n-1)` |
| otherwise | `s[0]`, `.`, `s[1..]`, `e`, sign of `n-1`, `abs(n-1)` |

An implementation SHOULD delegate this to a library that documents ECMAScript-compliant
`Number::toString` output (the reference implementation uses `ryu-js`) and MUST verify that
library against `spec/vectors/jcs-canonicalization.json`.

### 3.5 Object hash

For any JSON value `v`:

```
object-hash(v) = lowercase_hex( SHA-256( JCS(v) ) )
```

`object-hash` is the only way an object is referred to anywhere in this specification. All `*-ref`
and `*-hash` members hold `object-hash` values.

## 4. Keys and key identifiers

An Ed25519 public key is identified by its own bytes; there is no registry lookup on the
verification path:

```
key-id = "ed25519:" || lowercase_hex( 32-byte Ed25519 public key )
```

- A key identifier MUST match `^ed25519:[0-9a-f]{64}$` (`key-id-malformed`).
- Verifiers MUST NOT accept a key identifier whose hex decodes to a point of small order or to a
  non-canonical encoding. Implementations MUST use a strict verification routine that rejects
  small-order public keys and non-canonically-encoded scalars/points (in `ed25519-dalek`,
  `verify_strict`). Rationale: signature malleability and repudiation attacks against Ed25519
  batch/permissive verifiers are well documented.
- **Enrollment is separate from identification.** A key identifier says *which* key; it says
  nothing about *whose*. The binding key-id → named subject (human or agent), and whether that
  subject is a **human root**, is established by the organization's enrollment records and is
  authoritative only inside one organization (maxim 4). §03 §6 defines the root set.

## 5. Signed objects

Every signed object in Stozher — envelope, mandate, revocation, policy document, gate decision,
checkpoint, manifest registration — follows one pattern.

A signed object `S` is a JSON object with a member `sig`:

```json
{ "alg": "ed25519", "key": "ed25519:<64 hex>", "value": "<128 hex>" }
```

Definitions:

```
signing-input(S) = JCS( S with the member "sig" removed )
signature        = Ed25519-Sign( private key, signing-input(S) )      // over the bytes, pure
S.sig.value      = lowercase_hex( signature )
id(S)            = object-hash(S)      // over the COMPLETE object, sig included
```

Rules:

1. The signature is computed over the canonical bytes themselves. Ed25519ph (pre-hashed) MUST NOT
   be used.
2. `id(S)` covers `sig`. Therefore a hash chain over `id` values (§04) commits to the signatures
   of its predecessors, not merely to their bodies. Ed25519 signing is deterministic, so `id(S)`
   is a deterministic function of the body and the signing key.
3. `sig` MUST be the only member removed when computing `signing-input`. Removing or defaulting
   any other member before signing is a rejection (`sig-input-mismatch` on verification).
4. `sig.key` MUST be the signer. Where a section requires a specific signer (for example: a
   mandate MUST be signed by its grantor), a mismatch is that section's error, not a generic one.
5. Verification of `S` succeeds iff `sig` is present and well-formed, `sig.alg` is `ed25519`,
   `sig.key` is a well-formed key identifier, and `Ed25519-Verify(sig.key, signing-input(S),
   sig.value)` succeeds under strict verification. Otherwise `sig-invalid`.
6. Verifiers MUST canonicalize **the object as received**, including members they do not
   understand; they MUST NOT re-serialize a subset. (An implementation that deserializes into a
   fixed struct and re-serializes will silently drop unknown members and compute the wrong
   signing input.) Independently of this, ingest MUST reject protocol objects carrying unknown
   top-level members (`schema-unknown-member`) — see §02 §9.

## 6. Key derivation (SLIP-0010, ed25519)

Subject keys SHOULD be derived from a single high-entropy seed so that an organization can back up
one secret and recover every subject key. Derivation is SLIP-0010 for the `ed25519` curve:

```
master:  I = HMAC-SHA512( key = "ed25519 seed" (ASCII, 12 bytes), data = seed )
         k_master   = I[0..32]        (private key)
         c_master   = I[32..64]       (chain code)

child i (hardened only, i >= 2^31):
         data = 0x00 || k_parent || ser32(i)
         I    = HMAC-SHA512( key = c_parent, data = data )
         k_i  = I[0..32] ,  c_i = I[32..64]
```

- Non-hardened derivation MUST NOT be used for `ed25519` (`slip10-non-hardened-index`); it is not
  defined by SLIP-0010 for this curve.
- The seed MUST be 16–64 octets. Implementations SHOULD use 32.
- Unlike secp256k1, there is no retry loop: every `I[0..32]` is a valid ed25519 private key.
- The public key is the Ed25519 public key of `k`. SLIP-0010 test vectors publish it with a
  leading `0x00` byte; Stozher key identifiers use the 32-byte key **without** that prefix.

**Path convention.** Derivation paths MUST be `m/1054'/<role>'/<index>'`, all components hardened.
`1054` has no external significance; it is fixed so that key recovery is interoperable between
implementations.

| `role` | Subject |
|---|---|
| `0'` | human root key |
| `1'` | agent subject key |
| `2'` | device / session key (the key a gateway derives per connecting caller, §10) |
| `3'` | kernel checkpoint key |
| `4'` | organization policy key |

## 7. Non-goals for 0.1

- No encryption is specified. Envelopes and payloads are integrity-protected, not confidential;
  confidentiality is the deployment's problem (single-tenant, maxim 4) until the HPKE work lands
  with external review.
- No threshold or multi-signature. One effect, one executing subject, one signature (maxim 3).
- No algorithm agility. A future `stozher/0.2` may add a suite; `0.1` implementations MUST reject
  unknown tags rather than guess.

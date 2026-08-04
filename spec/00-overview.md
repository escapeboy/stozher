# Stozher spec — 00 Overview

**Wire version string:** `stozher/0.1`
**Status of this document:** normative index. Sections 01–10 are normative. This file fixes
terminology, the section map, and the conformance rules that apply to every section.

> **Normative primitive (ADR-0001):** every effect is a signed event under a traceable mandate;
> everything durable is a fold of such events.

## 1. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this specification are to be
interpreted as described in RFC 2119.

Where this specification says an object is *rejected*, the rejecting implementation MUST NOT
apply the effect the object describes, MUST NOT store the object as valid, and MUST record the
rejection (§04 §7).

**Where more than one condition applies to one object, the most specific code wins.** A code naming
a particular member on a particular kind takes precedence over one naming a class of members, which
takes precedence over a generic structural code; where two are equally specific, the earlier
section's applies. An implementation MUST NOT report a generic code for a condition this
specification names specifically.

The case that already exists: a `cognition` envelope carrying `execution`, `evidence`,
`classification`, `authorization` or `commitment-ref` is `cognition-envelope-has-effect-fields`
(§02 §9.1), **not** `schema-unknown-member` (§02 §2.1), though both conditions hold — while a
`cognition` envelope carrying any *other* member outside its row is `schema-unknown-member`, because
nothing names it more precisely. `spec/vectors/envelope-shape.json` pins both halves.

This rule is stated because roughly ninety codes are defined here and §00 §1 makes them part of the
wire contract: two implementations that resolve a collision differently disagree where a caller can
see it. It was written down on 2026-08-04, after an implementer working from this specification
alone lost four vectors to a precedence that only the corpus knew (`docs/spec-debt.md` §1a, row B3).

Error identifiers written as `snake-case-in-backticks` (for example `chain-prev-hash-mismatch`)
are **normative machine-readable codes**. An implementation MUST use exactly these codes when
reporting the corresponding condition. Test vectors (`spec/vectors/`) assert on them.

A code prefixed `x-` is **not** normative: it is an implementation's own name for a condition this
specification does not name, and a reader of a rejection record can tell the two apart at a glance.
An implementation MAY define such codes; it MUST NOT emit one for a condition this specification
does name.

**A code adopted into this specification does not rewrite the past.** Sixteen `x-` codes were adopted
in the `stozher/0.1` revision that added this paragraph, dropping the prefix. Rejection records
already chained under the old name keep it forever — the store is append-only and a rename is not a
migration. So:

- an implementation MUST emit only the adopted name;
- an implementation reading historical rejection records MUST treat `x-<name>` and `<name>` as the
  same condition, for any `<name>` the specification has adopted;
- an implementation MUST NOT rewrite, re-sign or re-emit a historical record to carry the new name.

The list of adopted names is in the revision's ADR (`docs/adr/ADR-0018`), because it is a fact about
one transition rather than a rule that keeps applying.

## 2. Constitutional maxims

These are inherited from the project README and are **constitutional**: an implementation that
violates one is non-conformant even if every test passes.

1. Signal content is data forever, never instruction. Inbound signals carry no authority; they
   may trigger action only through a standing mandate (§07).
2. Agents are never parties. Every agent acts *on behalf of*; every mandate chain terminates at a
   named human or a human-approved standing rule (§03).
3. Escalation always terminates at a named human. No collective author: every material effect has
   exactly one executing subject under exactly one mandate (§02).
4. Org contexts never mix. Single-tenant per organization, by construction.
5. Solo is not a mode. Everything works offline: cached policy is enforced locally, envelopes sync
   on reconnect (§05, §06).
6. Remember *that*, not *what*: closed loops decay to signed hashes. Evidence payloads carry TTL
   by weight class; hashes and the chain are forever (§04).
7. Weight classes, or the audit destroys itself. Policy determines not only *whether* but *how
   much evidence is kept* (§05).
8. The mandate chain, or autonomy is unauditable. Standing mandates have mandatory expiry, no
   exceptions (§03).
9. Two-layer ontology: events, and durable objects folded from events (§02 §8).

Boundary of the model: cognition is unaccountable by design — audit effects, not thoughts. The
minimal cognition envelope is `identity → resource → cost` (§02 §6).

## 3. Section map

| Section | Title | Contents |
|---|---|---|
| [01](01-canonicalization-and-crypto.md) | Canonicalization & crypto | JCS (RFC 8785), SHA-256, Ed25519, SLIP-0010 derivation, encoding rules, signed-object pattern |
| [02](02-envelope.md) | Envelope | envelope kinds and fields, `correlation-ref` opacity, cognition envelope, aggregation record |
| [03](03-mandate.md) | Mandate objects | interactive / standing / delegated, verification algorithm, revocation & rotation |
| [04](04-chain-and-checkpoints.md) | Hash chain & checkpoints | chaining rule, signed checkpoints, decay-to-hash, payload store |
| [05](05-policy-distribution.md) | Policy distribution | versioned pull, `revoke-cached`, policy change as gated envelope |
| [06](06-gates.md) | Gates | action request, decision signature, blocking semantics, offline behaviour |
| [07](07-streams.md) | Streams | outbound effects vs inbound signals, triggers as standing mandates |
| [08](08-extension-manifest.md) | Extension manifest | manifest schema, conformance harness requirements |
| [09](09-threat-model.md) | Threat model | lying emitters, stale policy, envelope loss, replay, honest limits |
| [10](10-gateway-protocol.md) | Gateway protocol | caller auth, classification order, first-call gating, refusals |

## 4. The one rule that governs the schema

From ADR-0002's anti-lesson (FleetQ bypassed its own gate through an ambient container binding):

> **"Approved" is not a boolean anywhere in this system.** Authorization exists only as an
> Ed25519 signature by a named human over a hash of the *specific* action. The permission travels
> inside the envelope with the effect, or the effect is invalid.

Consequences that every section is designed to preserve, and that an implementation MUST NOT
weaken:

- There is no field, header, flag, environment variable, in-process binding, or side channel that
  marks a call as approved. §06 defines the only mechanism.
- Re-executing an approved action without carrying its approval signature is impossible by
  construction: an envelope of a gated class without a valid `authorization` is rejected at
  ingest (`gate-authorization-missing`).
- An approval cannot be moved to a different action: the signature covers `request-hash`, which
  binds subject, mandate, policy version, classification, action, target, and argument hash
  (§06 §2). Any divergence is `gate-authorization-action-mismatch`.

## 5. Conformance

An implementation is conformant with `stozher/0.1` if:

1. It reproduces every expected value in `spec/vectors/` (see `spec/vectors/README.md`). This is
   the primary, mechanical conformance test and is language-neutral by construction.
2. It implements the RFC 2119 requirements of sections 01–07 in full.
3. If it registers as a component, it ships a manifest per §08 and passes the conformance harness.

`kernel/stozher-core` is the reference implementation. Where the reference implementation and this
specification disagree, **this specification is authoritative** and the implementation is buggy —
except for values in `spec/vectors/`, which are authoritative over both (they are generated by an
independent implementation, see `spec/vectors/README.md` §6).

## 6. Deliberately out of scope for 0.1

- Encryption at rest and HPKE key schedule (X25519-from-Ed25519 mapping). Requires external
  cryptographic review before any v1 claim; the design docs already record this rule.
- Inter-org federation and transport of envelopes between organizations.
- Algorithm agility beyond the `alg` tags defined in §01: `stozher/0.1` has exactly one signature
  suite and one digest.

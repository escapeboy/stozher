<!-- MIRROR of Svod note `projects/stozher/docs/design/identity-and-mandate.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Identity and mandate — the formal model

Reuses Servanda cryptography 1:1 — Ed25519 signatures, SLIP-0010 key derivation, JCS (RFC 8785) canonicalization + SHA-256. No new crypto is invented here; this is deliberate.

## Subjects

- **Humans**: root keys. The only terminal authority in the system.
- **Agents**: derived keys under mandate. An agent key with no valid mandate chain signs nothing the kernel accepts. (Servanda maxim: agents are never parties.)

## Mandate — signed delegation object

Three kinds:

| Kind | Grantor → grantee | Lifetime | Typical use |
|---|---|---|---|
| **interactive** | human → agent | dies with the session | "do this now, under my eyes" |
| **standing** | human → agent (via rule) | **mandatory expiry, no exceptions** | scheduled tasks, trigger rules, autonomy |
| **delegated** | agent → agent | bounded chain depth (config, default small) | crew fan-out, sub-tasking |

Fields (draft, to be schema'd in spec S0): grantor key, grantee key, kind, scope (action classes / components / resources), budget dimensions, expiry, parent-mandate ref (for delegated), signature.

## Verification

Envelope validity = signature valid AND mandate chain walks to a named human root AND every link in scope AND nothing expired. Invalid envelopes are rejected at ingest — the constitution binds ill-behaved clients mechanically (Servanda precedent: invalid assertions are discarded).

## Consequences

- Autonomous starts (ADR-0001 case 4) become auditable: the trigger rule IS a standing mandate with a human signature and an expiry date.
- The mandate registry is a first-class console surface: who delegated what to whom, expiring standing rules surfaced up front (see [[projects/stozher/docs/design/console]]).
- Revocation and rotation: reuse Servanda's attestation/revocation object shapes; a revocation is itself an envelope.

## Deliberately deferred

- HPKE / encryption-at-rest key schedule details → spec phase, with the same rule as Servanda: external crypto review before v1. One person must not trust himself on the X25519-from-Ed25519 map.

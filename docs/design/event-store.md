<!-- MIRROR of Svod note `projects/stozher/docs/design/event-store.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Event store — append-only, hash-chained, decaying to hashes

## Svod is NOT the log

Knowledge and telemetry have opposite write patterns. Svod remains the distilled memory (folds, decisions, provenance links); envelopes go to a dedicated store. Envelopes may *reference* Svod notes (memory-ref field); Svod notes may cite envelope hashes as provenance. Two systems, linked, never merged.

## Store

- Append-only, hash-chained (each record includes hash of predecessor; periodic signed checkpoints).
- Boring tech on purpose: SQLite (laptop / single node) → Postgres (org deployment). Same schema.
- Ingest API validates: signature, mandate chain, schema conformance per component manifest. Invalid → rejected + rejection itself logged (rejections are audit-valuable).
- Two streams per ADR-0001: **outbound effects** (envelopes) and **inbound signals** (data records, no authority, linked to any envelope they triggered via standing mandate ref).

## Retention — the GDPR answer

Maxim: *closed loops decay to signed hashes.*

- Evidence payloads carry TTL by weight class (see policy model). On expiry, payload is deleted; **hash + chain position remain forever**.
- Auditor can verify nothing was tampered with, without the org storing content until the end of time.
- Personal-data erasure requests: payload deletion is compatible with chain integrity by construction — the chain commits to hashes, not to content presence.
- This is a structural edge over "keep everything in S3" architectures. It goes in every pitch and every interview answer.

## Aggregation records

Mass reads (class `read`) are folded at emit time by the component into aggregate records: subject, mandate, window, counts, sample hashes. The kernel never sees the firehose; the audit stays legible.

## Query surface (feeds console)

- By subject, by mandate (chain), by class, by component, by time window, by durable-object ref (all transitions of commitment X / session Y / tool Z).
- Chain verification endpoint: given a range, verify integrity; given an envelope, walk its mandate to the human root.

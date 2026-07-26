-- Stozher event store — spec/04-chain-and-checkpoints.md §8.
--
-- PORTABILITY: this DDL is the Postgres-compatible subset. SQLite-only statements (the
-- append-only triggers) live in `append_only.sqlite.sql` so the dialect seam is one file, not a
-- scatter of conditionals. Rules observed here:
--   * no `INTEGER PRIMARY KEY` rowid aliasing, no AUTOINCREMENT, no WITHOUT ROWID, no rowid reads;
--   * every column has an explicit type and SQLite's dynamic typing is never relied upon;
--   * booleans are `INTEGER NOT NULL CHECK (x IN (0, 1))` — Postgres accepts this unchanged;
--   * timestamps are `TEXT` holding the single fixed RFC 3339 form of spec §01 §2.3, because the
--     specification compares them as strings and one format must survive a dialect change;
--   * `BLOB` appears once (payload octets) and is the one type name Postgres spells differently
--     (`BYTEA`).

CREATE TABLE IF NOT EXISTS envelopes (
    stream                TEXT   NOT NULL,
    seq                   BIGINT NOT NULL,
    id                    TEXT   NOT NULL,
    prev_hash             TEXT,
    kind                  TEXT   NOT NULL,
    subject               TEXT   NOT NULL,
    subject_key           TEXT   NOT NULL,
    component             TEXT   NOT NULL,
    mandate_ref           TEXT,
    human_root            TEXT,
    policy_version        TEXT,
    classification        TEXT,
    effective_class       TEXT,
    action                TEXT,
    target                TEXT,
    args_hash             TEXT,
    outcome               TEXT,
    emitted_at            TEXT   NOT NULL,
    received_at           TEXT   NOT NULL,
    correlation_ref       TEXT,
    commitment_type       TEXT,
    commitment_id         TEXT,
    commitment_transition TEXT,
    policy_violation      TEXT,
    canonical_json        TEXT   NOT NULL,
    PRIMARY KEY (stream, seq),
    UNIQUE (id)
);

-- The query surface of §04 §6 must be answerable by index, not by scan.
CREATE INDEX IF NOT EXISTS envelopes_by_subject     ON envelopes (subject, emitted_at);
CREATE INDEX IF NOT EXISTS envelopes_by_mandate     ON envelopes (mandate_ref);
CREATE INDEX IF NOT EXISTS envelopes_by_root        ON envelopes (human_root);
CREATE INDEX IF NOT EXISTS envelopes_by_class       ON envelopes (effective_class, emitted_at);
CREATE INDEX IF NOT EXISTS envelopes_by_component   ON envelopes (component, emitted_at);
CREATE INDEX IF NOT EXISTS envelopes_by_emitted_at  ON envelopes (emitted_at);
CREATE INDEX IF NOT EXISTS envelopes_by_correlation ON envelopes (correlation_ref);
CREATE INDEX IF NOT EXISTS envelopes_by_object      ON envelopes (commitment_id, stream, seq);
CREATE INDEX IF NOT EXISTS envelopes_by_outcome     ON envelopes (outcome, effective_class);
CREATE INDEX IF NOT EXISTS envelopes_by_action_args ON envelopes (action, args_hash);
CREATE INDEX IF NOT EXISTS envelopes_by_violation   ON envelopes (policy_violation);

-- One writer per stream, and a stream never mixes effects with inbound signals (§07 §2.5).
CREATE TABLE IF NOT EXISTS streams (
    stream          TEXT   NOT NULL,
    stream_kind     TEXT   NOT NULL,
    head_seq        BIGINT NOT NULL,
    head_hash       TEXT   NOT NULL,
    first_seen_at   TEXT   NOT NULL,
    last_appended_at TEXT  NOT NULL,
    PRIMARY KEY (stream)
);

-- Payloads are content-addressed and deletable. Nothing here is chain-bearing: erasing a row
-- changes no signed byte anywhere (§04 §5.1).
CREATE TABLE IF NOT EXISTS payloads (
    payload_hash  TEXT NOT NULL,
    media_type    TEXT NOT NULL,
    bytes         BLOB NOT NULL,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (payload_hash)
);

-- Deletion is reference-counted by construction: a payload survives while any referencing
-- envelope's retain-until is still in the future (§04 §5.2).
CREATE TABLE IF NOT EXISTS payload_refs (
    payload_hash TEXT NOT NULL,
    envelope_id  TEXT NOT NULL,
    stream       TEXT NOT NULL,
    retain_until TEXT NOT NULL,
    PRIMARY KEY (payload_hash, envelope_id)
);

CREATE INDEX IF NOT EXISTS payload_refs_by_retention ON payload_refs (retain_until);

CREATE TABLE IF NOT EXISTS checkpoints (
    stream      TEXT   NOT NULL,
    from_seq    BIGINT NOT NULL,
    to_seq      BIGINT NOT NULL,
    head_hash   TEXT   NOT NULL,
    envelope_id TEXT   NOT NULL,
    observed_at TEXT   NOT NULL,
    PRIMARY KEY (stream, from_seq)
);

-- Rejections are records (§04 §7): chained in the kernel's own stream, never in the submitter's.
-- They are deliberately not envelopes: §02 §2 is a closed `kind` vocabulary with no member for a
-- rejection, so a rejection record is a signed chained object of its own shape.
CREATE TABLE IF NOT EXISTS rejections (
    stream          TEXT   NOT NULL,
    seq             BIGINT NOT NULL,
    id              TEXT   NOT NULL,
    prev_hash       TEXT,
    reason          TEXT   NOT NULL,
    detail          TEXT   NOT NULL,
    object_hash     TEXT   NOT NULL,
    submitted_by    TEXT,
    received_at     TEXT   NOT NULL,
    claimed_stream  TEXT,
    claimed_seq     BIGINT,
    claimed_kind    TEXT,
    record_json     TEXT   NOT NULL,
    PRIMARY KEY (stream, seq),
    UNIQUE (id)
);

CREATE INDEX IF NOT EXISTS rejections_by_reason  ON rejections (reason, received_at);
CREATE INDEX IF NOT EXISTS rejections_by_subject ON rejections (submitted_by, received_at);

-- The gate replay set (§06 §3). The PRIMARY KEY is the enforcement: two concurrent submissions of
-- one approval cannot both insert, so "used twice" is impossible rather than unlikely.
CREATE TABLE IF NOT EXISTS gate_request_hashes (
    request_hash TEXT   NOT NULL,
    envelope_id  TEXT   NOT NULL,
    decided_by   TEXT   NOT NULL,
    single_use   INTEGER NOT NULL CHECK (single_use IN (0, 1)),
    not_after    TEXT   NOT NULL,
    recorded_at  TEXT   NOT NULL,
    PRIMARY KEY (request_hash)
);

-- Every policy version the kernel has ever published, forever (§05 §2.2).
CREATE TABLE IF NOT EXISTS policies (
    policy_version TEXT   NOT NULL,
    document_hash  TEXT   NOT NULL,
    document_json  TEXT   NOT NULL,
    published_by   TEXT   NOT NULL,
    envelope_id    TEXT   NOT NULL,
    published_at   TEXT   NOT NULL,
    ordinal        BIGINT NOT NULL,
    PRIMARY KEY (policy_version),
    UNIQUE (ordinal)
);

-- Every registered manifest version, forever (§08 §3.5).
CREATE TABLE IF NOT EXISTS manifests (
    name          TEXT   NOT NULL,
    version       TEXT   NOT NULL,
    manifest_hash TEXT   NOT NULL,
    component_key TEXT   NOT NULL,
    document_json TEXT   NOT NULL,
    envelope_id   TEXT   NOT NULL,
    registered_at TEXT   NOT NULL,
    ordinal       BIGINT NOT NULL,
    PRIMARY KEY (name, version)
);

CREATE TABLE IF NOT EXISTS roots (
    root_key    TEXT NOT NULL,
    subject     TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    retired_at  TEXT,
    envelope_id TEXT NOT NULL,
    PRIMARY KEY (root_key)
);

CREATE TABLE IF NOT EXISTS mandates (
    mandate_id    TEXT   NOT NULL,
    parent        TEXT,
    mandate_kind  TEXT   NOT NULL,
    grantor_key   TEXT   NOT NULL,
    grantee_key   TEXT   NOT NULL,
    grantee_subject TEXT NOT NULL,
    not_before    TEXT   NOT NULL,
    not_after     TEXT   NOT NULL,
    document_json TEXT   NOT NULL,
    envelope_id   TEXT   NOT NULL,
    PRIMARY KEY (mandate_id)
);

CREATE INDEX IF NOT EXISTS mandates_by_parent  ON mandates (parent);
CREATE INDEX IF NOT EXISTS mandates_by_grantee ON mandates (grantee_key);

CREATE TABLE IF NOT EXISTS revocations (
    revocation_id TEXT NOT NULL,
    revokes       TEXT NOT NULL,
    revoked_at    TEXT NOT NULL,
    document_json TEXT NOT NULL,
    envelope_id   TEXT NOT NULL,
    PRIMARY KEY (revocation_id)
);

CREATE INDEX IF NOT EXISTS revocations_by_target ON revocations (revokes);

-- Counters the store needs to be monotonic without leaning on any dialect's sequence type.
CREATE TABLE IF NOT EXISTS counters (
    name  TEXT   NOT NULL,
    value BIGINT NOT NULL,
    PRIMARY KEY (name)
);

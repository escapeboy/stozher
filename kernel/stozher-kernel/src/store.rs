//! The append-only hash-chained store — `spec/04-chain-and-checkpoints.md`.
//!
//! The DDL lives in `src/sql/` rather than beside this file: the repository's `.gitignore` excludes
//! `store/` to keep event-store *data* directories out of version control, and an unanchored pattern
//! matches a source directory of that name just as happily. Naming the directory `sql/` sidesteps the
//! collision without touching a root file that is not this stage's to change.
//!
//! # What makes this append-only
//!
//! Not a convention and not a code review rule: `envelopes`, `rejections`, `checkpoints`,
//! `policies`, `manifests` and `gate_request_hashes` carry `BEFORE UPDATE` / `BEFORE DELETE`
//! triggers that abort the statement (`append_only.sqlite.sql`). There is no application flag those
//! triggers consult and no method on [`Store`] that issues an UPDATE or DELETE against them, so an
//! attempt to rewrite history fails in the engine rather than in a reviewer's attention.
//!
//! Payload decay is the one deletion the system performs, and it touches `payloads` only — a table
//! with no chain-bearing column. Deleting from it changes no signed byte, so chain verification is
//! unaffected by construction rather than by care (§04 §5.1).
//!
//! # What makes concurrent appends safe
//!
//! Every write runs inside `BEGIN IMMEDIATE`, which takes the write lock before the transaction
//! reads anything. A writer therefore cannot observe a head that another writer is about to move.
//! `PRIMARY KEY (stream, seq)` is the second line: even if the lock were lost, two envelopes cannot
//! occupy one chain position. The same pairing protects the gate replay set, whose PRIMARY KEY on
//! `request_hash` makes "used twice" impossible rather than unlikely.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use serde_json::{Map, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use stozher_core::error::{Error, Result};
use stozher_core::signed::KeyId;

use crate::codes;
use crate::keys::SigningKey;

/// The DDL every dialect shares.
const SCHEMA: &str = include_str!("sql/schema.sql");
/// The append-only enforcement, SQLite dialect. The one file to port to Postgres.
const APPEND_ONLY_SQLITE: &str = include_str!("sql/append_only.sqlite.sql");

/// What a stream carries. Effect streams and signal streams never mix (§07 §2.5).
pub const STREAM_KIND_EFFECT: &str = "effect";
/// A stream of inbound signal records.
pub const STREAM_KIND_SIGNAL: &str = "signal";

fn db(e: sqlx::Error) -> Error {
    Error::new(codes::STORE_UNAVAILABLE, e.to_string())
}

/// True when a database error is a uniqueness violation, whatever the dialect calls it.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(err) if err.is_unique_violation())
}

/// A stored envelope, with the ingest-time facts that are not inside the signed object.
#[derive(Debug, Clone)]
pub struct StoredEnvelope {
    /// `id()` of the envelope.
    pub id: String,
    /// The stream it belongs to.
    pub stream: String,
    /// Its position in that stream.
    pub seq: u64,
    /// `JCS(envelope)` verbatim, so signature verification is reproducible from what is stored.
    pub canonical_json: String,
    /// When the kernel received it, recorded separately from `emitted-at` (§09 §5).
    pub received_at: String,
    /// The human root the mandate walk reached, when the envelope cites a mandate.
    pub human_root: Option<String>,
    /// The class policy computed, which may differ from the emitter's proposal.
    pub effective_class: Option<String>,
    /// Set when the envelope records an effect policy did not permit (§05 §3 step 2).
    pub policy_violation: Option<String>,
}

impl StoredEnvelope {
    /// Reparse the stored canonical form.
    ///
    /// # Errors
    ///
    /// `jcs-malformed-json` if the stored bytes are not parseable, which would mean corruption.
    pub fn envelope(&self) -> Result<Value> {
        stozher_core::jcs::parse(&self.canonical_json)
    }
}

/// A projection the store must maintain when an envelope is appended.
///
/// These are folds of the log, never independent sources of truth: everything here is rebuildable
/// from `envelopes` alone (§02 §8).
#[derive(Debug, Clone, Default)]
pub struct Projections {
    /// A mandate granted by this envelope: `(mandate-id, mandate object)`.
    pub mandate: Option<(String, Value)>,
    /// A revocation recorded by this envelope: `(revocation-id, revocation object)`.
    pub revocation: Option<(String, Value)>,
    /// A policy version published by this envelope: `(version, document, document-hash)`.
    pub policy: Option<(String, Value, String)>,
    /// A manifest registered by this envelope: `(name, version, hash, component key, document)`.
    pub manifest: Option<(String, String, String, String, Value)>,
    /// A human root enrolled by this envelope: `(key, subject)`.
    pub enroll_root: Option<(String, String)>,
    /// A human root retired by this envelope.
    pub retire_root: Option<String>,
    /// A checkpoint attested by this envelope.
    pub checkpoint: Option<CheckpointRow>,
}

/// A checkpoint's attested range (§04 §4).
#[derive(Debug, Clone)]
pub struct CheckpointRow {
    /// The stream attested.
    pub stream: String,
    /// First `seq` in the range.
    pub from_seq: u64,
    /// Last `seq` in the range.
    pub to_seq: u64,
    /// `id()` of envelope `to_seq`.
    pub head_hash: String,
    /// When the head was observed.
    pub observed_at: String,
}

/// A payload submitted alongside an envelope (§04 §5.2).
#[derive(Debug, Clone)]
pub struct PayloadRow {
    /// `object-hash` of the payload, already verified against the envelope's commitment.
    pub payload_hash: String,
    /// IANA media type.
    pub media_type: String,
    /// The octets to store.
    pub bytes: Vec<u8>,
    /// The deletion deadline, already clamped to the policy ceiling.
    pub retain_until: String,
}

/// An approval consumed by this envelope, recorded so it cannot be consumed twice (§06 §3).
#[derive(Debug, Clone)]
pub struct GateUse {
    /// `object-hash` of the action request the approval covers.
    pub request_hash: String,
    /// The approver's key.
    pub decided_by: String,
    /// Whether the approval was single-use.
    pub single_use: bool,
    /// When the approval stops being usable.
    pub not_after: String,
}

/// Everything ingest computed, ready to be committed as one unit.
#[derive(Debug, Clone)]
pub struct AppendPlan {
    /// The envelope, as received.
    pub envelope: Value,
    /// `id()` of it.
    pub id: String,
    /// `JCS(envelope)`.
    pub canonical_json: String,
    /// Whether this stream carries effects or inbound signals.
    pub stream_kind: &'static str,
    /// Kernel arrival time.
    pub received_at: String,
    /// The human root the mandate walk reached.
    pub human_root: Option<String>,
    /// The class policy computed.
    pub effective_class: Option<String>,
    /// Set when the record is a confession that policy was not honoured.
    pub policy_violation: Option<String>,
    /// Payloads to store.
    pub payloads: Vec<PayloadRow>,
    /// The approval this envelope consumes.
    pub gate_use: Option<GateUse>,
    /// Folds to maintain.
    pub projections: Projections,
}

/// The outcome of an append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// `id()` of the appended envelope.
    pub id: String,
    /// Stream it landed in.
    pub stream: String,
    /// Position it took.
    pub seq: u64,
    /// True when this exact envelope was already present and nothing was written (§04 §3).
    pub idempotent: bool,
}

/// The facts a rejection record must carry (§04 §7).
#[derive(Debug, Clone)]
pub struct RejectionInput {
    /// The normative reason code.
    pub reason: String,
    /// Human-readable detail. Never contractual, and never a payload or key.
    pub detail: String,
    /// `object-hash` of the rejected bytes as received, or their SHA-256 when they are not JSON.
    pub object_hash: String,
    /// The submitting connection's authenticated subject, if any.
    pub submitted_by: Option<String>,
    /// When the kernel received the rejected bytes.
    pub received_at: String,
    /// The stream the rejected object claimed, for investigation.
    pub claimed_stream: Option<String>,
    /// The position it claimed.
    pub claimed_seq: Option<u64>,
    /// The kind it claimed.
    pub claimed_kind: Option<String>,
}

/// A recorded rejection.
#[derive(Debug, Clone)]
pub struct RejectionRecord {
    /// `id()` of the signed rejection record.
    pub id: String,
    /// Its position in the kernel's rejection stream.
    pub seq: u64,
    /// The reason code.
    pub reason: String,
}

/// The store.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    rejection_stream: String,
}

impl Store {
    /// Open (creating if absent) and migrate a store at `path`.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`] on any database failure.
    pub async fn open(path: &Path, rejection_stream: &str) -> Result<Self> {
        // SQLite creates the file but not the directory holding it, and the failure it reports for a
        // missing directory ("unable to open database file") sends an operator looking at
        // permissions. Create the directory instead of explaining the error.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    codes::STORE_UNAVAILABLE,
                    format!("cannot create {}: {e}", parent.display()),
                )
            })?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(30));
        Self::connect(options, rejection_stream).await
    }

    /// Open an in-memory store, for tests.
    ///
    /// The database is named and shared-cache: a bare `:memory:` gives every pooled connection its
    /// own empty database, so the schema would appear to vanish on the second connection. The name
    /// is unique per call so two stores in one process do not see each other's rows.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`] on any database failure.
    pub async fn open_memory(rejection_stream: &str) -> Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ordinal = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let uri = format!(
            "sqlite:file:stozher-test-{}-{ordinal}?mode=memory&cache=shared",
            std::process::id()
        );
        let options = SqliteConnectOptions::from_str(&uri)
            .map_err(db)?
            .busy_timeout(Duration::from_secs(30))
            .foreign_keys(true);
        Self::connect(options, rejection_stream).await
    }

    async fn connect(options: SqliteConnectOptions, rejection_stream: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            // An in-memory database lives only as long as a connection to it does.
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await
            .map_err(db)?;
        sqlx::raw_sql(SCHEMA).execute(&pool).await.map_err(db)?;
        sqlx::raw_sql(APPEND_ONLY_SQLITE)
            .execute(&pool)
            .await
            .map_err(db)?;
        Ok(Self {
            pool,
            rejection_stream: rejection_stream.to_owned(),
        })
    }

    /// The kernel's rejection stream name.
    #[must_use]
    pub fn rejection_stream(&self) -> &str {
        &self.rejection_stream
    }

    // -- reads ------------------------------------------------------------------------------

    /// Look an envelope up by `id()`.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn envelope_by_id(&self, id: &str) -> Result<Option<StoredEnvelope>> {
        let row = sqlx::query(
            "SELECT id, stream, seq, canonical_json, received_at, human_root, effective_class, \
             policy_violation FROM envelopes WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.as_ref().map(stored_from_row))
    }

    /// The head of a stream: `(seq, id)`, or `None` for an empty stream.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn stream_head(&self, stream: &str) -> Result<Option<(u64, String)>> {
        let row = sqlx::query(
            "SELECT seq, id FROM envelopes WHERE stream = ?1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(stream)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| (as_u64(&r, "seq"), r.get::<String, _>("id"))))
    }

    /// The declared kind of a stream, if it has been written to.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn stream_kind(&self, stream: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT stream_kind FROM streams WHERE stream = ?1")
            .bind(stream)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        Ok(row.map(|r| r.get::<String, _>("stream_kind")))
    }

    /// Every stream, with its head and last append time — the quiet-stream surface of §09 §4.2.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn streams(&self) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT stream, stream_kind, head_seq, head_hash, first_seen_at, last_appended_at \
             FROM streams ORDER BY stream",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "stream": r.get::<String, _>("stream"),
                    "stream-kind": r.get::<String, _>("stream_kind"),
                    "head-seq": as_u64(r, "head_seq"),
                    "head-hash": r.get::<String, _>("head_hash"),
                    "first-seen-at": r.get::<String, _>("first_seen_at"),
                    "last-appended-at": r.get::<String, _>("last_appended_at"),
                })
            })
            .collect())
    }

    /// A contiguous range of one stream, in chain order, as parsed envelopes.
    ///
    /// This is the input to chain verification, and it reads no payload (§04 §5.1).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn range(&self, stream: &str, from_seq: u64, to_seq: u64) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT canonical_json FROM envelopes WHERE stream = ?1 AND seq >= ?2 AND seq <= ?3 \
             ORDER BY seq",
        )
        .bind(stream)
        .bind(i64::try_from(from_seq).unwrap_or(i64::MAX))
        .bind(i64::try_from(to_seq).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| stozher_core::jcs::parse(&r.get::<String, _>("canonical_json")))
            .collect()
    }

    /// Total envelopes in the store.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn envelope_count(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM envelopes")
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        Ok(as_u64(&row, "n"))
    }

    /// The enrolled human root keys as of `at`, with their subjects (§03 §6).
    ///
    /// Retirement is not retroactive: a root retired after `at` still counts at `at`
    /// (`root-retirement-is-not-retroactive`).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn roots_at(&self, at: &str) -> Result<Vec<(KeyId, String)>> {
        let rows = sqlx::query(
            "SELECT root_key, subject FROM roots WHERE enrolled_at <= ?1 \
             AND (retired_at IS NULL OR retired_at > ?1) ORDER BY root_key",
        )
        .bind(at)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                KeyId::parse(&r.get::<String, _>("root_key"))
                    .map(|key| (key, r.get::<String, _>("subject")))
            })
            .collect()
    }

    /// The mandate chain reachable from `leaf_ref` by `parent` links, bounded by `max_links`.
    ///
    /// Loading the ancestry rather than every mandate keeps verification O(depth): the walk of
    /// §03 §5 only ever needs the leaf and its ancestors, and a revocation of an ancestor still
    /// propagates downward because every link on the path is present.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn mandate_ancestry(
        &self,
        leaf_ref: &str,
        max_links: u32,
    ) -> Result<Map<String, Value>> {
        let mut chain = Map::new();
        let mut cursor = Some(leaf_ref.to_owned());
        // One extra hop so the walk can see the parent that puts it over the bound and report
        // `mandate-delegation-depth-exceeded` rather than `mandate-unresolved`.
        for _ in 0..=max_links.saturating_add(2) {
            let Some(id) = cursor.take() else { break };
            if chain.contains_key(&id) {
                break;
            }
            let Some(row) =
                sqlx::query("SELECT document_json, parent FROM mandates WHERE mandate_id = ?1")
                    .bind(&id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db)?
            else {
                break;
            };
            let document = stozher_core::jcs::parse(&row.get::<String, _>("document_json"))?;
            chain.insert(id, document);
            cursor = row.get::<Option<String>, _>("parent");
        }
        Ok(chain)
    }

    /// Every revocation targeting any mandate in `ids`.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn revocations_targeting(&self, ids: &[String]) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        for id in ids {
            let rows = sqlx::query("SELECT document_json FROM revocations WHERE revokes = ?1")
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?;
            for row in &rows {
                out.push(stozher_core::jcs::parse(
                    &row.get::<String, _>("document_json"),
                )?);
            }
        }
        Ok(out)
    }

    /// Every revocation in force, with the epoch that identifies the set.
    ///
    /// The epoch is `sha256` over the sorted revocation ids. It is not a counter: a counter would
    /// have to be stored, and a stored counter can disagree with the rows it counts. A hash of the
    /// set is recomputed from the set, so "the epoch changed" and "the set changed" are the same
    /// statement. A poller that holds the epoch can be answered `304 Not Modified` without the
    /// documents being read at all (§03 §5 keys the verification cache on exactly this value).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn revocation_feed(&self) -> Result<(String, Vec<Value>)> {
        let rows = sqlx::query(
            "SELECT revocation_id, document_json FROM revocations ORDER BY revocation_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut ids = String::new();
        let mut documents = Vec::with_capacity(rows.len());
        for row in &rows {
            ids.push_str(&row.get::<String, _>("revocation_id"));
            ids.push('\n');
            documents.push(stozher_core::jcs::parse(
                &row.get::<String, _>("document_json"),
            )?);
        }
        Ok((stozher_core::crypto::sha256_hex(ids.as_bytes()), documents))
    }

    /// The mandate registry: every granted mandate, with the instant it was revoked if it was.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn mandate_registry(&self) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT m.mandate_id, m.parent, m.mandate_kind, m.grantee_subject, m.not_before, \
             m.not_after, m.document_json, m.envelope_id, \
             (SELECT MIN(r.revoked_at) FROM revocations r WHERE r.revokes = m.mandate_id) \
             AS revoked_at FROM mandates m ORDER BY m.not_after",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                let document = stozher_core::jcs::parse(&r.get::<String, _>("document_json"))?;
                Ok(serde_json::json!({
                    "mandate-id": r.get::<String, _>("mandate_id"),
                    "parent": r.get::<Option<String>, _>("parent"),
                    "mandate-kind": r.get::<String, _>("mandate_kind"),
                    "grantor": document["grantor"],
                    "grantee-subject": r.get::<String, _>("grantee_subject"),
                    "not-before": r.get::<String, _>("not_before"),
                    "not-after": r.get::<String, _>("not_after"),
                    "scope": document["scope"],
                    "envelope-id": r.get::<String, _>("envelope_id"),
                    "revoked-at": r.get::<Option<String>, _>("revoked_at"),
                }))
            })
            .collect()
    }

    /// A mandate object by id.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn mandate(&self, id: &str) -> Result<Option<Value>> {
        let row = sqlx::query("SELECT document_json FROM mandates WHERE mandate_id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| stozher_core::jcs::parse(&r.get::<String, _>("document_json")))
            .transpose()
    }

    /// A mandate and every mandate delegated beneath it (§04 §6, "the transitive set").
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn mandate_subtree(&self, root: &str) -> Result<Vec<String>> {
        let mut found = BTreeSet::new();
        found.insert(root.to_owned());
        let mut frontier = vec![root.to_owned()];
        while let Some(parent) = frontier.pop() {
            let rows = sqlx::query("SELECT mandate_id FROM mandates WHERE parent = ?1")
                .bind(&parent)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?;
            for row in &rows {
                let child: String = row.get("mandate_id");
                if found.insert(child.clone()) {
                    frontier.push(child);
                }
            }
        }
        Ok(found.into_iter().collect())
    }

    /// Mandates held by a human subject and valid at `at`, for approver resolution (§06 §5).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn mandates_held_by(&self, subject: &str, at: &str) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT document_json FROM mandates WHERE grantee_subject = ?1 \
             AND not_before <= ?2 AND not_after >= ?2",
        )
        .bind(subject)
        .bind(at)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| stozher_core::jcs::parse(&r.get::<String, _>("document_json")))
            .collect()
    }

    /// The transitions of a durable object, in chain order (§02 §8, §04 §6).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn durable_transitions(
        &self,
        object_type: &str,
        object_id: &str,
    ) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT commitment_transition, subject FROM envelopes \
             WHERE commitment_type = ?1 AND commitment_id = ?2 ORDER BY stream, seq",
        )
        .bind(object_type)
        .bind(object_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<Option<String>, _>("commitment_transition")
                        .unwrap_or_default(),
                    r.get::<String, _>("subject"),
                )
            })
            .collect())
    }

    /// Whether a green conformance run has been recorded for a manifest hash (§08 §3.3).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn conformance_run_is_green(&self, manifest_hash: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 AS present FROM envelopes WHERE action = 'kernel.conformance_run' \
             AND outcome = 'applied' AND args_hash = ?1 LIMIT 1",
        )
        .bind(manifest_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.is_some())
    }

    /// Whether an approval covering `request_hash` has already been consumed (§06 §2 step 11).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn gate_request_seen(&self, request_hash: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 AS present FROM gate_request_hashes WHERE request_hash = ?1 AND single_use = 1",
        )
        .bind(request_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.is_some())
    }

    /// The policy in force: the most recently published version.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn current_policy(&self) -> Result<Option<Value>> {
        let row = sqlx::query("SELECT document_json FROM policies ORDER BY ordinal DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| stozher_core::jcs::parse(&r.get::<String, _>("document_json")))
            .transpose()
    }

    /// A specific policy version, which resolves forever once published (§05 §2.2).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn policy_version(&self, version: &str) -> Result<Option<Value>> {
        let row = sqlx::query("SELECT document_json FROM policies WHERE policy_version = ?1")
            .bind(version)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| stozher_core::jcs::parse(&r.get::<String, _>("document_json")))
            .transpose()
    }

    /// Whether a policy version has ever been published (`policy-version-reused`).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn policy_version_exists(&self, version: &str) -> Result<bool> {
        let row = sqlx::query("SELECT 1 AS present FROM policies WHERE policy_version = ?1")
            .bind(version)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        Ok(row.is_some())
    }

    /// The most recently registered manifest for a component.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn latest_manifest(&self, name: &str) -> Result<Option<Value>> {
        let row = sqlx::query(
            "SELECT document_json FROM manifests WHERE name = ?1 ORDER BY ordinal DESC LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|r| stozher_core::jcs::parse(&r.get::<String, _>("document_json")))
            .transpose()
    }

    /// The key a component name is already bound to (`manifest-name-key-conflict`).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn manifest_component_key(&self, name: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT component_key FROM manifests WHERE name = ?1 ORDER BY ordinal LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| r.get::<String, _>("component_key")))
    }

    /// Whether a specific manifest version is already registered.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn manifest_version_exists(&self, name: &str, version: &str) -> Result<bool> {
        let row =
            sqlx::query("SELECT 1 AS present FROM manifests WHERE name = ?1 AND version = ?2")
                .bind(name)
                .bind(version)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        Ok(row.is_some())
    }

    /// A stored payload, or `None` if it has decayed.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn payload(&self, payload_hash: &str) -> Result<Option<(String, Vec<u8>)>> {
        let row = sqlx::query("SELECT media_type, bytes FROM payloads WHERE payload_hash = ?1")
            .bind(payload_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        Ok(row.map(|r| {
            (
                r.get::<String, _>("media_type"),
                r.get::<Vec<u8>, _>("bytes"),
            )
        }))
    }

    /// The last checkpoint recorded for a stream, if any (§04 §4.4 contiguity).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn last_checkpoint(&self, stream: &str) -> Result<Option<(u64, u64, String)>> {
        let row = sqlx::query(
            "SELECT from_seq, to_seq, head_hash FROM checkpoints WHERE stream = ?1 \
             ORDER BY to_seq DESC LIMIT 1",
        )
        .bind(stream)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| {
            (
                as_u64(&r, "from_seq"),
                as_u64(&r, "to_seq"),
                r.get::<String, _>("head_hash"),
            )
        }))
    }

    /// Rejection records, newest first (§04 §7: they must be visible).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn rejections(&self, reason: Option<&str>, limit: i64) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT seq, id, prev_hash, reason, detail, object_hash, submitted_by, received_at, \
             claimed_stream, claimed_seq, claimed_kind FROM rejections \
             WHERE (?1 IS NULL OR reason = ?1) ORDER BY seq DESC LIMIT ?2",
        )
        .bind(reason)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "seq": as_u64(r, "seq"),
                    "id": r.get::<String, _>("id"),
                    "prev-hash": r.get::<Option<String>, _>("prev_hash"),
                    "reason": r.get::<String, _>("reason"),
                    "detail": r.get::<String, _>("detail"),
                    "object-hash": r.get::<String, _>("object_hash"),
                    "submitted-by": r.get::<Option<String>, _>("submitted_by"),
                    "received-at": r.get::<String, _>("received_at"),
                    "claimed-stream": r.get::<Option<String>, _>("claimed_stream"),
                    "claimed-seq": r.get::<Option<i64>, _>("claimed_seq"),
                    "claimed-kind": r.get::<Option<String>, _>("claimed_kind"),
                })
            })
            .collect())
    }

    /// The rejection stream as signed chained records, for chain verification.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn rejection_chain(&self) -> Result<Vec<Value>> {
        let rows = sqlx::query("SELECT record_json FROM rejections ORDER BY seq")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| stozher_core::jcs::parse(&r.get::<String, _>("record_json")))
            .collect()
    }

    /// Query envelopes by the indexed dimensions of §04 §6.
    ///
    /// The predicate is built from the filters that are actually set, so each query can use an
    /// index instead of a full scan behind a wall of `?n IS NULL OR` disjunctions.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn query(&self, filter: &EnvelopeQuery<'_>) -> Result<Vec<Value>> {
        let mut sql = String::from(
            "SELECT id, stream, seq, canonical_json, received_at, human_root, effective_class, \
             policy_violation FROM envelopes",
        );
        let mut binds: Vec<String> = Vec::new();
        let mut clauses: Vec<String> = Vec::new();

        let mut equals = |column: &str, value: Option<&str>| {
            if let Some(value) = value {
                binds.push(value.to_owned());
                clauses.push(format!("{column} = ?{}", binds.len()));
            }
        };
        equals("subject", filter.subject);
        equals("mandate_ref", filter.mandate_ref);
        equals("effective_class", filter.classification);
        equals("kind", filter.kind);
        equals("action", filter.action);
        equals("component", filter.component);
        equals("stream", filter.stream);
        equals("correlation_ref", filter.correlation_ref);
        equals("commitment_id", filter.commitment_id);
        equals("outcome", filter.outcome);
        equals("human_root", filter.human_root);
        if let Some(from) = filter.emitted_from {
            binds.push(from.to_owned());
            clauses.push(format!("emitted_at >= ?{}", binds.len()));
        }
        if let Some(to) = filter.emitted_to {
            binds.push(to.to_owned());
            clauses.push(format!("emitted_at <= ?{}", binds.len()));
        }
        if let Some(prefix) = filter.correlation_prefix {
            // `correlation-ref` is opaque and never interpreted (§02 §10); a prefix query is a
            // string operation on it, not an attempt to understand its structure.
            binds.push(format!("{}%", like_escape(prefix)));
            clauses.push(format!("correlation_ref LIKE ?{} ESCAPE '\\'", binds.len()));
        }
        if filter.violations_only {
            clauses.push("policy_violation IS NOT NULL".to_owned());
        }
        if let Some(root) = filter.mandate_subtree_of {
            let subtree = self.mandate_subtree(root).await?;
            let mut placeholders = Vec::with_capacity(subtree.len());
            for id in subtree {
                binds.push(id);
                placeholders.push(format!("?{}", binds.len()));
            }
            clauses.push(format!("mandate_ref IN ({})", placeholders.join(", ")));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY emitted_at DESC, stream, seq DESC LIMIT ");
        sql.push_str(&filter.limit.clamp(1, 10_000).to_string());

        // Audited for injection as `SqlSafeStr` requires: every fragment appended above is a
        // literal, and every value reaches the statement through `bind`. The only interpolated
        // non-literals are `?n` placeholder indices and a clamped integer row cap.
        let mut statement = sqlx::query(sqlx::AssertSqlSafe(sql));
        for bind in &binds {
            statement = statement.bind(bind);
        }
        let rows = statement.fetch_all(&self.pool).await.map_err(db)?;
        rows.iter()
            .map(|r| {
                let stored = stored_from_row(r);
                let envelope = stored.envelope()?;
                Ok(serde_json::json!({
                    "id": stored.id,
                    "received-at": stored.received_at,
                    "human-root": stored.human_root,
                    "effective-class": stored.effective_class,
                    "policy-violation": stored.policy_violation,
                    "envelope": envelope,
                }))
            })
            .collect()
    }

    // -- the single write path ------------------------------------------------------------

    /// Append an envelope, enforcing chain position, idempotency and replay atomically.
    ///
    /// This is the **only** method that inserts into `envelopes`. There is no variant that skips a
    /// check, no parameter that suppresses one, and no administrative sibling: an envelope reaches
    /// the chain through [`crate::ingest::Ingest::submit`] and through nothing else (§06 §2).
    ///
    /// # Errors
    ///
    /// `chain-seq-gap`, `chain-seq-duplicate`, `chain-prev-hash-mismatch`,
    /// `chain-genesis-prev-not-null`, `stream-kind-mixed`, `gate-authorization-replayed`,
    /// `policy-version-reused`, `checkpoint-range-discontinuous`, or
    /// [`codes::STORE_UNAVAILABLE`].
    pub(crate) async fn append(&self, plan: &AppendPlan) -> Result<Appended> {
        let stream = plan.envelope["stream"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let seq = plan.envelope["seq"].as_u64().unwrap_or_default();

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;

        // Idempotency by id() comes first: re-submitting a byte-identical envelope must succeed
        // without a second row and, crucially, without tripping the replay check below (§04 §3).
        let existing = sqlx::query("SELECT stream, seq FROM envelopes WHERE id = ?1")
            .bind(&plan.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        if let Some(row) = existing {
            tx.rollback().await.map_err(db)?;
            return Ok(Appended {
                id: plan.id.clone(),
                stream: row.get("stream"),
                seq: as_u64(&row, "seq"),
                idempotent: true,
            });
        }

        // One writer per stream, and a stream never mixes effects with inbound signals (§07 §2.5).
        let declared_kind = sqlx::query("SELECT stream_kind FROM streams WHERE stream = ?1")
            .bind(&stream)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .map(|r| r.get::<String, _>("stream_kind"));
        if let Some(kind) = &declared_kind {
            if kind != plan.stream_kind {
                tx.rollback().await.map_err(db)?;
                return Err(Error::new(
                    "stream-kind-mixed",
                    format!(
                        "stream {stream} carries {kind} records, not {}",
                        plan.stream_kind
                    ),
                ));
            }
        }

        // Chain position, read under the write lock so no other writer can move the head between
        // the read and the insert.
        let head = sqlx::query(
            "SELECT seq, id FROM envelopes WHERE stream = ?1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(&stream)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .map(|r| (as_u64(&r, "seq"), r.get::<String, _>("id")));

        let claimed_prev = plan.envelope["prev-hash"].as_str();
        let position = match &head {
            None => {
                if seq != 0 {
                    tx.rollback().await.map_err(db)?;
                    return Err(Error::new(
                        "chain-seq-gap",
                        format!("stream {stream} is empty, so the first envelope must be seq 0, not {seq}"),
                    )
                    .at_seq(seq));
                }
                if claimed_prev.is_some() {
                    tx.rollback().await.map_err(db)?;
                    return Err(Error::new(
                        "chain-genesis-prev-not-null",
                        "seq 0 must carry prev-hash null",
                    )
                    .at_seq(seq));
                }
                Ok(())
            }
            Some((head_seq, head_id)) => {
                if seq <= *head_seq {
                    Err(Error::new(
                        "chain-seq-duplicate",
                        format!(
                            "stream {stream} is already at seq {head_seq}; {seq} is in the past"
                        ),
                    )
                    .at_seq(seq))
                } else if seq > head_seq + 1 {
                    // An emitter must not be able to reserve future positions (§04 §3).
                    Err(Error::new(
                        "chain-seq-gap",
                        format!("stream {stream} is at seq {head_seq}; {seq} would leave a gap"),
                    )
                    .at_seq(seq))
                } else if claimed_prev != Some(head_id.as_str()) {
                    Err(Error::new(
                        "chain-prev-hash-mismatch",
                        format!(
                            "prev-hash {} does not match the head {head_id}",
                            claimed_prev.unwrap_or("null")
                        ),
                    )
                    .at_seq(seq))
                } else {
                    Ok(())
                }
            }
        };
        if let Err(e) = position {
            tx.rollback().await.map_err(db)?;
            return Err(e);
        }

        // The replay set. The PRIMARY KEY does the enforcing, so two concurrent submissions of one
        // approval cannot both succeed no matter how their pre-checks raced.
        if let Some(gate_use) = &plan.gate_use {
            let inserted = sqlx::query(
                "INSERT INTO gate_request_hashes \
                 (request_hash, envelope_id, decided_by, single_use, not_after, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&gate_use.request_hash)
            .bind(&plan.id)
            .bind(&gate_use.decided_by)
            .bind(i64::from(gate_use.single_use))
            .bind(&gate_use.not_after)
            .bind(&plan.received_at)
            .execute(&mut *tx)
            .await;
            match inserted {
                Ok(_) => {}
                Err(e) if is_unique_violation(&e) => {
                    // Only single-use approvals may not be reused; a standing one is expected to
                    // appear again and its existing row is simply left alone.
                    let single_use_before = sqlx::query(
                        "SELECT single_use FROM gate_request_hashes WHERE request_hash = ?1",
                    )
                    .bind(&gate_use.request_hash)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db)?
                    .map(|r| r.get::<i64, _>("single_use") == 1)
                    .unwrap_or(true);
                    if single_use_before || gate_use.single_use {
                        tx.rollback().await.map_err(db)?;
                        return Err(Error::new(
                            "gate-authorization-replayed",
                            format!("request {} was already used", gate_use.request_hash),
                        ));
                    }
                }
                Err(e) => {
                    tx.rollback().await.map_err(db)?;
                    return Err(db(e));
                }
            }
        }

        let identity = &plan.envelope["identity"];
        let execution = plan.envelope.get("execution");
        let commitment = plan.envelope.get("commitment-ref");
        let insert = sqlx::query(
            "INSERT INTO envelopes (stream, seq, id, prev_hash, kind, subject, subject_key, \
             component, mandate_ref, human_root, policy_version, classification, effective_class, \
             action, target, args_hash, outcome, emitted_at, received_at, correlation_ref, \
             commitment_type, commitment_id, commitment_transition, policy_violation, \
             canonical_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
             ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
        )
        .bind(&stream)
        .bind(i64::try_from(seq).unwrap_or(i64::MAX))
        .bind(&plan.id)
        .bind(claimed_prev)
        .bind(plan.envelope["kind"].as_str())
        .bind(identity["subject"].as_str())
        .bind(identity["key"].as_str())
        .bind(identity["component"].as_str())
        .bind(plan.envelope["mandate-ref"].as_str())
        .bind(plan.human_root.as_deref())
        .bind(plan.envelope["policy-version"].as_str())
        .bind(plan.envelope["classification"].as_str())
        .bind(plan.effective_class.as_deref())
        .bind(execution.and_then(|e| e["action"].as_str()))
        .bind(execution.and_then(|e| e["target"].as_str()))
        .bind(execution.and_then(|e| e["args-hash"].as_str()))
        .bind(execution.and_then(|e| e["outcome"].as_str()))
        .bind(plan.envelope["emitted-at"].as_str())
        .bind(&plan.received_at)
        .bind(plan.envelope["correlation-ref"].as_str())
        .bind(commitment.and_then(|c| c["object-type"].as_str()))
        .bind(commitment.and_then(|c| c["object-id"].as_str()))
        .bind(commitment.and_then(|c| c["transition"].as_str()))
        .bind(plan.policy_violation.as_deref())
        .bind(&plan.canonical_json)
        .execute(&mut *tx)
        .await;
        if let Err(e) = insert {
            let mapped = if is_unique_violation(&e) {
                Error::new(
                    "chain-seq-duplicate",
                    format!("({stream}, {seq}) is already occupied"),
                )
                .at_seq(seq)
            } else {
                db(e)
            };
            tx.rollback().await.map_err(db)?;
            return Err(mapped);
        }

        // Payloads. Deduplicated by hash; the reference row is what keeps them alive (§04 §5.2).
        for payload in &plan.payloads {
            sqlx::query(
                "INSERT INTO payloads (payload_hash, media_type, bytes, first_seen_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (payload_hash) DO NOTHING",
            )
            .bind(&payload.payload_hash)
            .bind(&payload.media_type)
            .bind(&payload.bytes)
            .bind(&plan.received_at)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            sqlx::query(
                "INSERT INTO payload_refs (payload_hash, envelope_id, stream, retain_until) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (payload_hash, envelope_id) DO NOTHING",
            )
            .bind(&payload.payload_hash)
            .bind(&plan.id)
            .bind(&stream)
            .bind(&payload.retain_until)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }

        if let Err(e) = self.write_projections(&mut tx, plan, &stream, seq).await {
            tx.rollback().await.map_err(db)?;
            return Err(e);
        }

        // `streams` is a rebuildable projection — a cache of the head plus the stream's kind. It is
        // deliberately not append-only: chain verification recomputes the head from `envelopes`, so
        // this row is a convenience for the quiet-stream surface, never an authority.
        sqlx::query(
            "INSERT INTO streams (stream, stream_kind, head_seq, head_hash, first_seen_at, \
             last_appended_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5) \
             ON CONFLICT (stream) DO UPDATE SET head_seq = ?3, head_hash = ?4, last_appended_at = ?5",
        )
        .bind(&stream)
        .bind(plan.stream_kind)
        .bind(i64::try_from(seq).unwrap_or(i64::MAX))
        .bind(&plan.id)
        .bind(&plan.received_at)
        .execute(&mut *tx)
        .await
        .map_err(db)?;

        tx.commit().await.map_err(db)?;
        Ok(Appended {
            id: plan.id.clone(),
            stream,
            seq,
            idempotent: false,
        })
    }

    async fn write_projections(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        plan: &AppendPlan,
        stream: &str,
        seq: u64,
    ) -> Result<()> {
        let projections = &plan.projections;
        if let Some((id, mandate)) = &projections.mandate {
            sqlx::query(
                "INSERT INTO mandates (mandate_id, parent, mandate_kind, grantor_key, grantee_key, \
                 grantee_subject, not_before, not_after, document_json, envelope_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT (mandate_id) DO NOTHING",
            )
            .bind(id)
            .bind(mandate["parent"].as_str())
            .bind(mandate["mandate-kind"].as_str())
            .bind(mandate["grantor"]["key"].as_str())
            .bind(mandate["grantee"]["key"].as_str())
            .bind(mandate["grantee"]["subject"].as_str())
            .bind(mandate["not-before"].as_str())
            .bind(mandate["not-after"].as_str())
            .bind(stozher_core::jcs::canonicalize(mandate)?)
            .bind(&plan.id)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        }
        if let Some((id, revocation)) = &projections.revocation {
            // Revocation is idempotent and the earliest valid instant wins (§03 §7), which the
            // revocation index computes from the rows; a repeat insert is simply a no-op.
            sqlx::query(
                "INSERT INTO revocations (revocation_id, revokes, revoked_at, document_json, \
                 envelope_id) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (revocation_id) DO NOTHING",
            )
            .bind(id)
            .bind(revocation["revokes"].as_str())
            .bind(revocation["revoked-at"].as_str())
            .bind(stozher_core::jcs::canonicalize(revocation)?)
            .bind(&plan.id)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        }
        if let Some((version, document, hash)) = &projections.policy {
            let ordinal = next_counter(tx, "policy-ordinal").await?;
            let inserted = sqlx::query(
                "INSERT INTO policies (policy_version, document_hash, document_json, published_by, \
                 envelope_id, published_at, ordinal) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(version)
            .bind(hash)
            .bind(stozher_core::jcs::canonicalize(document)?)
            .bind(plan.envelope["identity"]["subject"].as_str())
            .bind(&plan.id)
            .bind(&plan.received_at)
            .bind(ordinal)
            .execute(&mut **tx)
            .await;
            if let Err(e) = inserted {
                return Err(if is_unique_violation(&e) {
                    Error::new(
                        "policy-version-reused",
                        format!("policy version {version} has already been published"),
                    )
                } else {
                    db(e)
                });
            }
        }
        if let Some((name, version, hash, component_key, document)) = &projections.manifest {
            let ordinal = next_counter(tx, "manifest-ordinal").await?;
            let inserted = sqlx::query(
                "INSERT INTO manifests (name, version, manifest_hash, component_key, \
                 document_json, envelope_id, registered_at, ordinal) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(name)
            .bind(version)
            .bind(hash)
            .bind(component_key)
            .bind(stozher_core::jcs::canonicalize(document)?)
            .bind(&plan.id)
            .bind(&plan.received_at)
            .bind(ordinal)
            .execute(&mut **tx)
            .await;
            if let Err(e) = inserted {
                return Err(if is_unique_violation(&e) {
                    Error::new(
                        "manifest-version-retained",
                        format!("manifest {name} {version} is already registered"),
                    )
                } else {
                    db(e)
                });
            }
        }
        if let Some((key, subject)) = &projections.enroll_root {
            sqlx::query(
                "INSERT INTO roots (root_key, subject, enrolled_at, retired_at, envelope_id) \
                 VALUES (?1, ?2, ?3, NULL, ?4) ON CONFLICT (root_key) DO NOTHING",
            )
            .bind(key)
            .bind(subject)
            .bind(plan.envelope["emitted-at"].as_str())
            .bind(&plan.id)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        }
        if let Some(key) = &projections.retire_root {
            // Retirement is not retroactive: the row keeps `enrolled_at` so historical envelopes
            // still verify (`root-retirement-is-not-retroactive`, §03 §8).
            sqlx::query(
                "UPDATE roots SET retired_at = ?2 WHERE root_key = ?1 AND retired_at IS NULL",
            )
            .bind(key)
            .bind(plan.envelope["emitted-at"].as_str())
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        }
        if let Some(checkpoint) = &projections.checkpoint {
            let previous = sqlx::query(
                "SELECT to_seq FROM checkpoints WHERE stream = ?1 ORDER BY to_seq DESC LIMIT 1",
            )
            .bind(&checkpoint.stream)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .map(|r| as_u64(&r, "to_seq"));
            let expected_from = previous.map_or(0, |to| to + 1);
            if checkpoint.from_seq != expected_from {
                return Err(Error::new(
                    "checkpoint-range-discontinuous",
                    format!(
                        "checkpoint of {} starts at {}, expected {expected_from}",
                        checkpoint.stream, checkpoint.from_seq
                    ),
                ));
            }
            let inserted = sqlx::query(
                "INSERT INTO checkpoints (stream, from_seq, to_seq, head_hash, envelope_id, \
                 observed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&checkpoint.stream)
            .bind(i64::try_from(checkpoint.from_seq).unwrap_or(i64::MAX))
            .bind(i64::try_from(checkpoint.to_seq).unwrap_or(i64::MAX))
            .bind(&checkpoint.head_hash)
            .bind(&plan.id)
            .bind(&checkpoint.observed_at)
            .execute(&mut **tx)
            .await;
            if let Err(e) = inserted {
                return Err(if is_unique_violation(&e) {
                    Error::new(
                        "checkpoint-range-discontinuous",
                        format!(
                            "a checkpoint of {} already starts at {}",
                            checkpoint.stream, checkpoint.from_seq
                        ),
                    )
                } else {
                    db(e)
                });
            }
        }
        let _ = (stream, seq);
        Ok(())
    }

    /// Record a rejection in the kernel's own chained rejection stream (§04 §7).
    ///
    /// A rejection record is **not** an envelope: §02 §2 is a closed `kind` vocabulary with no
    /// member for one. It is a signed, chained object of its own shape, written to its own table, so
    /// this method structurally cannot put anything into `envelopes` — which is what keeps "record
    /// the rejection" from becoming a second way in.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or a canonicalization failure.
    pub async fn record_rejection(
        &self,
        signer: &SigningKey,
        input: &RejectionInput,
    ) -> Result<RejectionRecord> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let head = sqlx::query(
            "SELECT seq, id FROM rejections WHERE stream = ?1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(&self.rejection_stream)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .map(|r| (as_u64(&r, "seq"), r.get::<String, _>("id")));
        let (seq, prev_hash) = match head {
            Some((head_seq, head_id)) => (head_seq + 1, Some(head_id)),
            None => (0, None),
        };

        let body = serde_json::json!({
            "v": stozher_core::VERSION,
            "kind": "rejection",
            "stream": self.rejection_stream,
            "seq": seq,
            "prev-hash": prev_hash,
            "reason": input.reason,
            "detail": input.detail,
            "object-hash": input.object_hash,
            "submitted-by": input.submitted_by,
            "received-at": input.received_at,
            "identity": {
                "subject": "agent:kernel",
                "key": signer.id().as_str(),
                "component": "kernel"
            },
        });
        let record = signer.sign(&body)?;
        let canonical = stozher_core::jcs::canonicalize(&record)?;
        let id = stozher_core::signed::object_id(&record)?;

        sqlx::query(
            "INSERT INTO rejections (stream, seq, id, prev_hash, reason, detail, object_hash, \
             submitted_by, received_at, claimed_stream, claimed_seq, claimed_kind, record_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )
        .bind(&self.rejection_stream)
        .bind(i64::try_from(seq).unwrap_or(i64::MAX))
        .bind(&id)
        .bind(prev_hash.as_deref())
        .bind(&input.reason)
        .bind(&input.detail)
        .bind(&input.object_hash)
        .bind(input.submitted_by.as_deref())
        .bind(&input.received_at)
        .bind(input.claimed_stream.as_deref())
        .bind(input.claimed_seq.and_then(|s| i64::try_from(s).ok()))
        .bind(input.claimed_kind.as_deref())
        .bind(&canonical)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;

        Ok(RejectionRecord {
            id,
            seq,
            reason: input.reason.clone(),
        })
    }

    /// Delete every payload whose retention has expired for every referencing envelope (§04 §5.4).
    ///
    /// Returns the hashes deleted. **Nothing is written to any envelope row**, which is why chain
    /// verification is unaffected — the property is structural, not a promise this function keeps.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn decay_payloads(&self, now: &str) -> Result<Vec<String>> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let rows = sqlx::query(
            "SELECT p.payload_hash AS payload_hash FROM payloads p WHERE NOT EXISTS \
             (SELECT 1 FROM payload_refs r WHERE r.payload_hash = p.payload_hash \
              AND r.retain_until > ?1)",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let hashes: Vec<String> = rows
            .iter()
            .map(|r| r.get::<String, _>("payload_hash"))
            .collect();
        for hash in &hashes {
            sqlx::query("DELETE FROM payloads WHERE payload_hash = ?1")
                .bind(hash)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(hashes)
    }

    /// The streams a payload decay run would touch, so they can be checkpointed first (§04 §4.6).
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn streams_with_expiring_payloads(&self, now: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT DISTINCT r.stream AS stream FROM payload_refs r \
             JOIN payloads p ON p.payload_hash = r.payload_hash \
             WHERE NOT EXISTS (SELECT 1 FROM payload_refs q WHERE q.payload_hash = r.payload_hash \
              AND q.retain_until > ?1) ORDER BY stream",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows.iter().map(|r| r.get::<String, _>("stream")).collect())
    }

    /// Enrol a human root as deployment configuration — the recorded output of a ceremony.
    ///
    /// The bootstrap ceremony is S5. Until it exists the root set has to enter the store somehow,
    /// and configuration is the honest place for it: it is operator-controlled, it is visible, and
    /// it grants **no** approval. An enrolled root can sign approvals; it cannot make a gated
    /// envelope appendable without one, because [`Store::append`] never sees the root set.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn seed_configured_root(
        &self,
        root_key: &KeyId,
        subject: &str,
        enrolled_at: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO roots (root_key, subject, enrolled_at, retired_at, envelope_id) \
             VALUES (?1, ?2, ?3, NULL, 'configuration') ON CONFLICT (root_key) DO NOTHING",
        )
        .bind(root_key.as_str())
        .bind(subject)
        .bind(enrolled_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }
}

/// The indexed dimensions an audit query may filter on (§04 §6).
#[derive(Debug, Clone, Default)]
pub struct EnvelopeQuery<'a> {
    /// Acting subject.
    pub subject: Option<&'a str>,
    /// Exact mandate.
    pub mandate_ref: Option<&'a str>,
    /// A mandate and everything delegated beneath it.
    pub mandate_subtree_of: Option<&'a str>,
    /// Effective weight class.
    pub classification: Option<&'a str>,
    /// Envelope kind (§02 §2). Without it, "show me every revocation" is a full scan of the log.
    pub kind: Option<&'a str>,
    /// The action executed.
    pub action: Option<&'a str>,
    /// Emitting component.
    pub component: Option<&'a str>,
    /// One stream.
    pub stream: Option<&'a str>,
    /// Time window lower bound on `emitted-at`.
    pub emitted_from: Option<&'a str>,
    /// Time window upper bound on `emitted-at`.
    pub emitted_to: Option<&'a str>,
    /// Exact `correlation-ref` match.
    pub correlation_ref: Option<&'a str>,
    /// `correlation-ref` prefix match.
    pub correlation_prefix: Option<&'a str>,
    /// All transitions of a durable object.
    pub commitment_id: Option<&'a str>,
    /// Execution outcome — `attempted` is the first-class prohibited-attempt view.
    pub outcome: Option<&'a str>,
    /// The human root the mandate walk reached.
    pub human_root: Option<&'a str>,
    /// Only records that confess an effect policy did not permit.
    pub violations_only: bool,
    /// Row cap.
    pub limit: i64,
}

fn stored_from_row(row: &sqlx::sqlite::SqliteRow) -> StoredEnvelope {
    StoredEnvelope {
        id: row.get("id"),
        stream: row.get("stream"),
        seq: as_u64(row, "seq"),
        canonical_json: row.get("canonical_json"),
        received_at: row.get("received_at"),
        human_root: row.get("human_root"),
        effective_class: row.get("effective_class"),
        policy_violation: row.get("policy_violation"),
    }
}

fn as_u64(row: &sqlx::sqlite::SqliteRow, column: &str) -> u64 {
    u64::try_from(row.get::<i64, _>(column)).unwrap_or(0)
}

/// Neutralize `LIKE` metacharacters so a prefix query matches literally.
fn like_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

async fn next_counter(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, name: &str) -> Result<i64> {
    sqlx::query(
        "INSERT INTO counters (name, value) VALUES (?1, 1) \
         ON CONFLICT (name) DO UPDATE SET value = value + 1",
    )
    .bind(name)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    let row = sqlx::query("SELECT value FROM counters WHERE name = ?1")
        .bind(name)
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    Ok(row.get::<i64, _>("value"))
}

/// Verify the kernel's rejection stream: signatures, `seq` continuity and `prev-hash` linkage.
///
/// The rejection stream is chained "like anything else" (§04 §7), but its records are not envelopes,
/// so [`stozher_core::chain::verify_chain`] — which validates envelope structure — does not apply.
/// The chaining rule verified here is the same one, minus the envelope schema.
///
/// # Errors
///
/// `sig-invalid`, `chain-seq-gap`, `chain-seq-duplicate`, `chain-prev-hash-mismatch`,
/// `chain-genesis-prev-not-null`, `chain-prev-hash-missing`, or `chain-stream-mismatch`.
pub fn verify_rejection_chain(records: &[Value], stream: &str) -> Result<Option<String>> {
    let mut previous: Option<String> = None;
    for (index, record) in records.iter().enumerate() {
        let seq = record["seq"].as_u64().unwrap_or_default();
        stozher_core::signed::verify_signed_object(record).map_err(|e| e.at_seq(seq))?;
        if record["stream"].as_str() != Some(stream) {
            return Err(Error::new(
                "chain-stream-mismatch",
                format!("record {seq} does not belong to {stream}"),
            )
            .at_seq(seq));
        }
        let expected = index as u64;
        if seq != expected {
            let code = if seq < expected {
                "chain-seq-duplicate"
            } else {
                "chain-seq-gap"
            };
            return Err(
                Error::new(code, format!("expected seq {expected}, found {seq}")).at_seq(seq),
            );
        }
        match (&previous, record["prev-hash"].as_str()) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(Error::new(
                    "chain-genesis-prev-not-null",
                    "seq 0 must carry prev-hash null",
                )
                .at_seq(seq));
            }
            (Some(actual), Some(claimed)) if claimed == actual => {}
            (Some(actual), Some(claimed)) => {
                return Err(Error::new(
                    "chain-prev-hash-mismatch",
                    format!("prev-hash {claimed} != predecessor id {actual}"),
                )
                .at_seq(seq));
            }
            (Some(_), None) => {
                return Err(Error::new(
                    "chain-prev-hash-missing",
                    format!("seq {seq} has no prev-hash"),
                )
                .at_seq(seq));
            }
        }
        previous = Some(stozher_core::signed::object_id(record)?);
    }
    Ok(previous)
}

/// Summarize a set of rejection reasons for the console.
#[must_use]
pub fn reason_histogram(records: &[Value]) -> BTreeMap<String, usize> {
    let mut histogram = BTreeMap::new();
    for record in records {
        if let Some(reason) = record["reason"].as_str() {
            *histogram.entry(reason.to_owned()).or_insert(0) += 1;
        }
    }
    histogram
}

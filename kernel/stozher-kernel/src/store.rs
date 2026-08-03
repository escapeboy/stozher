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
//! `policies`, `manifests`, `gate_request_hashes`, `gate_requests`, `gate_decisions` and
//! `gate_notifications` carry `BEFORE UPDATE` / `BEFORE DELETE` triggers that abort the statement
//! (`append_only.sqlite.sql`). There is no application flag those triggers consult and no method on
//! [`Store`] that issues an UPDATE or DELETE against them, so an attempt to rewrite history fails in
//! the engine rather than in a reviewer's attention. A parked request an operator could edit after
//! an approver read it would not be the request they approved, which is why the queue is in that
//! list rather than treated as mutable working state.
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
    /// A gate decision recorded by this envelope (§06 §5).
    pub gate_decision: Option<GateDecisionRow>,
}

/// What one envelope adds to the running totals.
#[derive(Debug, Clone, Default)]
pub struct SpendAccrual {
    /// The citing mandate and its ancestors, all charged the same amounts.
    pub mandates: Vec<String>,
    /// Dimension to amount, as decimal strings — integers included, because a running total is
    /// exact arithmetic either way and one representation is fewer things to get wrong.
    pub amounts: BTreeMap<String, String>,
}

/// A decision folded out of a `gate-decision` envelope (§06 §5).
#[derive(Debug, Clone)]
pub struct GateDecisionRow {
    /// The request it answers.
    pub request_hash: String,
    /// `approve` or `deny`.
    pub verdict: String,
    /// Why, for a denial. Denial reasons are the training data of policy tier 3 (§05 §8).
    pub reason: Option<String>,
    /// The approver's key.
    pub decided_by: String,
    /// When the human decided.
    pub decided_at: String,
    /// The signed decision object, verbatim — this is what travels in a later envelope.
    pub decision: Value,
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
    /// Spend to accrue: the mandates to charge, and the amounts per dimension (§03 §4.3).
    ///
    /// The mandate list is the citing mandate **and every ancestor**, because a budget caps "this
    /// mandate and everything delegated beneath it" — so a delegated agent's spend has to reach the
    /// human root's cap, or a chain of delegations would be a way to multiply an org's limit by its
    /// own depth. Ingest computes both halves; the store only adds.
    pub spend: Option<SpendAccrual>,
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
        Self::open_with_migrations(path, rejection_stream, crate::migrate::MIGRATIONS).await
    }

    /// [`Self::open`], against a caller-supplied migration registry.
    ///
    /// Exists so a test can drive a real store from schema version N to N+1 with a real step, which
    /// is the v0.3 gate. The production path calls it with [`crate::migrate::MIGRATIONS`] and
    /// nothing else does.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`] on any database failure, or any code from
    /// [`crate::migrate::run`].
    pub async fn open_with_migrations(
        path: &Path,
        rejection_stream: &str,
        migrations: &[crate::migrate::Migration],
    ) -> Result<Self> {
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
        Self::connect(options, rejection_stream, migrations).await
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
        Self::connect(options, rejection_stream, crate::migrate::MIGRATIONS).await
    }

    async fn connect(
        options: SqliteConnectOptions,
        rejection_stream: &str,
        migrations: &[crate::migrate::Migration],
    ) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            // An in-memory database lives only as long as a connection to it does.
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await
            .map_err(db)?;
        // Read before migrating, so a re-verification that refuses can put the stamp back.
        let before = crate::migrate::version(&pool).await?;
        let applied = crate::migrate::run(&pool, migrations).await?;
        let store = Self {
            pool,
            rejection_stream: rejection_stream.to_owned(),
        };
        // §4.1: a migration verifies the chain after applying, before reporting success. Anything
        // else discovers a corrupting upgrade at audit time, which is the one time it must not be
        // discovered. Nothing is verified when nothing was applied — a boot that changed no schema
        // has nothing new to be wrong about, and re-reading every stream on every start would turn
        // a startup into a full scan.
        if !applied.is_empty() {
            if let Err(refusal) = store.verify_every_chain().await {
                // The step and its version stamp are already committed — verification needs a
                // `Store`, so it cannot run inside the migration's own transaction. Left forward,
                // the stamp makes the *next* start find nothing to apply, and the check above is
                // skipped when nothing was applied: the second boot would serve the very chain this
                // one just refused. `restart: unless-stopped` in the shipped compose file makes that
                // second boot automatic, unattended, and about a second later.
                crate::migrate::rewind_version(&store.pool, before).await?;
                return Err(refusal);
            }
            tracing::info!(
                versions = ?applied,
                schema_version = crate::migrate::SCHEMA_VERSION,
                "schema migrated; every chain re-verified"
            );
        }
        Ok(store)
    }

    /// Re-verify every stream the store holds, and the rejection chain.
    ///
    /// An empty store passes vacuously. That is the right answer *here* and the wrong answer at the
    /// CLI, where `stozher-kernel verify` refuses an empty store outright: this runs on the boot
    /// that creates the store, where holding no records is the expected state, whereas an operator
    /// asking whether their audit trail verifies is asking a question an empty box must not answer
    /// with a green line.
    ///
    /// # Errors
    ///
    /// Any chain code, or [`codes::STORE_UNAVAILABLE`].
    async fn verify_every_chain(&self) -> Result<()> {
        // Enumerated from the chain, not from the `streams` projection. `streams` is in
        // `REBUILDABLE_TABLES` — a fold of the log, carrying no triggers and no chain of its own —
        // so deleting one of its rows made this loop skip that stream in silence and report a clean
        // verify over a store it had not looked at. "We did not check" and "it verifies" must never
        // look the same, and enumerating from the thing being verified is what keeps them apart.
        for name in self.streams_holding_envelopes().await? {
            let name = name.as_str();
            let Some((head_seq, _)) = self.stream_head(name).await? else {
                continue;
            };
            let envelopes = self.range(name, 0, head_seq).await?;
            stozher_core::chain::verify_chain(&envelopes, name, None)?;
        }
        verify_rejection_chain(&self.rejection_chain().await?, &self.rejection_stream)?;
        Ok(())
    }

    /// The kernel's rejection stream name.
    #[must_use]
    pub fn rejection_stream(&self) -> &str {
        &self.rejection_stream
    }

    /// Write a consistent copy of the store to `out`, with the service still running.
    ///
    /// `VACUUM INTO` takes a read transaction over the source and writes a complete, already
    /// compacted database — so the copy is a snapshot of one consistent instant, with no
    /// half-written page and no separate WAL to reunite it with. Copying the three files with `cp`
    /// while a writer is mid-transaction produces something that usually restores, which is the
    /// worst property a backup can have.
    ///
    /// Nothing about this path can write to the store: the statement reads.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`] if the source cannot be read or the destination written.
    pub async fn snapshot_to(database: &Path, out: &Path) -> Result<()> {
        if out.exists() {
            // `VACUUM INTO` refuses an existing file, but its message is about SQLite rather than
            // about the operator having pointed a backup at something that already matters.
            return Err(Error::new(
                codes::STORE_UNAVAILABLE,
                format!("{} exists; a snapshot never overwrites", out.display()),
            ));
        }
        let options = SqliteConnectOptions::new()
            .filename(database)
            .create_if_missing(false)
            .read_only(true)
            .busy_timeout(Duration::from_secs(30));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(db)?;
        let destination = out.to_string_lossy().replace('\'', "''");
        sqlx::query(sqlx::AssertSqlSafe(format!("VACUUM INTO '{destination}'")))
            .execute(&pool)
            .await
            .map_err(db)?;
        pool.close().await;
        Ok(())
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

    /// Every stream name that actually holds an envelope, read from the chain itself.
    ///
    /// [`Self::streams`] answers from the `streams` projection, which is the right source for the
    /// operator-facing surface it feeds — it carries `first_seen_at` and `last_appended_at`, which
    /// the chain does not. It is the wrong source for verification: a projection is rebuildable,
    /// carries no triggers, and a row removed from it removes a whole stream from anything that
    /// enumerates through it.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn streams_holding_envelopes(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT DISTINCT stream FROM envelopes ORDER BY stream")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        Ok(rows.iter().map(|r| r.get::<String, _>("stream")).collect())
    }

    /// Every stream, with its head and last append time — the quiet-stream surface of §09 §4.2.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn streams(&self) -> Result<Vec<Value>> {
        // Driven from `envelopes`, with the projection joined on for the two things only it knows.
        //
        // `streams` is in `REBUILDABLE_TABLES`: a fold, carrying no triggers, writable by anyone who
        // can write the database file. Read as the authority it was one — a forged `head_hash` made
        // the console and the §09 §4.2 quiet-stream surface report a head the chain never had, a
        // ghost row invented a stream holding nothing, and a deleted row hid a real one from every
        // caller that enumerated through it. None of that touches a signature, so nothing else
        // contradicted it.
        //
        // Deriving the stream set and the head from the chain leaves the projection authoritative
        // for `first-seen-at` and `last-appended-at` alone — timestamps about *observation*, which
        // the chain does not record and which carry no authority. SQLite's documented bare-column
        // rule makes `id` the value from the same row as `MAX(seq)`.
        let rows = sqlx::query(
            "SELECT e.stream AS stream, MAX(e.seq) AS head_seq, e.id AS head_hash, e.kind AS kind, \
                    s.stream_kind AS stream_kind, s.first_seen_at AS first_seen_at, \
                    s.last_appended_at AS last_appended_at \
             FROM envelopes e LEFT JOIN streams s ON s.stream = e.stream \
             GROUP BY e.stream ORDER BY e.stream",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                let emitted: Option<String> = r.get("last_appended_at");
                serde_json::json!({
                    "stream": r.get::<String, _>("stream"),
                    // A projection row can be missing entirely; the kind is then whatever the head
                    // envelope says, which is where the projection got it from in the first place.
                    "stream-kind": r
                        .get::<Option<String>, _>("stream_kind")
                        .unwrap_or_else(|| r.get::<String, _>("kind")),
                    "head-seq": as_u64(r, "head_seq"),
                    "head-hash": r.get::<String, _>("head_hash"),
                    "first-seen-at": r.get::<Option<String>, _>("first_seen_at"),
                    "last-appended-at": emitted,
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

    /// The subject a key holds a live mandate as, if any (§06 §5's second approver kind).
    ///
    /// The reverse of [`Self::mandates_held_by`]: that one answers "which mandates does this person
    /// hold", this one answers "who is this key", which is the question the self-approval check has
    /// to ask about an approver it did not resolve from a subject in the first place.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn mandated_subject_of(&self, key: &str, at: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT grantee_subject FROM mandates WHERE grantee_key = ?1 \
             AND not_before <= ?2 AND not_after >= ?2 LIMIT 1",
        )
        .bind(key)
        .bind(at)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| r.get::<String, _>("grantee_subject")))
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
    /// Both halves of the run's own statement have to agree: `args-hash` is what the approval binds
    /// (§06 §2 step 10) and `target` is what the run says it tested. Matching only the first would
    /// accept a run that was approved *about* this manifest while naming another one.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn conformance_run_is_green(&self, manifest_hash: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 AS present FROM envelopes WHERE action = 'kernel.conformance_run' \
             AND outcome = 'applied' AND args_hash = ?1 AND target = ?2 LIMIT 1",
        )
        .bind(manifest_hash)
        .bind(format!("manifest:{manifest_hash}"))
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

    // -- the pending queue (§06 §4.3) -------------------------------------------------------
    //
    // These write to `gate_requests` and `gate_notifications` and to nothing else. Neither table
    // has a chain-bearing column and neither is reachable from `append`, so recording a park cannot
    // put anything into `envelopes` — which is what keeps "the kernel records the parked request"
    // from becoming a second way in. The decision half is a projection written by `append` itself.

    /// Record a parked request. Returns `false` when the request was already queued.
    ///
    /// Idempotent by `request_hash`, because a component that retries a submission after a lost
    /// response is doing the right thing and must not be answered with a refusal.
    ///
    /// `cap` is `(per_subject, since)`, and it is counted **inside this transaction**. Counting it
    /// outside made the §09 §7 approval-fatigue limit hold only for a caller that waited for each
    /// answer: sixty-four parks offered one at a time were capped at thirty, and the same
    /// sixty-four offered at once put sixty-three in the queue, because every one of them read the
    /// count before any of them had written a row. A limit that yields under concurrency is absent
    /// in the one circumstance it exists for — a runaway component spraying requests at a human.
    ///
    /// # Errors
    ///
    /// [`crate::codes::GATE_RATE_LIMITED`] when the subject is at or over `cap`,
    /// [`codes::STORE_UNAVAILABLE`], or a canonicalization failure.
    /// `arguments` is the canonical form of the values the approver will read (§06 §4.4), already
    /// checked against the request's `args-hash` by [`crate::gatequeue::check_arguments`]. It is
    /// written only alongside a *fresh* request: §06 §4.4 rule 7 makes the first accepted
    /// submission's values the recorded ones, so a later submission of the same `request-hash`
    /// cannot add, replace or remove what an approver may already have read.
    pub async fn queue_gate_request(
        &self,
        request: &crate::gatequeue::GateRequest,
        submitted_by: &str,
        received_at: &str,
        cap: Option<(u32, &str)>,
        arguments: Option<&str>,
    ) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some((per_subject, since)) = cap {
            let row = sqlx::query(
                "SELECT COUNT(*) AS parked FROM gate_requests \
                 WHERE subject = ?1 AND received_at >= ?2",
            )
            .bind(&request.subject)
            .bind(since)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            let parked = u32::try_from(as_u64(&row, "parked")).unwrap_or(u32::MAX);
            if parked >= per_subject {
                tx.rollback().await.map_err(db)?;
                return Err(Error::new(
                    crate::codes::GATE_RATE_LIMITED,
                    format!(
                        "{} has parked {parked} requests in this window, at or above the \
                         configured cap of {per_subject}",
                        request.subject
                    ),
                ));
            }
        }
        let inserted = sqlx::query(
            "INSERT INTO gate_requests (request_hash, request_json, submitted_by, received_at, \
             subject, subject_key, component, mandate_ref, policy_version, classification, action, \
             target, args_hash, requested_at, not_after) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        )
        .bind(&request.request_hash)
        .bind(stozher_core::jcs::canonicalize(&request.request)?)
        .bind(submitted_by)
        .bind(received_at)
        .bind(&request.subject)
        .bind(&request.subject_key)
        .bind(&request.component)
        .bind(&request.mandate_ref)
        .bind(&request.policy_version)
        .bind(&request.classification)
        .bind(&request.action)
        .bind(&request.target)
        .bind(&request.args_hash)
        .bind(&request.requested_at)
        .bind(&request.not_after)
        .execute(&mut *tx)
        .await;
        let fresh = match inserted {
            Ok(_) => true,
            Err(e) if is_unique_violation(&e) => false,
            Err(e) => {
                tx.rollback().await.map_err(db)?;
                return Err(db(e));
            }
        };
        if let (true, Some(arguments)) = (fresh, arguments) {
            sqlx::query(
                "INSERT INTO gate_request_arguments (request_hash, arguments, recorded_at) \
                 VALUES (?1, ?2, ?3)",
            )
            .bind(&request.request_hash)
            .bind(arguments)
            .bind(received_at)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(fresh)
    }

    /// The argument values recorded beside a parked request, canonical, or `None` when there are
    /// none to serve.
    ///
    /// `None` covers two facts and the caller must not conflate them (§06 §4.4 rule 8): the
    /// component supplied nothing, or the request has expired and §06 §4.4 rule 7 forbids serving
    /// what a human can no longer act on. Both are "not shown"; neither is "the call had no
    /// arguments", which is a recorded `{}`.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn gate_request_arguments(
        &self,
        request_hash: &str,
        at: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT a.arguments AS arguments FROM gate_request_arguments a \
             JOIN gate_requests q ON q.request_hash = a.request_hash \
             WHERE a.request_hash = ?1 AND q.not_after > ?2",
        )
        .bind(request_hash)
        .bind(at)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|r| r.get::<String, _>("arguments")))
    }

    /// Erase the argument values of every request that can no longer be answered (§06 §4.4 rule 7).
    ///
    /// Returns how many rows went. This is the storage half of a rule the read paths already
    /// enforce: an expired request is refused a decision by §06 §2 step (8), so values kept past
    /// that instant are readable only by someone who could not act on them, and the queue is not a
    /// place to accumulate a component's unsigned bytes indefinitely.
    ///
    /// **Nothing chained is touched.** The request object, its `request-hash` and its `args-hash`
    /// all remain, so no signed byte moves and no checkpoint is owed — this is not §04 §5 decay and
    /// must not be mistaken for it.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn erase_expired_gate_arguments(&self, now: &str) -> Result<u64> {
        let erased = sqlx::query(
            "DELETE FROM gate_request_arguments WHERE request_hash IN \
             (SELECT request_hash FROM gate_requests WHERE not_after <= ?1)",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(erased.rows_affected())
    }

    /// How many requests this subject has parked since `since`, and how many other subjects are
    /// also over `threshold` in that window (§09 §7).
    ///
    /// Counting by `subject` rather than by the authenticated submitter is deliberate. The subject
    /// is the identity whose approval an approver is being asked to give, and it is the axis
    /// approval fatigue runs along: one credential driving twenty subjects is twenty separate
    /// queues to a human reading them, and one subject behind twenty credentials is still one
    /// person's attention being spent.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn gate_requests_since(&self, subject: &str, since: &str) -> Result<u32> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS parked FROM gate_requests WHERE subject = ?1 AND received_at >= ?2",
        )
        .bind(subject)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        Ok(u32::try_from(as_u64(&row, "parked")).unwrap_or(u32::MAX))
    }

    /// Subjects whose parked requests since `since` reach `threshold` — the spike §09 §7 requires
    /// an interface to surface *as a finding*, rather than as a queue that is merely longer.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn gate_request_spikes(&self, since: &str, threshold: u32) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT subject, COUNT(*) AS parked, MAX(received_at) AS latest FROM gate_requests \
             WHERE received_at >= ?1 GROUP BY subject HAVING COUNT(*) >= ?2 ORDER BY parked DESC",
        )
        .bind(since)
        .bind(i64::from(threshold))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "subject": r.get::<String, _>("subject"),
                    "parked": as_u64(r, "parked"),
                    "latest": r.get::<Option<String>, _>("latest")
                })
            })
            .collect())
    }

    /// A queued request by hash, as the object an approver signs over.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn gate_request(&self, request_hash: &str) -> Result<Option<(Value, String)>> {
        let row = sqlx::query(
            "SELECT request_json, submitted_by FROM gate_requests WHERE request_hash = ?1",
        )
        .bind(request_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok((
                stozher_core::jcs::parse(&r.get::<String, _>("request_json"))?,
                r.get::<String, _>("submitted_by"),
            ))
        })
        .transpose()
    }

    /// The signed decision answering a request, when a human has answered it.
    ///
    /// This is what a component polls for. It returns the decision object **verbatim**, because the
    /// component must run all of §06 §2 over it itself before acting — the kernel handing back a
    /// verdict the component trusted on sight would be exactly the ambient approval §06 §2 forbids.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn gate_decision(&self, request_hash: &str) -> Result<Option<Value>> {
        let row = sqlx::query("SELECT decision_json FROM gate_decisions WHERE request_hash = ?1")
            .bind(request_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| stozher_core::jcs::parse(&r.get::<String, _>("decision_json")))
            .transpose()
    }

    /// The queue as the console and `GET /v1/gate/requests` render it.
    ///
    /// `answered` selects between "still waiting on a human" and "already decided". Notification
    /// state is joined in because a request nobody was told about is a different fact from one an
    /// approver has seen and not answered, and a queue that renders them identically is lying by
    /// omission.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn gate_queue(&self, answered: bool, at: &str, limit: i64) -> Result<Vec<Value>> {
        let sql = format!(
            "SELECT q.request_hash, q.request_json, q.submitted_by, q.received_at, q.subject, \
             q.subject_key, q.component, q.mandate_ref, q.policy_version, q.classification, \
             q.action, q.target, q.args_hash, q.requested_at, q.not_after, \
             d.verdict, d.reason, d.decided_by, d.decided_at, d.envelope_id, \
             (SELECT COUNT(*) FROM gate_notifications n WHERE n.request_hash = q.request_hash \
              AND n.outcome = 'delivered') AS delivered, \
             (SELECT COUNT(*) FROM gate_notifications n WHERE n.request_hash = q.request_hash \
              AND n.outcome = 'failed') AS failed, \
             (SELECT n.detail FROM gate_notifications n WHERE n.request_hash = q.request_hash \
              AND n.outcome = 'failed' ORDER BY n.attempted_at DESC LIMIT 1) AS last_failure, \
             CASE WHEN q.not_after > ?1 THEN a.arguments END AS arguments \
             FROM gate_requests q LEFT JOIN gate_decisions d ON d.request_hash = q.request_hash \
             LEFT JOIN gate_request_arguments a ON a.request_hash = q.request_hash \
             WHERE d.request_hash IS {} NULL ORDER BY q.requested_at DESC LIMIT {}",
            if answered { "NOT" } else { "" },
            limit.clamp(1, 10_000)
        );
        // Audited for injection as `SqlSafeStr` requires: the two interpolations are a literal
        // chosen from a boolean and a clamped integer. Every value reaches the statement by `bind`.
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(at)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| {
                let not_after = r.get::<String, _>("not_after");
                // §06 §4.4 rule 8: "the component supplied none" and "the call took none" are
                // different facts, and `arguments: null` cannot carry both — a submitted JSON
                // `null` is a value that hashes. The boolean says which, structurally.
                let arguments = r.get::<Option<String>, _>("arguments");
                Ok(serde_json::json!({
                    "arguments-supplied": arguments.is_some(),
                    "arguments": arguments
                        .as_deref()
                        .map(stozher_core::jcs::parse)
                        .transpose()?,
                    "request-hash": r.get::<String, _>("request_hash"),
                    "request": stozher_core::jcs::parse(&r.get::<String, _>("request_json"))?,
                    "submitted-by": r.get::<String, _>("submitted_by"),
                    "received-at": r.get::<String, _>("received_at"),
                    "subject": r.get::<String, _>("subject"),
                    "subject-key": r.get::<String, _>("subject_key"),
                    "component": r.get::<String, _>("component"),
                    "mandate-ref": r.get::<String, _>("mandate_ref"),
                    "policy-version": r.get::<String, _>("policy_version"),
                    "classification": r.get::<String, _>("classification"),
                    "action": r.get::<String, _>("action"),
                    "target": r.get::<String, _>("target"),
                    "args-hash": r.get::<String, _>("args_hash"),
                    "requested-at": r.get::<String, _>("requested_at"),
                    // A request whose window has closed is a *block*, never an allow (§06 §4.6), so
                    // the queue states it rather than leaving a stale row looking answerable.
                    "expired": not_after.as_str() <= at,
                    "not-after": not_after,
                    "verdict": r.get::<Option<String>, _>("verdict"),
                    "reason": r.get::<Option<String>, _>("reason"),
                    "decided-by": r.get::<Option<String>, _>("decided_by"),
                    "decided-at": r.get::<Option<String>, _>("decided_at"),
                    "decision-envelope-id": r.get::<Option<String>, _>("envelope_id"),
                    "notified": as_u64(r, "delivered"),
                    "notify-failures": as_u64(r, "failed"),
                    "last-notify-failure": r.get::<Option<String>, _>("last_failure"),
                }))
            })
            .collect()
    }

    /// Record what each channel did with one approver ping.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn record_notifications(
        &self,
        request_hash: &str,
        attempts: &[crate::notify::Attempt],
        at: &str,
    ) -> Result<()> {
        for attempt in attempts {
            sqlx::query(
                "INSERT INTO gate_notifications (request_hash, channel, attempted_at, outcome, \
                 detail) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (request_hash, channel, attempted_at) DO NOTHING",
            )
            .bind(request_hash)
            .bind(&attempt.channel)
            .bind(at)
            .bind(if attempt.delivered {
                "delivered"
            } else {
                "failed"
            })
            .bind(attempt.detail.as_deref())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        }
        Ok(())
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

    /// Accrued spend under one mandate, per dimension.
    ///
    /// This is the mandate's **own** accrual. A budget is a cap on "this mandate and everything
    /// delegated beneath it" (§03 §4.3), and that is honoured by accruing each cost to the citing
    /// mandate *and to every ancestor* at append time — so the figure a cap is compared against is
    /// read here directly rather than by walking the subtree on every check.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn spend(&self, mandate_id: &str) -> Result<BTreeMap<String, String>> {
        let rows = sqlx::query("SELECT dimension, amount FROM spend WHERE mandate_id = ?1")
            .bind(mandate_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("dimension"),
                    r.get::<String, _>("amount"),
                )
            })
            .collect())
    }

    /// The latest registered manifest of every component, for tier-A classification (§08, §10 §3).
    ///
    /// One row per component name, so a component that has registered three versions appears once,
    /// as its newest. Earlier versions are retained forever (§08 §3.5) and are still readable by
    /// version; what a classifier wants is what the component *is* now.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `jcs-malformed-json` on stored corruption.
    pub async fn registered_manifests(&self) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT document_json FROM manifests AS m WHERE ordinal = \
             (SELECT MAX(ordinal) FROM manifests WHERE name = m.name) ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| stozher_core::jcs::parse(&r.get::<String, _>("document_json")))
            .collect()
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

    /// The newest checkpoint of every stream that has one — what §04 §4.7 asks to leave the box.
    ///
    /// Unlike [`Self::last_checkpoint`] this carries `envelope_id` and `observed_at`, because the
    /// reader is outside: a head hash on its own is a number to compare, while the envelope id lets
    /// them fetch the signed checkpoint later and check that the number was attested rather than
    /// asserted by whoever mailed the file.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn checkpoint_heads(&self) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            "SELECT c.stream, c.from_seq, c.to_seq, c.head_hash, c.envelope_id, c.observed_at \
             FROM checkpoints c JOIN (SELECT stream, MAX(to_seq) AS top FROM checkpoints \
             GROUP BY stream) latest ON latest.stream = c.stream AND latest.top = c.to_seq \
             ORDER BY c.stream",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "stream": r.get::<String, _>("stream"),
                    "from-seq": as_u64(r, "from_seq"),
                    "to-seq": as_u64(r, "to_seq"),
                    "head-hash": r.get::<String, _>("head_hash"),
                    "checkpoint-envelope": r.get::<String, _>("envelope_id"),
                    "observed-at": r.get::<String, _>("observed_at"),
                })
            })
            .collect())
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
        let (mut predicate, mut binds) = self.predicate(filter).await?;
        if let Some(after) = filter.after {
            // Deliberately not in `predicate()`, which `query_count` shares: the count answers "how
            // many match these filters", and narrowing it by the cursor would make it shrink as the
            // reader pages, so page three of five would report two records left and read as the end.
            binds.push(after.emitted_at.to_owned());
            let emitted = binds.len();
            binds.push(after.stream.to_owned());
            let stream = binds.len();
            // `seq` is inlined rather than bound because the surrounding binds are all `String` and
            // `seq` is compared against a `BIGINT`; it is a `u64` this crate parsed, so it renders
            // as digits and nothing else.
            predicate.push_str(if predicate.is_empty() {
                " WHERE "
            } else {
                " AND "
            });
            predicate.push_str(&format!(
                "(emitted_at < ?{emitted} \
                 OR (emitted_at = ?{emitted} AND stream > ?{stream}) \
                 OR (emitted_at = ?{emitted} AND stream = ?{stream} AND seq < {}))",
                after.seq
            ));
        }
        let mut sql = String::from(
            "SELECT id, stream, seq, canonical_json, received_at, human_root, effective_class, \
             policy_violation FROM envelopes",
        );
        sql.push_str(&predicate);
        // `ORDER BY emitted_at DESC, stream ASC, seq DESC`, and `envelopes_by_cursor` is the index
        // that shape was added for. The three columns are a total order (`PRIMARY KEY (stream,
        // seq)`), which is what lets the cursor below resume without skipping or repeating a tie.
        sql.push_str(" ORDER BY emitted_at DESC, stream, seq DESC LIMIT ");
        sql.push_str(&filter.limit.clamp(1, 10_000).to_string());

        // Audited for injection as `SqlSafeStr` requires: every fragment appended above is a
        // literal, and every value reaches the statement through `bind`. The only interpolated
        // non-literals are `?n` placeholder indices and one clamped integer.
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

    /// How many envelopes the same filters match, ignoring `limit` and `offset`.
    ///
    /// The console shows this next to the number of rows it drew. "200 record(s)" for a filter that
    /// matched five thousand is not a smaller truth, it is a different one, and an auditor has no
    /// way to tell the two apart from the page.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn query_count(&self, filter: &EnvelopeQuery<'_>) -> Result<u64> {
        let (predicate, binds) = self.predicate(filter).await?;
        let mut sql = String::from("SELECT COUNT(*) AS matched FROM envelopes");
        sql.push_str(&predicate);
        let mut statement = sqlx::query(sqlx::AssertSqlSafe(sql));
        for bind in &binds {
            statement = statement.bind(bind);
        }
        let row = statement.fetch_one(&self.pool).await.map_err(db)?;
        Ok(as_u64(&row, "matched"))
    }

    /// The `WHERE` clause the filters describe, and the values to bind to it.
    ///
    /// Shared by [`Self::query`] and [`Self::query_count`] so the two can never disagree about what
    /// "matching" means — a count that came from a different predicate than the rows would be worse
    /// than no count at all.
    async fn predicate(&self, filter: &EnvelopeQuery<'_>) -> Result<(String, Vec<String>)> {
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
        let mut sql = String::new();
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        Ok((sql, binds))
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
        if let Some(decision) = &projections.gate_decision {
            // One request, one answer. The PRIMARY KEY is the enforcement: a second, contradicting
            // decision over the same request cannot be written, so "a human said no and someone
            // then recorded a yes" is not representable (§06 §5).
            let inserted = sqlx::query(
                "INSERT INTO gate_decisions (request_hash, verdict, reason, decided_by, \
                 decided_at, decision_json, envelope_id, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&decision.request_hash)
            .bind(&decision.verdict)
            .bind(decision.reason.as_deref())
            .bind(&decision.decided_by)
            .bind(&decision.decided_at)
            .bind(stozher_core::jcs::canonicalize(&decision.decision)?)
            .bind(&plan.id)
            .bind(&plan.received_at)
            .execute(&mut **tx)
            .await;
            if let Err(e) = inserted {
                return Err(if is_unique_violation(&e) {
                    Error::new(
                        codes::GATE_DECISION_ALREADY_RECORDED,
                        format!(
                            "request {} has already been answered by a named human",
                            decision.request_hash
                        ),
                    )
                } else {
                    db(e)
                });
            }
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
        if let Some(accrual) = &plan.spend {
            // Inside the same transaction as the append. Spend that was committed separately could
            // be lost while the effect it belongs to survived, and a budget whose total is quietly
            // below the log it was folded from is worse than no budget at all: it reads as headroom.
            for mandate in &accrual.mandates {
                for (dimension, amount) in &accrual.amounts {
                    let held: Option<String> = sqlx::query(
                        "SELECT amount FROM spend WHERE mandate_id = ?1 AND dimension = ?2",
                    )
                    .bind(mandate)
                    .bind(dimension)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(db)?
                    .map(|r| r.get::<String, _>("amount"));
                    let total = match held {
                        Some(held) => stozher_core::decimal::add(&held, amount)?,
                        None => amount.to_owned(),
                    };
                    sqlx::query(
                        "INSERT INTO spend (mandate_id, dimension, amount) VALUES (?1, ?2, ?3) \
                         ON CONFLICT (mandate_id, dimension) DO UPDATE SET amount = ?3",
                    )
                    .bind(mandate)
                    .bind(dimension)
                    .bind(&total)
                    .execute(&mut **tx)
                    .await
                    .map_err(db)?;
                }
            }
        }
        let _ = (stream, seq);
        Ok(())
    }

    /// Recompute the spend projection from the envelope stream.
    ///
    /// The projection is a fold and this is the proof: drop the table, replay the log, get the same
    /// figures. It exists so the claim in [`crate::migrate::REBUILDABLE_TABLES`] is something a test
    /// can execute rather than something a comment asserts — and so an operator who suspects the
    /// figures has a way to settle it that does not involve trusting them.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or `schema-type-mismatch` on a cost that is not a decimal.
    pub async fn rebuild_spend(&self) -> Result<u64> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        sqlx::query("DELETE FROM spend")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let rows = sqlx::query(
            "SELECT canonical_json, mandate_ref FROM envelopes \
             WHERE mandate_ref IS NOT NULL ORDER BY stream, seq",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;

        let mut folded = 0u64;
        let mut totals: BTreeMap<(String, String), String> = BTreeMap::new();
        for row in &rows {
            let envelope = stozher_core::jcs::parse(&row.get::<String, _>("canonical_json"))?;
            let mandate_ref: String = row.get("mandate_ref");
            let amounts = crate::budget::accrual_of(&envelope);
            if amounts.is_empty() {
                continue;
            }
            folded += 1;
            for mandate in self.mandate_line(&mandate_ref).await? {
                for (dimension, amount) in &amounts {
                    let key = (mandate.clone(), dimension.clone());
                    let total = match totals.get(&key) {
                        Some(held) => stozher_core::decimal::add(held, amount)?,
                        None => amount.to_owned(),
                    };
                    totals.insert(key, total);
                }
            }
        }
        for ((mandate, dimension), amount) in totals {
            sqlx::query("INSERT INTO spend (mandate_id, dimension, amount) VALUES (?1, ?2, ?3)")
                .bind(&mandate)
                .bind(&dimension)
                .bind(&amount)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(folded)
    }

    /// A mandate and every ancestor of it, for accrual.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`].
    pub async fn mandate_line(&self, mandate_id: &str) -> Result<Vec<String>> {
        let mut line = vec![mandate_id.to_owned()];
        let mut current = mandate_id.to_owned();
        // Bounded by the same depth policy bounds delegation to, so a cycle written by a future
        // defect cannot make this walk forever. `mandate_ancestry` enforces the real limit; this is
        // the belt to its braces, because an unbounded loop inside a write transaction is an outage.
        for _ in 0..64 {
            let parent: Option<String> =
                sqlx::query("SELECT parent FROM mandates WHERE mandate_id = ?1")
                    .bind(&current)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db)?
                    .and_then(|r| r.get::<Option<String>, _>("parent"));
            match parent {
                Some(parent) if !line.contains(&parent) => {
                    line.push(parent.clone());
                    current = parent;
                }
                _ => break,
            }
        }
        Ok(line)
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
    /// Resume after this row, so a caller that needs *all* matches can page through them rather
    /// than silently receiving the first [`Store::query`]'s worth.
    pub after: Option<Cursor<'a>>,
}

/// A position in the audit ordering, so the next page starts exactly where the last one stopped.
///
/// # Why not `OFFSET`
///
/// `OFFSET n` means "re-run the query and throw away the first n rows", which is only stable if
/// nothing sorts into the discarded region between one page and the next. This is a log under a live
/// writer and `emitted-at` is the *emitter's* clock, not arrival order, so a record can land ahead of
/// rows a reader has already passed. Every later row then shifts down by one and the next page begins
/// one row early: the reader is handed an envelope they have already seen.
///
/// Being precise about what that costs, because the opposite failure would be worse and is not the
/// one here: **nothing is lost.** The store is append-only and enforced so by triggers, so no row can
/// vanish from under an offset — the defect is duplication, not truncation. It still matters. A
/// regulator's export containing one signed envelope twice is a file somebody has to reconcile, and
/// neither they nor the operator who sent it can tell a paging artefact from a genuine repeat
/// without re-deriving `id()` across the whole file.
///
/// A keyset cursor has no such window at all. It names the last row seen and asks for what sorts
/// strictly after it, so a concurrent append can add rows but can never renumber the ones already
/// read.
///
/// # Why these three columns
///
/// The audit ordering is `emitted_at DESC, stream ASC, seq DESC`, and `PRIMARY KEY (stream, seq)`
/// makes the last two unique on their own — so the triple is a **total** order. That matters: a
/// cursor over a non-unique key either skips the rest of a tie or repeats it, and there is no third
/// option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor<'a> {
    /// `emitted-at` of the last row of the previous page.
    pub emitted_at: &'a str,
    /// Its stream.
    pub stream: &'a str,
    /// Its position in that stream.
    pub seq: u64,
}

impl Cursor<'_> {
    /// Render a cursor for a URL.
    ///
    /// The stream comes last and is not escaped, because it is the only field whose alphabet this
    /// module does not fix: `emitted-at` is §01 §2.3's single timestamp form and `seq` is digits, so
    /// neither can contain a `/`, and everything after the second one is the stream whatever it
    /// holds. That is a parsing rule rather than a convention, so no stream name can be constructed
    /// that splits into a different cursor than the one written.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}/{}/{}", self.emitted_at, self.seq, self.stream)
    }
}

/// The cursor naming the last row of `records`, or `None` when the page is empty.
///
/// Reads the three ordering columns back out of a [`Store::query`] result, so a caller can ask for
/// the next page without re-deriving what the ordering is.
#[must_use]
pub fn cursor_after(records: &[Value]) -> Option<OwnedCursor> {
    let last = records.last()?;
    let envelope = last.get("envelope")?;
    Some(OwnedCursor {
        emitted_at: envelope.get("emitted-at")?.as_str()?.to_owned(),
        stream: envelope.get("stream")?.as_str()?.to_owned(),
        seq: envelope.get("seq")?.as_u64()?,
    })
}

/// A [`Cursor`] that owns its strings, for a caller that parsed one out of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCursor {
    /// `emitted-at` of the last row of the previous page.
    pub emitted_at: String,
    /// Its stream.
    pub stream: String,
    /// Its position in that stream.
    pub seq: u64,
}

impl OwnedCursor {
    /// Parse the form [`Cursor::encode`] writes.
    ///
    /// Returns `None` rather than a partial cursor: a caller that fell back to "no cursor" on a
    /// malformed one would answer a request for page four with page one, and look like it had
    /// succeeded. The console refuses instead.
    #[must_use]
    pub fn decode(value: &str) -> Option<Self> {
        let mut parts = value.splitn(3, '/');
        let emitted_at = parts.next()?;
        let seq = parts.next()?.parse().ok()?;
        let stream = parts.next()?;
        if emitted_at.is_empty() || stream.is_empty() {
            return None;
        }
        crate::clock::parse_timestamp(emitted_at).ok()?;
        Some(Self {
            emitted_at: emitted_at.to_owned(),
            stream: stream.to_owned(),
            seq,
        })
    }

    /// Borrow it for an [`EnvelopeQuery`].
    #[must_use]
    pub fn borrowed(&self) -> Cursor<'_> {
        Cursor {
            emitted_at: &self.emitted_at,
            stream: &self.stream,
            seq: self.seq,
        }
    }

    /// Render it for a URL.
    #[must_use]
    pub fn encode(&self) -> String {
        self.borrowed().encode()
    }
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

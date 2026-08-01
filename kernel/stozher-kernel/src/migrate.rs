//! Forward-only schema migration — `docs/product-completion-design.md` §4.1.
//!
//! # Why this is not a normal migration runner
//!
//! The store is append-only, hash-chained, and enforced by database triggers. A conventional
//! migration that rewrites rows is not merely discouraged here: rewriting a chain-bearing row
//! invalidates every signature and hash link after it, which destroys the only claim the product
//! makes. So the rules are stricter than "run the SQL in order":
//!
//! * **Chain-bearing tables are additive-only.** New columns must be nullable or defaulted, and
//!   nothing may rewrite `canonical_json`, `id`, `prev_hash` or `seq`. A change that cannot be
//!   expressed additively is a new stream or a new envelope kind, never a rewrite.
//! * **Projections are rebuildable; the chain is not.** [`REBUILDABLE_TABLES`] may be dropped and
//!   recomputed from the envelope stream. [`CHAIN_BEARING_TABLES`] may not. That distinction is
//!   stated here as data, and `the_classification_covers_every_table_the_database_holds`
//!   (`tests/schema_migration.rs`) binds it to the tables the database actually holds, so it cannot
//!   drift into folklore.
//! * **The whole run is one transaction.** A step that drops a chain-bearing table or one of its
//!   triggers is caught by the post-apply assertion *before* the commit, so the damage is rolled
//!   back rather than reported.
//! * **The chain is re-verified after applying, before the store is reported open.** An upgrade
//!   that silently corrupted the log would otherwise be discovered by an auditor rather than by us.
//!
//! # What "version 1" is
//!
//! The baseline is the schema as it stood through v0.2, when there was no version at all. Both a
//! fresh file and an existing v0.2 store report `PRAGMA user_version = 0`, and applying the baseline
//! to either is idempotent — every statement in it is `CREATE ... IF NOT EXISTS`. So the first boot
//! of a v0.3 kernel over a v0.2 store stamps it 1 and re-verifies it, which is the upgrade gate
//! rather than a special case of it.

use std::collections::BTreeSet;

use sqlx::{Row, SqlitePool};
use stozher_core::error::{Error, Result};

use crate::codes;

/// The DDL every dialect shares, as it stood at v0.2. **Frozen** — see [`MIGRATIONS`].
const SCHEMA: &str = include_str!("sql/schema.sql");
/// The append-only enforcement, SQLite dialect. The one file to port to Postgres.
const APPEND_ONLY_SQLITE: &str = include_str!("sql/append_only.sqlite.sql");

/// The schema version this build writes and expects.
pub const SCHEMA_VERSION: u32 = 6;

/// One forward-only step. There is no `down`: a downgrade would have to discard rows, and the rows
/// in question are an audit trail.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// The version the store is at once this step has been applied.
    pub to_version: u32,
    /// What it does, for the log line an operator reads during an upgrade.
    pub name: &'static str,
    /// The scripts to execute, in order.
    pub sql: &'static [&'static str],
}

/// The registry. Ordered, contiguous, and asserted to be both by `the_registry_is_well_formed`.
///
/// # The registry is the only place a schema change may be written
///
/// Step 1 embeds `sql/schema.sql`, and step 1 runs **only against a store that has never been
/// stamped**. A store an earlier binary already stamped will never see an edit to that file — so
/// editing it changes the schema of new installs and of nothing else, and the two shapes then
/// diverge with nothing to notice. The file is frozen at v0.2 for that reason
/// (`the_baseline_schema_is_frozen` pins its digest), and everything after it is a numbered step
/// here, which every store reaches exactly once whatever version it starts from.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        to_version: 1,
        name: "baseline: the schema as of v0.2, adopted under version control",
        sql: &[SCHEMA, APPEND_ONLY_SQLITE],
    },
    Migration {
        to_version: 2,
        name: "additive: the audit-cursor index, so paging resumes instead of re-sorting",
        // Additive-only, on a chain-bearing table, in the one shape §4.1 permits there: it adds an
        // index and no column, so no signed byte moves and nothing is rewritten to build it.
        sql: &["CREATE INDEX IF NOT EXISTS envelopes_by_cursor \
                ON envelopes (emitted_at DESC, stream, seq DESC);"],
    },
    Migration {
        to_version: 3,
        name: "additive: the spend projection, so a budget is a figure and not a declaration",
        // A new projection table, not a change to a chain-bearing one. Everything in it is a fold
        // of `envelopes` and it is listed in `REBUILDABLE_TABLES` for that reason: drop it and it
        // can be recomputed from the log, which is the property that makes it safe to have at all
        // (§02 §8, maxim 9).
        sql: &["CREATE TABLE IF NOT EXISTS spend (
                    mandate_id TEXT NOT NULL,
                    dimension  TEXT NOT NULL,
                    amount     TEXT NOT NULL,
                    PRIMARY KEY (mandate_id, dimension)
                );
                CREATE INDEX IF NOT EXISTS spend_by_mandate ON spend (mandate_id);"],
    },
    Migration {
        to_version: 4,
        name: "append-only covers INSERT too, not only UPDATE and DELETE",
        // The baseline's triggers make an existing row immutable, which is what append-only means
        // and all it means. They say nothing about *new* rows, so anyone able to write the database
        // file could INSERT a record `Ingest` would have refused — a consequential effect carrying
        // no authorization — and every read path serves it as genuine. `Store::append` being
        // crate-private is a guarantee of the Rust type system, not of the storage engine, and
        // §09's threat model does not stop at the process boundary. Found by attacking a throwaway
        // deployment: the forged row verified, and after one INSERT into the `streams` projection
        // it was reported by `stozher-kernel verify` as part of a clean run.
        //
        // Additive in the sense §4.1 permits: triggers only, no column, no rewrite, no signed byte
        // moved.
        //
        // What this closes: an insert into an *existing* stream that does not extend it — a gap, a
        // repeated position, or a `prev_hash` naming something other than the row before it.
        //
        // What it does NOT close, said plainly because a partial defence read as a total one is
        // worse than none: a forged **new** stream. Its first envelope is legitimately seq 0 with a
        // null `prev_hash`, and no SQL predicate separates that from a real one — the difference is
        // whether an enrolled key signed it under a resolvable mandate, which is `Ingest`'s
        // judgement and is not expressible here. Catching a stream that should not exist needs the
        // off-box checkpoint set plus knowing which streams an emitter ought to have, which is why
        // §04 §4 rule 7 says a checkpoint that never leaves the box proves little.
        sql: &["CREATE TRIGGER IF NOT EXISTS envelopes_insert_must_extend_the_chain
                BEFORE INSERT ON envelopes
                WHEN NEW.seq > 0
                BEGIN
                    SELECT RAISE(ABORT, 'envelopes are append-only: an insert must extend its stream, naming the row at seq - 1 as prev_hash')
                    WHERE NOT EXISTS (
                        SELECT 1 FROM envelopes
                        WHERE stream = NEW.stream AND seq = NEW.seq - 1 AND id = NEW.prev_hash
                    );
                END;
                CREATE TRIGGER IF NOT EXISTS envelopes_insert_at_seq_zero_starts_a_stream
                BEFORE INSERT ON envelopes
                WHEN NEW.seq = 0
                BEGIN
                    SELECT RAISE(ABORT, 'envelopes are append-only: seq 0 starts a stream, so prev_hash must be null and the stream must be empty')
                    WHERE NEW.prev_hash IS NOT NULL
                       OR EXISTS (SELECT 1 FROM envelopes WHERE stream = NEW.stream);
                END;"],
    },
    Migration {
        to_version: 5,
        name: "INSERT guards for the chain-bearing tables step 4 left open",
        // Step 4 guarded `envelopes` and nothing else, and an attack run against a throwaway
        // deployment showed what that leaves: a forged `gate_decisions` row carrying `verdict:
        // 'approve'` with no envelope behind it, inserted straight into the store and served as a
        // real decision. Every read path believed it.
        //
        // The tables do not share a shape, so they do not share a guard.
        //
        // `rejections` is a chain (§04 §7) with the same `stream`/`seq`/`prev_hash` members, so it
        // gets the same linkage rule as `envelopes`: extend the stream or be refused.
        //
        // `checkpoints`, `policies`, `manifests` and `gate_decisions` are folds that each name the
        // `envelope_id` they came from. Requiring that envelope to exist is what makes the guard
        // worth having: an envelope cannot be conjured without a signature over its canonical form
        // by a key the walk resolves, so the projection inherits the chain's authenticity instead
        // of asserting its own. A forged approval now needs a forged approver.
        //
        // **`gate_request_hashes` is deliberately not guarded**, and that is worth saying rather
        // than leaving to be discovered: `Store::append` inserts it *before* the envelope, inside
        // one transaction, so a trigger demanding the envelope would refuse the legitimate path.
        // The exposure is narrower than the others — a forged row marks a single-use approval as
        // already spent, which denies a real approval rather than manufacturing one. Reordering the
        // two inserts would close it and is a change to the append path, which belongs with a
        // reason bigger than tidiness.
        //
        // `gate_requests` and `gate_notifications` have nothing signed behind them to check against.
        sql: &["CREATE TRIGGER IF NOT EXISTS rejections_insert_must_extend_the_chain
                BEFORE INSERT ON rejections
                WHEN NEW.seq > 0
                BEGIN
                    SELECT RAISE(ABORT, 'rejections are append-only: an insert must extend its stream, naming the row at seq - 1 as prev_hash')
                    WHERE NOT EXISTS (
                        SELECT 1 FROM rejections
                        WHERE stream = NEW.stream AND seq = NEW.seq - 1 AND id = NEW.prev_hash
                    );
                END;
                CREATE TRIGGER IF NOT EXISTS rejections_insert_at_seq_zero_starts_a_stream
                BEFORE INSERT ON rejections
                WHEN NEW.seq = 0
                BEGIN
                    SELECT RAISE(ABORT, 'rejections are append-only: seq 0 starts a stream, so prev_hash must be null and the stream must be empty')
                    WHERE NEW.prev_hash IS NOT NULL
                       OR EXISTS (SELECT 1 FROM rejections WHERE stream = NEW.stream);
                END;
                CREATE TRIGGER IF NOT EXISTS checkpoints_insert_needs_its_envelope
                BEFORE INSERT ON checkpoints
                BEGIN
                    SELECT RAISE(ABORT, 'a checkpoint must name an envelope this store holds')
                    WHERE NOT EXISTS (SELECT 1 FROM envelopes WHERE id = NEW.envelope_id);
                END;
                CREATE TRIGGER IF NOT EXISTS policies_insert_needs_its_envelope
                BEFORE INSERT ON policies
                BEGIN
                    SELECT RAISE(ABORT, 'a published policy must name an envelope this store holds')
                    WHERE NOT EXISTS (SELECT 1 FROM envelopes WHERE id = NEW.envelope_id);
                END;
                CREATE TRIGGER IF NOT EXISTS manifests_insert_needs_its_envelope
                BEFORE INSERT ON manifests
                BEGIN
                    SELECT RAISE(ABORT, 'a registered manifest must name an envelope this store holds')
                    WHERE NOT EXISTS (SELECT 1 FROM envelopes WHERE id = NEW.envelope_id);
                END;
                CREATE TRIGGER IF NOT EXISTS gate_decisions_insert_needs_its_envelope
                BEFORE INSERT ON gate_decisions
                BEGIN
                    SELECT RAISE(ABORT, 'a gate decision must name an envelope this store holds')
                    WHERE NOT EXISTS (SELECT 1 FROM envelopes WHERE id = NEW.envelope_id);
                END;"],
    },
    Migration {
        to_version: 6,
        name: "the arguments an approver reads (§06 §4.4), erasable and outside the chain",
        // A separate table rather than a column on `gate_requests`, for two reasons that both point
        // the same way. `gate_requests` is chain-bearing: its rows are immutable and undeletable, so
        // an `arguments` column there could never be erased, and §06 §4.4 rule 7 requires exactly
        // that once the request expires. And the values are not part of the request — they are not
        // covered by `request-hash` and no signature reaches them — so putting them in the row whose
        // whole point is "this is the object the approver signed over" would misfile them.
        //
        // Content, in the sense `payloads` is content: erasing a row here changes no signed byte,
        // and nothing in the chain can put it back. Hence `CONTENT_TABLES`, hence a `BEFORE UPDATE`
        // guard and deliberately no `BEFORE DELETE` one — immutable while it exists, erasable when
        // it should not.
        sql: &["CREATE TABLE IF NOT EXISTS gate_request_arguments (
                    request_hash TEXT PRIMARY KEY,
                    arguments    TEXT NOT NULL,
                    recorded_at  TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS gate_request_arguments_no_update
                BEFORE UPDATE ON gate_request_arguments
                BEGIN
                    SELECT RAISE(ABORT, 'the arguments an approver read are immutable: an edited argument list is not the one they were shown');
                END;"],
    },
];

/// Tables whose rows are chained, or are signed attestations about a chain, or record a human
/// decision. Every one carries `BEFORE UPDATE` / `BEFORE DELETE` triggers, and no migration may
/// rewrite, drop or rename one.
pub const CHAIN_BEARING_TABLES: [&str; 9] = [
    "envelopes",
    "rejections",
    "checkpoints",
    "policies",
    "manifests",
    "gate_request_hashes",
    "gate_requests",
    "gate_decisions",
    "gate_notifications",
];

/// Folds of the envelope stream (§02 §8). Nothing here is a source of truth, so a migration may
/// drop and recompute any of them.
pub const REBUILDABLE_TABLES: [&str; 7] = [
    "streams",
    "roots",
    "mandates",
    "revocations",
    "payload_refs",
    "counters",
    // Accrued spend per (mandate, dimension). A fold of the effect and cognition envelopes and
    // nothing else, so it is droppable and recomputable — which is what keeps a budget figure an
    // answer *about* the log rather than a second place the truth lives (maxim 9).
    "spend",
];

/// Content. Neither chained nor rebuildable: deleting a row here changes no signed byte (§04 §5.1),
/// and nothing in the chain can put it back.
///
/// `payloads` is evidence octets, erased by decay (§04 §5.4). `gate_request_arguments` is the
/// argument values an approver reads beside a parked request (§06 §4.4), erased when the request
/// they belong to expires — which is a different erasure with a different trigger and no checkpoint,
/// because no envelope ever committed to them.
pub const CONTENT_TABLES: [&str; 2] = ["payloads", "gate_request_arguments"];

/// Bring the store at `pool` up to [`SCHEMA_VERSION`], returning the steps applied.
///
/// An empty return means the store was already current and nothing was written.
///
/// # Errors
///
/// [`codes::SCHEMA_VERSION_AHEAD`] when the store was written by a newer kernel — the refusal is
/// deliberate: a build that does not know what a column means must not serve the chain that has it.
/// [`codes::SCHEMA_MIGRATION_FAILED`] when a step fails, or when the append-only enforcement is not
/// intact once the steps have run.
pub async fn run(pool: &SqlitePool, migrations: &[Migration]) -> Result<Vec<u32>> {
    let target = migrations.last().map_or(0, |m| m.to_version);
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;

    // Read the version inside the write transaction, not before it: two kernels starting against one
    // store must not both decide they are the one applying step N.
    let current = user_version(&mut tx).await?;
    if current > target {
        return Err(Error::new(
            codes::SCHEMA_VERSION_AHEAD,
            format!(
                "the store is at schema version {current}; this build understands {target}. \
                 It was written by a newer kernel. Upgrade the kernel rather than downgrading the \
                 store — there is no downward migration, because one would have to discard records."
            ),
        ));
    }

    let mut applied = Vec::new();
    for migration in migrations.iter().filter(|m| m.to_version > current) {
        for script in migration.sql {
            sqlx::raw_sql(*script)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    Error::new(
                        codes::SCHEMA_MIGRATION_FAILED,
                        format!(
                            "schema step {} ({}) failed: {e}",
                            migration.to_version, migration.name
                        ),
                    )
                })?;
        }
        applied.push(migration.to_version);
    }

    if !applied.is_empty() {
        assert_append_only_intact(&mut tx).await?;
        set_user_version(&mut tx, target).await?;
    }

    tx.commit()
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    Ok(applied)
}

/// Refuse to commit a migration that left the store rewritable.
///
/// This is the check that makes the transaction worth having. A step that dropped `envelopes` to
/// "rebuild" it, or that dropped a trigger to make its own `UPDATE` succeed, gets this far and no
/// further: the assertion runs before the commit, so the store an operator is left with is the one
/// they started the upgrade with.
///
/// It deliberately **refuses** rather than re-running the trigger DDL to heal the gap. Healing would
/// be easy and is the wrong answer: it would let a migration that disarms the store report success,
/// and it would make this check unfireable — which by this repository's own standard is an untested
/// check. Chain-bearing tables are additive-only, so a migration that loses one of their triggers is
/// a bug in the migration, and the safe direction is to say so before the commit.
async fn assert_append_only_intact(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<()> {
    // This check has been wrong twice, each time by asking a question next to the one that matters.
    // It counted triggers per table and required two, which stopped meaning anything the moment
    // `envelopes` gained two INSERT triggers and a dropped UPDATE guard still left three. It then
    // matched the strings "BEFORE UPDATE" and "BEFORE DELETE" in `sqlite_master.sql`, which an empty
    // trigger body satisfies exactly as well as a `RAISE(ABORT)` does — and so does
    // `BEFORE UPDATE OF <column>`, which guards one column. Both asked whether a trigger *exists*.
    //
    // The property is that a write is *refused*, so that is what is asserted: the write is attempted.
    // A probe that succeeds means the table is writable, and returning an error unwinds the
    // migration transaction, so the successful probe is rolled back with everything else. A probe
    // that is refused leaves nothing behind — SQLite's `RAISE(ABORT)` reverts its own statement and
    // the transaction stays usable.
    for table in CHAIN_BEARING_TABLES {
        let populated: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM (SELECT 1 FROM \"{table}\" LIMIT 1)"
        )))
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;

        if populated == 0 {
            // Nothing to probe: a `BEFORE UPDATE`/`BEFORE DELETE` trigger fires per row, so on an
            // empty table both probes would succeed while proving nothing. A fresh install reaches
            // here with every table empty. Fall back to the structural check, tightened to require
            // the abort itself — which is what the empty-body substitution could not fake.
            assert_guards_declared(tx, table).await?;
            continue;
        }

        // A no-op assignment: the trigger fires `BEFORE` the write whatever the values are, and if
        // no trigger fires the row is left byte-identical.
        let column = first_column(tx, table).await?;
        let probes = [
            format!("UPDATE \"{table}\" SET \"{column}\" = \"{column}\""),
            format!("DELETE FROM \"{table}\" WHERE rowid = (SELECT MIN(rowid) FROM \"{table}\")"),
        ];
        for probe in probes {
            if sqlx::query(sqlx::AssertSqlSafe(probe.clone()))
                .execute(&mut **tx)
                .await
                .is_ok()
            {
                return Err(Error::new(
                    codes::SCHEMA_MIGRATION_FAILED,
                    format!(
                        "after migrating, the storage engine accepted `{probe}`. The migration has \
                         been rolled back, and with it that write: a chain-bearing table that can \
                         be rewritten is not a chain."
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// The first column of `table`, for a probe that assigns a value to itself.
async fn first_column(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, table: &str) -> Result<String> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "PRAGMA table_info(\"{table}\")"
    )))
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?
    .ok_or_else(|| {
        Error::new(
            codes::SCHEMA_MIGRATION_FAILED,
            format!("after migrating, {table} has no columns — it is not the table it was"),
        )
    })?;
    Ok(row.get::<String, _>(1))
}

/// The empty-table fallback: a `BEFORE UPDATE` and a `BEFORE DELETE` that actually abort.
///
/// Weaker than the probe and known to be — `BEFORE UPDATE OF <column>` would satisfy it while
/// guarding one column. It applies only where there is nothing yet to protect, and the probe takes
/// over the moment the table holds a row.
async fn assert_guards_declared(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    table: &str,
) -> Result<()> {
    let rows =
        sqlx::query("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?1")
            .bind(table)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    let mut refuses_update = false;
    let mut refuses_delete = false;
    for row in rows {
        let sql = row
            .get::<Option<String>, _>(0)
            .unwrap_or_default()
            .to_uppercase();
        if !sql.contains("RAISE(ABORT") {
            continue;
        }
        refuses_update |= sql.contains("BEFORE UPDATE");
        refuses_delete |= sql.contains("BEFORE DELETE");
    }
    if refuses_update && refuses_delete {
        return Ok(());
    }
    Err(Error::new(
        codes::SCHEMA_MIGRATION_FAILED,
        format!(
            "after migrating, {table} does not declare a BEFORE UPDATE and a BEFORE DELETE trigger \
             that aborts. The migration has been rolled back: a chain-bearing table that can be \
             rewritten is not a chain."
        ),
    ))
}

/// Every table the database holds, for the classification test.
///
/// # Errors
///
/// [`codes::SCHEMA_MIGRATION_FAILED`] if the catalogue cannot be read.
pub async fn tables(pool: &SqlitePool) -> Result<BTreeSet<String>> {
    let rows = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    Ok(rows
        .into_iter()
        .map(|row| row.get::<String, _>(0))
        .collect())
}

/// The version the store reports.
///
/// # Errors
///
/// [`codes::SCHEMA_MIGRATION_FAILED`] if the pragma cannot be read.
pub async fn version(pool: &SqlitePool) -> Result<u32> {
    let value: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    Ok(u32::try_from(value).unwrap_or(u32::MAX))
}

/// Put the version stamp back to `to` after a post-migration check refused the store.
///
/// [`run`] commits the step and its stamp before the chain can be re-verified: verification needs a
/// `Store`, and the migration holds the only write transaction. So when that verification refuses,
/// the stamp on disk already says "current" — and the next start would then find nothing to apply
/// and skip the re-verification, which is exactly what makes skipping it safe when it is true.
///
/// Rewinding means every subsequent start re-applies the step (each is `IF NOT EXISTS`, so this is
/// idempotent) and re-runs the check, so a refusal stays a refusal for as long as the chain stays
/// broken. It matters most on the deployment this ships with: `restart: unless-stopped` makes the
/// next start automatic and unattended, seconds later, with nobody reading the first one's log line.
///
/// # Errors
///
/// [`codes::SCHEMA_MIGRATION_FAILED`] if the pragma cannot be written.
pub async fn rewind_version(pool: &SqlitePool, to: u32) -> Result<()> {
    // As in `set_user_version`: `PRAGMA user_version` takes no bind parameter, and `to` is a `u32`
    // this crate read out of the store's own header, never a caller's string.
    sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA user_version = {to}")))
        .execute(pool)
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    Ok(())
}

async fn user_version(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<u32> {
    let value: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    // A negative or oversized header value is not a version this build wrote. Saturating it to
    // `u32::MAX` sends it through the "ahead of this build" refusal above rather than wrapping it
    // into a version whose migrations would then be re-applied over real records.
    Ok(u32::try_from(value).unwrap_or(u32::MAX))
}

async fn set_user_version(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, to: u32) -> Result<()> {
    // `PRAGMA user_version` takes no bind parameter, so the value is formatted in. It is a `u32`
    // from this module's own registry, never a caller's string, so there is nothing to inject.
    sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA user_version = {to}")))
        .execute(&mut **tx)
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{APPEND_ONLY_SQLITE, MIGRATIONS, SCHEMA, SCHEMA_VERSION};

    /// `sha256(sql/schema.sql)` and `sha256(sql/append_only.sqlite.sql)` at v0.2.
    ///
    /// Update these **only** when deliberately re-baselining, which is not a thing this project
    /// should ever need to do while any deployment holds records.
    const FROZEN_BASELINE: [(&str, &str); 2] = [
        (
            "schema.sql",
            "47b66aec5be73cda0c41e211fd307d5fbb12db02fc8db96c55ae06471d777c39",
        ),
        (
            "append_only.sqlite.sql",
            "41b0ae1ef747794fc4dd994b85a12ac3e4d4d21eef5be6fa270b80c5e0383991",
        ),
    ];

    #[test]
    fn the_baseline_schema_is_frozen() {
        // Step 1 runs only against a store that has never been stamped, so an edit to either file
        // reaches new installs and nothing else — and the two shapes then diverge with nothing to
        // notice. If this test fails, the change belongs in a **new numbered step**, not in the
        // baseline; if you are genuinely re-baselining, the digest below is what you update.
        for (name, expected) in FROZEN_BASELINE {
            let text = match name {
                "schema.sql" => SCHEMA,
                _ => APPEND_ONLY_SQLITE,
            };
            assert_eq!(
                stozher_core::crypto::sha256_hex(text.as_bytes()),
                expected,
                "{name} has changed. A store an earlier binary already stamped will never see this \
                 edit — add a migration step instead"
            );
        }
    }

    #[test]
    fn the_registry_is_well_formed() {
        // Contiguous and ascending from 1: a gap would let a store stamped with the missing version
        // skip a step for ever, and a duplicate would make "which step ran" unanswerable.
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            let expected = u32::try_from(index + 1).expect("the registry is not that long");
            assert_eq!(
                migration.to_version, expected,
                "migration {index} claims version {}, expected {expected}",
                migration.to_version
            );
            assert!(
                !migration.sql.is_empty(),
                "migration {expected} carries no SQL"
            );
        }
        assert_eq!(
            MIGRATIONS.last().map_or(0, |m| m.to_version),
            SCHEMA_VERSION,
            "SCHEMA_VERSION does not name the last registered step"
        );
    }
}

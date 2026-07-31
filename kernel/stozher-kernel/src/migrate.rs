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

use std::collections::{BTreeMap, BTreeSet};

use sqlx::{Row, SqlitePool};
use stozher_core::error::{Error, Result};

use crate::codes;

/// The DDL every dialect shares, as it stood at v0.2. **Frozen** — see [`MIGRATIONS`].
const SCHEMA: &str = include_str!("sql/schema.sql");
/// The append-only enforcement, SQLite dialect. The one file to port to Postgres.
const APPEND_ONLY_SQLITE: &str = include_str!("sql/append_only.sqlite.sql");

/// The schema version this build writes and expects.
pub const SCHEMA_VERSION: u32 = 3;

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

/// Evidence octets. Neither chained nor rebuildable: deleting a row here changes no signed byte
/// (§04 §5.1), and nothing in the chain can put the content back. Decay is the one deletion the
/// system performs and it touches exactly this table.
pub const CONTENT_TABLES: [&str; 1] = ["payloads"];

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
    let mut triggers: BTreeMap<String, usize> = BTreeMap::new();
    let rows = sqlx::query("SELECT tbl_name FROM sqlite_master WHERE type = 'trigger'")
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| Error::new(codes::SCHEMA_MIGRATION_FAILED, e.to_string()))?;
    for row in rows {
        let table: String = row.get(0);
        *triggers.entry(table).or_default() += 1;
    }

    for table in CHAIN_BEARING_TABLES {
        // Two: one for UPDATE, one for DELETE. A table left with one of them is half-protected,
        // which reads as protected.
        match triggers.get(table) {
            Some(&count) if count >= 2 => {}
            _ => {
                return Err(Error::new(
                    codes::SCHEMA_MIGRATION_FAILED,
                    format!(
                        "after migrating, {table} does not carry its append-only triggers. \
                         The migration has been rolled back: a chain-bearing table that can be \
                         rewritten is not a chain."
                    ),
                ));
            }
        }
    }
    Ok(())
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

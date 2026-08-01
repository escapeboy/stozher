//! The v0.3 gate: **an install upgraded across a schema change retains and re-verifies its full
//! chain** — `docs/product-completion-design.md` §3, §4.1.
//!
//! # Why these tests are shaped like this
//!
//! A migration runner is easy to test vacuously. "The store opened and the version went up" is true
//! of a runner that silently dropped every record, and it is true of a runner whose post-apply
//! verification never actually looked at anything. So each positive claim here is paired with the
//! counterfactual that would pass if the mechanism were hollow:
//!
//! * the upgrade **retains** the chain — and an upgrade over a chain someone tampered with is
//!   **refused**, which is what shows the re-verification is load-bearing rather than decorative;
//! * the upgrade **keeps the store append-only** — attempted with an ordinary database client
//!   against every chain-bearing table, after the migration, with a row in each so the `BEFORE`
//!   triggers actually fire;
//! * a migration that disarms a trigger is **rolled back**, not healed — asserted by finding the
//!   store still at its previous version afterwards.
//!
//! The tampering tests have to drop a trigger to do their damage, which is itself the strongest
//! statement of what the triggers are worth: there is no way to corrupt this store through the
//! engine without first disabling the engine's own refusal.

use std::path::{Path, PathBuf};

use serde_json::json;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};
use stozher_core::{chain, jcs};
use stozher_kernel::migrate::{
    self, CHAIN_BEARING_TABLES, CONTENT_TABLES, Migration, REBUILDABLE_TABLES,
};
use stozher_kernel::store::Store;
use stozher_kernel::{checkpoint, codes};
use stozher_testkit::{EFFECT_STREAM, tamper, world_at};

const REJECTION_STREAM: &str = "kernel:rejections";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stozher-migrate-{}-{name}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("stozher.db")
}

/// A connection that bypasses every line of kernel code, as the append-only tests use.
async fn raw(database: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(database))
        .await
        .expect("opening the database directly")
}

/// The registry a *later* kernel would carry: everything shipped, plus one step of exactly the shape
/// §4.1 permits on a chain-bearing table — a nullable column and an index over it. It adds a place to
/// put something; it rewrites nothing, and it touches no signed byte.
fn next_version() -> Vec<Migration> {
    let mut registry = migrate::MIGRATIONS.to_vec();
    registry.push(Migration {
        to_version: migrate::SCHEMA_VERSION + 1,
        name: "additive: an annotation column on envelopes",
        sql: &["ALTER TABLE envelopes ADD COLUMN x_test_annotation TEXT;
             CREATE INDEX IF NOT EXISTS envelopes_by_test_annotation
                 ON envelopes (x_test_annotation);"],
    });
    registry
}

/// A registry whose second step disarms the store — the thing the runner must refuse.
fn disarming() -> Vec<Migration> {
    let mut registry = migrate::MIGRATIONS.to_vec();
    registry.push(Migration {
        to_version: migrate::SCHEMA_VERSION + 1,
        name: "hostile: drop an append-only trigger",
        sql: &["DROP TRIGGER envelopes_are_append_only_no_update;"],
    });
    registry
}

/// Build a store at the shipped schema version holding a real chain, and return its head hash and
/// envelope count. The world is dropped before returning: the old kernel has stopped, which is the
/// state an upgrade actually starts from.
async fn an_install_holding_records(database: &Path) -> (String, u64) {
    let world = world_at(database).await;

    // A row in every chain-bearing table the ordinary paths reach: an accepted effect, a refused
    // one, a published policy (the bootstrap), a registered manifest, a gated effect that consumes
    // an approval, and a checkpoint over the lot.
    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    world
        .reject(
            &tamper(
                &world.last_effect_draft(),
                json!({ "policy-version": "2026.07.99" }),
            ),
            &[],
            "sig-invalid",
        )
        .await;
    let manifest = world.component.sign(&stozher_testkit::manifest_object(
        "github",
        "1.0.0",
        json!({}),
    ));
    let (registration, payloads) = world.register_component(&manifest, true).await;
    world.accept(&registration, &payloads).await;
    let gated = world.gated_effect("github.create_issue", json!({})).await;
    world.accept(&gated, &[]).await;
    checkpoint::emit(world.ingest(), EFFECT_STREAM, "kernel:checkpoints")
        .await
        .expect("emitting a checkpoint")
        .expect("a checkpoint was emitted");

    let (head_seq, _) = world
        .ingest()
        .store()
        .stream_head(EFFECT_STREAM)
        .await
        .expect("reading the head")
        .expect("the stream has a head");
    let envelopes = world
        .ingest()
        .store()
        .range(EFFECT_STREAM, 0, head_seq)
        .await
        .expect("reading the range");
    let head = chain::verify_chain(&envelopes, EFFECT_STREAM, None)
        .expect("the chain verifies before the upgrade")
        .head_hash;
    (head, head_seq + 1)
}

#[tokio::test]
async fn an_install_upgraded_across_a_schema_change_retains_and_reverifies_its_chain() {
    let database = scratch("upgrade");
    let (head_before, count_before) = an_install_holding_records(&database).await;

    let pool = raw(&database).await;
    assert_eq!(
        migrate::version(&pool)
            .await
            .expect("reading the schema version"),
        migrate::SCHEMA_VERSION,
        "the shipped kernel did not stamp the store with its own schema version"
    );

    // The upgrade. `open_with_migrations` verifies every chain after applying and refuses to return
    // a store whose records do not verify, so reaching the `expect` is itself the re-verification —
    // `an_upgrade_over_a_tampered_chain_is_refused` below is what proves that is not vacuous.
    let upgraded = Store::open_with_migrations(&database, REJECTION_STREAM, &next_version())
        .await
        .expect("the upgrade");

    assert_eq!(
        migrate::version(&pool)
            .await
            .expect("reading the schema version"),
        migrate::SCHEMA_VERSION + 1,
        "the store was not stamped with the version it was migrated to"
    );

    // The new column is really there — otherwise this test would pass against a runner that stamped
    // the version and executed nothing.
    sqlx::query("SELECT x_test_annotation FROM envelopes LIMIT 1")
        .fetch_optional(&pool)
        .await
        .expect("the additive column exists after the migration");

    // And the chain is byte-identical to the one the previous version held.
    let (head_seq, _) = upgraded
        .stream_head(EFFECT_STREAM)
        .await
        .expect("reading the head")
        .expect("the stream has a head");
    assert_eq!(
        head_seq + 1,
        count_before,
        "the upgrade did not retain every envelope"
    );
    let envelopes = upgraded
        .range(EFFECT_STREAM, 0, head_seq)
        .await
        .expect("reading the range");
    assert_eq!(
        chain::verify_chain(&envelopes, EFFECT_STREAM, None)
            .expect("the chain verifies after the upgrade")
            .head_hash,
        head_before,
        "the head hash moved across a migration that was supposed to touch no signed byte"
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn an_upgrade_over_a_tampered_chain_is_refused() {
    let database = scratch("tampered");
    an_install_holding_records(&database).await;

    // Corrupting this store requires first disabling the engine's own refusal, which is the whole
    // point of the triggers. The trigger is put back afterwards, so what the migration meets is a
    // store that looks entirely normal and holds one record that is not what was signed.
    let pool = raw(&database).await;
    sqlx::raw_sql("DROP TRIGGER envelopes_are_append_only_no_update;")
        .execute(&pool)
        .await
        .expect("dropping the trigger");
    let stored: String =
        sqlx::query("SELECT canonical_json FROM envelopes WHERE stream = ?1 AND seq = 0")
            .bind(EFFECT_STREAM)
            .fetch_one(&pool)
            .await
            .expect("reading an envelope")
            .get(0);
    let mut envelope = jcs::parse(&stored).expect("the stored envelope parses");
    envelope["emitted-at"] = json!("2026-07-26T09:00:01.000Z");
    let rewritten = jcs::canonicalize(&envelope).expect("re-canonicalizing");
    sqlx::query("UPDATE envelopes SET canonical_json = ?1 WHERE stream = ?2 AND seq = 0")
        .bind(&rewritten)
        .bind(EFFECT_STREAM)
        .execute(&pool)
        .await
        .expect("rewriting the record");
    sqlx::raw_sql(
        "CREATE TRIGGER envelopes_are_append_only_no_update
         BEFORE UPDATE ON envelopes
         BEGIN
             SELECT RAISE(ABORT, 'envelopes are append-only: UPDATE is not a supported operation');
         END;",
    )
    .execute(&pool)
    .await
    .expect("restoring the trigger");

    let refused = Store::open_with_migrations(&database, REJECTION_STREAM, &next_version())
        .await
        .expect_err("the upgrade opened a store whose records do not verify");
    assert_eq!(
        refused.code(),
        "sig-invalid",
        "the upgrade refused for the wrong reason: {refused}"
    );

    // And it refuses *again*, which is the half that was missing and the half that matters.
    //
    // The step and its version stamp commit before the chain can be re-verified — verification needs
    // a `Store`, so it cannot run inside the migration's own transaction. While the stamp was left
    // forward, the second start found nothing to apply, and re-verification is deliberately skipped
    // when nothing was applied: boot two opened and served the chain boot one had just refused. The
    // shipped compose file sets `restart: unless-stopped`, so boot two arrived by itself about a
    // second later, with nobody reading boot one's log line. A refusal has to survive a restart or
    // it is not a refusal.
    Store::open_with_migrations(&database, REJECTION_STREAM, &next_version())
        .await
        .expect_err("the second start served a chain the first start refused");

    // The mechanism, asserted directly rather than through the second refusal's code. The stamp is
    // rewound, so the step is pending again and the check that refused runs again. Asserting the
    // code here would assert something else: this test's fixture step is an `ALTER TABLE ADD
    // COLUMN`, which SQLite cannot express idempotently, so re-applying it fails on the column
    // before reaching the chain. Every step in the shipped registry is `CREATE ... IF NOT EXISTS`
    // and re-applies cleanly — which is a property of that registry that nothing enforces, and a
    // future non-idempotent step would turn this refusal into a different one.
    let pool = raw(&database).await;
    assert_eq!(
        migrate::version(&pool).await.expect("reading the version"),
        migrate::SCHEMA_VERSION,
        "the refused upgrade left its version stamp forward, so the next start would find nothing \
         to apply, skip re-verification, and serve the chain this one refused"
    );
    pool.close().await;

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn a_store_written_by_a_newer_kernel_is_refused() {
    let database = scratch("ahead");
    an_install_holding_records(&database).await;

    let pool = raw(&database).await;
    sqlx::raw_sql("PRAGMA user_version = 99")
        .execute(&pool)
        .await
        .expect("stamping a future version");

    let refused = Store::open(&database, REJECTION_STREAM)
        .await
        .expect_err("an old kernel opened a store it does not understand");
    assert_eq!(refused.code(), codes::SCHEMA_VERSION_AHEAD);
    assert_eq!(
        migrate::version(&pool).await.expect("reading the version"),
        99,
        "the refusal rewrote the version it refused"
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn a_migration_that_disarms_the_append_only_triggers_is_rolled_back() {
    let database = scratch("disarming");
    an_install_holding_records(&database).await;

    let refused = Store::open_with_migrations(&database, REJECTION_STREAM, &disarming())
        .await
        .expect_err("a migration that dropped an append-only trigger was allowed to commit");
    assert_eq!(refused.code(), codes::SCHEMA_MIGRATION_FAILED);

    // Rolled back, not merely reported: the store is still at the version it started at, the
    // trigger is back, and an ordinary client still cannot rewrite the chain.
    let pool = raw(&database).await;
    assert_eq!(
        migrate::version(&pool).await.expect("reading the version"),
        migrate::SCHEMA_VERSION,
        "a refused migration left the store stamped as migrated"
    );
    let error = sqlx::query("UPDATE envelopes SET canonical_json = '{}'")
        .execute(&pool)
        .await
        .expect_err("the engine allowed a rewrite after a refused migration");
    assert!(
        error.to_string().contains("append-only"),
        "the rewrite failed for the wrong reason: {error}"
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn every_chain_bearing_table_still_refuses_rewriting_after_a_migration() {
    let database = scratch("still-append-only");
    an_install_holding_records(&database).await;
    Store::open_with_migrations(&database, REJECTION_STREAM, &next_version())
        .await
        .expect("the upgrade");

    let pool = raw(&database).await;

    // The queue tables are the three no ordinary ingest path fills, and a `BEFORE` trigger that
    // matches no row never fires — so an attempt against an empty table would prove nothing. These
    // rows carry no chain position; what is under test is that the engine refuses to rewrite them.
    for statement in [
        "INSERT INTO gate_requests (request_hash, request_json, submitted_by, received_at, \
         subject, subject_key, component, mandate_ref, policy_version, classification, action, \
         target, args_hash, requested_at, not_after) \
         VALUES ('h', '{}', 's', 't', 'subj', 'k', 'c', 'm', 'p', 'gated', 'a', 'tg', 'ah', 't', 't')",
        "INSERT INTO gate_decisions (request_hash, verdict, reason, decided_by, decided_at, \
         decision_json, envelope_id, recorded_at) \
         VALUES ('h', 'approve', NULL, 'k', 't', '{}', 'e', 't')",
        "INSERT INTO gate_notifications (request_hash, channel, attempted_at, outcome, detail) \
         VALUES ('h', 'c', 't', 'delivered', NULL)",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .expect("seeding a queue table");
    }

    for table in CHAIN_BEARING_TABLES {
        // Anti-vacuity: an attempt against an empty table is not an attempt.
        let count: i64 = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) AS n FROM {table}"
        )))
        .fetch_one(&pool)
        .await
        .expect("counting rows")
        .get("n");
        assert!(
            count > 0,
            "{table} is empty; the attempt would prove nothing"
        );

        for statement in [
            format!("DELETE FROM {table}"),
            // `SET x = x` is a real UPDATE as far as the engine is concerned: the trigger fires
            // before any value is considered, which is exactly the claim under test.
            format!("UPDATE {table} SET received_at = received_at"),
        ] {
            // Not every table has `received_at`; the ones that do not are covered by the DELETE.
            let outcome = sqlx::query(sqlx::AssertSqlSafe(statement.clone()))
                .execute(&pool)
                .await;
            match outcome {
                Ok(_) => panic!("the engine allowed, after a migration: {statement}"),
                Err(e) => {
                    let message = e.to_string();
                    assert!(
                        message.contains("append-only")
                            || message.contains("immutable")
                            || message.contains("retained forever")
                            || message.contains("no such column"),
                        "{statement} failed for the wrong reason: {message}"
                    );
                }
            }
        }
    }

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn a_store_stamped_by_an_earlier_binary_reaches_the_same_schema_as_a_fresh_one() {
    // The upgrade an existing deployment actually performs: it was stamped 1 by a binary that had
    // never heard of step 2, and the next start has to bring it all the way. What this asserts is
    // that a store's schema depends on the registry and not on when it was installed — an operator
    // whose index is missing because they installed in July has a query plan nobody tested.
    //
    // It cannot catch an edit to the *frozen* baseline, because step 1 never runs again on a stamped
    // store and a fresh store here runs today's copy of it. That is what `the_baseline_schema_is_frozen`
    // in `migrate.rs` is for, and the two are only adequate together.
    let fresh_db = scratch("fresh");
    let old_db = scratch("old");

    // Today's kernel, from nothing.
    drop(
        Store::open(&fresh_db, REJECTION_STREAM)
            .await
            .expect("a fresh store"),
    );

    // A store that stopped at version 1, then upgraded — the path a real deployment took.
    let baseline: Vec<Migration> = migrate::MIGRATIONS[..1].to_vec();
    drop(
        Store::open_with_migrations(&old_db, REJECTION_STREAM, &baseline)
            .await
            .expect("a version 1 store"),
    );
    drop(
        Store::open(&old_db, REJECTION_STREAM)
            .await
            .expect("the upgrade"),
    );

    let fresh_pool = raw(&fresh_db).await;
    let old_pool = raw(&old_db).await;
    assert_eq!(
        migrate::version(&fresh_pool).await.expect("a version"),
        migrate::version(&old_pool).await.expect("a version")
    );
    let upgraded = schema_objects(&old_pool).await;
    assert_eq!(
        upgraded,
        schema_objects(&fresh_pool).await,
        "a migrated store and a fresh one do not have the same schema"
    );
    // Equality alone is satisfied by two stores that are equally wrong — a step that did nothing
    // leaves both without the index and both matching. So what this release's step exists to create
    // is named, and its presence asserted rather than implied. A later step adds its object here.
    assert!(
        upgraded
            .iter()
            .any(|(name, _)| name == "envelopes_by_cursor"),
        "the upgraded store has no envelopes_by_cursor: the migration that adds it did not run"
    );

    fresh_pool.close().await;
    old_pool.close().await;
    let _ = std::fs::remove_dir_all(fresh_db.parent().expect("a parent directory"));
    let _ = std::fs::remove_dir_all(old_db.parent().expect("a parent directory"));
}

/// Every table, index and trigger, as the engine records them.
async fn schema_objects(pool: &SqlitePool) -> Vec<(String, String)> {
    let mut objects: Vec<(String, String)> = sqlx::query(
        "SELECT name, COALESCE(sql, '') AS sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(pool)
    .await
    .expect("reading the catalogue")
    .into_iter()
    .map(|row| (row.get::<String, _>(0), row.get::<String, _>(1)))
    .collect();
    objects.sort();
    objects
}

#[tokio::test]
async fn the_classification_covers_every_table_the_database_holds() {
    // §4.1 requires the chain/projection distinction to be stated rather than left as folklore.
    // This is what stops it drifting: add a table to the schema and this fails until it has been
    // classified as chained (additive-only), rebuildable (a fold, droppable) or content (erasable
    // by design, and recoverable from nothing).
    let database = scratch("classification");
    let store = Store::open(&database, REJECTION_STREAM)
        .await
        .expect("a store");
    drop(store);

    let pool = raw(&database).await;
    let present = migrate::tables(&pool).await.expect("the table catalogue");
    let classified: std::collections::BTreeSet<String> = CHAIN_BEARING_TABLES
        .into_iter()
        .chain(REBUILDABLE_TABLES)
        .chain(CONTENT_TABLES)
        .map(str::to_owned)
        .collect();

    assert_eq!(
        present.difference(&classified).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the schema holds a table that migrate.rs does not classify"
    );
    assert_eq!(
        classified.difference(&present).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "migrate.rs classifies a table the schema does not hold"
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

/// The upgrade path an operator will actually take: the shipped binary, twice, over the same store.
///
/// The second open must apply nothing and must therefore verify nothing — re-reading every stream on
/// every restart would turn a boot into a full scan of the audit trail, which on a real log is the
/// difference between a service that restarts and one that appears to hang.
#[tokio::test]
async fn reopening_at_the_current_version_applies_nothing() {
    let database = scratch("idempotent");
    an_install_holding_records(&database).await;

    let pool = raw(&database).await;
    let before = migrate::version(&pool).await.expect("reading the version");
    Store::open(&database, REJECTION_STREAM)
        .await
        .expect("reopening");
    assert_eq!(
        migrate::version(&pool).await.expect("reading the version"),
        before
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

/// A registry that *replaces* the UPDATE guard with a trigger that guards nothing.
///
/// The hostile migration above drops a trigger, which any check that looks for one will catch. This
/// one keeps a trigger of the right name, on the right table, for the right operation — and gives it
/// an empty body. Every structural check passes; the chain becomes writable.
fn disarming_by_substitution() -> Vec<Migration> {
    let mut registry = migrate::MIGRATIONS.to_vec();
    registry.push(Migration {
        to_version: migrate::SCHEMA_VERSION + 1,
        name: "hostile: replace an append-only trigger with an empty one",
        sql: &["DROP TRIGGER envelopes_are_append_only_no_update;
                CREATE TRIGGER envelopes_are_append_only_no_update
                BEFORE UPDATE ON envelopes
                BEGIN
                    SELECT 1;
                END;"],
    });
    registry
}

/// A trigger that exists is not a trigger that refuses.
///
/// The guard this exercises has now been wrong twice, each time by asking a question adjacent to the
/// one that matters. It first counted triggers per table and required two — which stopped meaning
/// anything the moment `envelopes` gained two more. It then asserted the strings "BEFORE UPDATE" and
/// "BEFORE DELETE" appeared in `sqlite_master.sql`, which an empty body satisfies exactly as well as
/// a `RAISE(ABORT)` does. Both answered "a trigger exists". Neither answered "a write is refused",
/// and that is the only property worth asserting.
#[tokio::test]
async fn a_migration_that_replaces_a_guard_with_an_empty_one_is_rolled_back() {
    let database = scratch("substitution");
    an_install_holding_records(&database).await;

    let refused =
        Store::open_with_migrations(&database, REJECTION_STREAM, &disarming_by_substitution())
            .await
            .expect_err("a migration that neutered an append-only trigger was allowed to commit");
    assert_eq!(refused.code(), codes::SCHEMA_MIGRATION_FAILED);

    // Rolled back, not merely reported: an ordinary client still cannot rewrite the chain.
    let pool = raw(&database).await;
    let error = sqlx::query("UPDATE envelopes SET canonical_json = '{}'")
        .execute(&pool)
        .await
        .expect_err("the engine allowed a rewrite after a refused migration");
    assert!(
        error.to_string().contains("append-only"),
        "the rewrite failed for the wrong reason: {error}"
    );
    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

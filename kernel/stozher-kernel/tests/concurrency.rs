//! Concurrency: what the chain, the checkpoints and the gate queue do with more than one writer.
//!
//! Everything here runs against a **file-backed** store (`world_at`), because the properties under
//! test are the storage engine's: WAL, `BEGIN IMMEDIATE`, `synchronous = FULL`, and the two
//! `BEFORE INSERT` triggers schema step 4 added. An in-memory store answers a different question.
//!
//! # These began as a measurement harness, and two of them measured without asserting
//!
//! It was written to *observe* concurrent behaviour, and it found two real defects that way: a
//! contended approval reported to a human as a permanent rejection, and a per-subject park limit
//! that held serially and yielded 2× under concurrency. But the two tests covering exactly those
//! paths only printed their numbers — they passed identically before and after the fixes they
//! exist for. Adopting them as a guard meant giving them the assertions they lacked, which are
//! marked where they appear. A test that cannot fail is a measurement wearing a test's name.
//!
//! Throughput figures are still printed rather than asserted, and deliberately: they are
//! measurements on one machine under whatever else it was running, and a threshold here would fail
//! for reasons that have nothing to do with this code. Read them with `--nocapture`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};
use stozher_core::chain;
use stozher_kernel::{Outcome, checkpoint, migrate, store::Store};
use stozher_testkit::{EFFECT_STREAM, revise, world_at};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stozher-load-{}-{name}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("stozher.db")
}

/// Read every envelope of a stream back and prove it is one unbroken chain: seq strictly increasing
/// by one from zero, no gaps, no duplicates, every `prev-hash` naming its predecessor.
async fn assert_chain_is_whole(store: &Store, stream: &str) -> (u64, String) {
    let (head_seq, head_id) = store
        .stream_head(stream)
        .await
        .expect("reading the head")
        .expect("a populated stream");
    let range = store.range(stream, 0, head_seq).await.expect("the range");
    assert_eq!(
        range.len() as u64,
        head_seq + 1,
        "{stream}: {} rows for a head at seq {head_seq} — a gap or a duplicate",
        range.len()
    );
    let mut seen = BTreeSet::new();
    let mut previous: Option<String> = None;
    for (index, envelope) in range.iter().enumerate() {
        let seq = envelope["seq"].as_u64().expect("seq");
        assert_eq!(seq, index as u64, "{stream}: seq {seq} at position {index}");
        assert!(seen.insert(seq), "{stream}: seq {seq} appears twice");
        let prev = envelope["prev-hash"].as_str().map(str::to_owned);
        assert_eq!(prev, previous, "{stream}: prev-hash at seq {seq} is wrong");
        previous = Some(stozher_core::jcs::object_hash(envelope).expect("id"));
    }
    let verified = chain::verify_chain(&range, stream, None).expect("the chain must verify");
    assert_eq!(verified.head_hash, head_id);
    (head_seq, head_id)
}

// ---------------------------------------------------------------------------------------------
// Scenario 1 — concurrent writers on one stream.
// ---------------------------------------------------------------------------------------------

/// Many emitters, one stream, all racing for the same position. What do the losers get told?
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s1_many_writers_one_position() {
    for racers in [16usize, 64, 128] {
        let database = scratch(&format!("s1-{racers}"));
        let world = Arc::new(world_at(&database).await);
        let base = world.effect("github.get_file", "read", json!({})).await;
        let contenders: Vec<_> = (0..racers)
            .map(|i| {
                revise(
                    &base,
                    json!({ "correlation-ref": format!("racer/{i}") }),
                    &world.agent,
                )
            })
            .collect();

        let started = Instant::now();
        let mut tasks = Vec::with_capacity(racers);
        for envelope in contenders {
            let world = Arc::clone(&world);
            tasks.push(tokio::spawn(
                async move { world.submit(&envelope, &[]).await },
            ));
        }
        let mut accepted = 0usize;
        let mut codes: BTreeMap<String, usize> = BTreeMap::new();
        for task in tasks {
            match task.await.expect("a writer task") {
                Outcome::Accepted(a) => {
                    accepted += 1;
                    assert!(!a.idempotent, "distinct envelopes must not dedup");
                }
                Outcome::Rejected { reason, .. } => *codes.entry(reason).or_default() += 1,
                Outcome::Unavailable(d) => {
                    *codes.entry(format!("UNAVAILABLE: {d}")).or_default() += 1
                }
            }
        }
        let elapsed = started.elapsed();
        println!("S1 racers={racers} accepted={accepted} elapsed={elapsed:?} refusals={codes:?}");
        assert_eq!(accepted, 1, "exactly one writer may take a position");
        assert_eq!(
            codes.get("chain-seq-duplicate").copied().unwrap_or(0),
            racers - 1,
            "every loser must get a retryable chain-seq-duplicate; got {codes:?}"
        );
        assert_chain_is_whole(world.ingest().store(), EFFECT_STREAM).await;
    }
}

/// The realistic shape: many emitters that each read the head, build an envelope and submit,
/// retrying on refusal. The chain must come out contiguous and every refusal must be one an
/// emitter can act on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s1_contending_emitters_build_one_unbroken_chain() {
    const EMITTERS: usize = 24;
    const PER_EMITTER: usize = 25;
    let database = scratch("s1-loop");
    let world = Arc::new(world_at(&database).await);

    let retries = Arc::new(AtomicU64::new(0));
    let codes = Arc::new(std::sync::Mutex::new(BTreeMap::<String, usize>::new()));
    let started = Instant::now();
    let mut tasks = Vec::new();
    for emitter in 0..EMITTERS {
        let world = Arc::clone(&world);
        let retries = Arc::clone(&retries);
        let codes = Arc::clone(&codes);
        tasks.push(tokio::spawn(async move {
            for n in 0..PER_EMITTER {
                loop {
                    let envelope = world
                        .effect(
                            "github.get_file",
                            "read",
                            json!({ "correlation-ref": format!("e{emitter}/{n}") }),
                        )
                        .await;
                    match world.submit(&envelope, &[]).await {
                        Outcome::Accepted(_) => break,
                        Outcome::Rejected { reason, .. } => {
                            *codes.lock().expect("lock").entry(reason).or_default() += 1;
                            retries.fetch_add(1, Ordering::Relaxed);
                        }
                        Outcome::Unavailable(d) => {
                            *codes
                                .lock()
                                .expect("lock")
                                .entry(format!("UNAVAILABLE: {d}"))
                                .or_default() += 1;
                            retries.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }
    for task in tasks {
        task.await.expect("an emitter task");
    }
    let elapsed = started.elapsed();
    let total = (EMITTERS * PER_EMITTER) as u64;
    let refusals = retries.load(Ordering::Relaxed);
    let codes = codes.lock().expect("lock").clone();
    println!(
        "S1-loop emitters={EMITTERS} appended={total} elapsed={elapsed:?} \
         throughput={:.0}/s refusals={refusals} codes={codes:?}",
        total as f64 / elapsed.as_secs_f64()
    );
    let (head, _) = assert_chain_is_whole(world.ingest().store(), EFFECT_STREAM).await;
    assert_eq!(
        head,
        total - 1,
        "every accepted envelope must be in the chain"
    );
    // Every refusal must be a code an emitter can classify as "retry me".
    for code in codes.keys() {
        assert!(
            matches!(
                code.as_str(),
                "chain-seq-duplicate" | "chain-seq-gap" | "chain-prev-hash-mismatch"
            ),
            "an emitter cannot tell 'retry me' from 'you are broken' when it gets {code}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Scenario 2 — many streams at once, and what the step-4 triggers cost.
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s2_many_streams_throughput() {
    const STREAMS: usize = 16;
    const PER_STREAM: usize = 100;
    let database = scratch("s2");
    let world = Arc::new(world_at(&database).await);

    let started = Instant::now();
    let mut tasks = Vec::new();
    for s in 0..STREAMS {
        let world = Arc::clone(&world);
        tasks.push(tokio::spawn(async move {
            let stream = format!("gw:load:{s:04}");
            let mut prev: Option<String> = None;
            for n in 0..PER_STREAM {
                let envelope = world
                    .effect(
                        "github.get_file",
                        "read",
                        json!({
                            "stream": stream,
                            "seq": n,
                            "prev-hash": prev,
                            "correlation-ref": format!("s{s}/{n}")
                        }),
                    )
                    .await;
                match world.submit(&envelope, &[]).await {
                    Outcome::Accepted(a) => prev = Some(a.id),
                    other => panic!("stream {stream} seq {n}: {other:?}"),
                }
            }
            stream
        }));
    }
    let mut streams = Vec::new();
    for task in tasks {
        streams.push(task.await.expect("a stream writer"));
    }
    let elapsed = started.elapsed();
    let total = (STREAMS * PER_STREAM) as u64;
    println!(
        "S2 streams={STREAMS} appended={total} elapsed={elapsed:?} throughput={:.0}/s",
        total as f64 / elapsed.as_secs_f64()
    );
    for stream in &streams {
        assert_chain_is_whole(world.ingest().store(), stream).await;
    }
}

/// What the two `BEFORE INSERT` triggers cost, measured rather than assumed.
///
/// A/B over the *same* insert statement against the *same* schema, differing only in whether
/// migration step 4 ran. `Store::open_with_migrations` makes that possible without DDL surgery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2_trigger_cost() {
    const ROWS: usize = 4_000;
    const REPEATS: usize = 3;

    async fn bench(
        label: &str,
        migrations: &'static [migrate::Migration],
        rows: usize,
        durable: bool,
    ) -> Duration {
        let database = scratch(&format!("triggers-{label}"));
        let store = Store::open_with_migrations(&database, "kernel:rejections", migrations)
            .await
            .expect("a store");
        drop(store); // migrations have run; talk to the file directly from here.
        let pool = SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(&database)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .synchronous(if durable {
                    sqlx::sqlite::SqliteSynchronous::Full
                } else {
                    sqlx::sqlite::SqliteSynchronous::Off
                })
                .busy_timeout(Duration::from_secs(30)),
        )
        .await
        .expect("a raw pool");

        // One transaction per row, as `Store::append` does. With `durable` the fsync floor is in
        // the number, which is what production pays; without it the trigger's own work is what is
        // left, which is what the trigger actually costs.
        let started = Instant::now();
        let mut prev: Option<String> = None;
        for seq in 0..rows {
            let id = format!("{:064x}", seq + 1);
            sqlx::query(
                "INSERT INTO envelopes (stream, seq, id, prev_hash, kind, subject, subject_key, \
                 component, emitted_at, received_at, canonical_json) \
                 VALUES ('gw:bench:0001', ?1, ?2, ?3, 'effect', 's', 'k', 'c', 't', 't', '{}')",
            )
            .bind(seq as i64)
            .bind(&id)
            .bind(prev.as_deref())
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("{label} insert at seq {seq}: {e}"));
            prev = Some(id);
        }
        let elapsed = started.elapsed();
        pool.close().await;
        elapsed
    }

    // The two arms are named by version rather than by position: step 4 adds the `envelopes`
    // INSERT triggers this measures, and everything at or below 3 is the baseline without them.
    // Written as "the last migration" it broke the moment a step 5 was added — correctly, since the
    // comparison would otherwise have silently started measuring something else.
    const TRIGGERS_ADDED_AT: u32 = 4;
    let upto = |version: u32| {
        migrate::MIGRATIONS
            .iter()
            .position(|m| m.to_version > version)
            .unwrap_or(migrate::MIGRATIONS.len())
    };
    let without = &migrate::MIGRATIONS[..upto(TRIGGERS_ADDED_AT - 1)];
    let with = &migrate::MIGRATIONS[..upto(TRIGGERS_ADDED_AT)];
    assert_eq!(
        without.last().map(|m| m.to_version),
        Some(TRIGGERS_ADDED_AT - 1),
        "the baseline arm must stop just before the INSERT triggers"
    );

    let _ = (ROWS, REPEATS, bench as fn(_, _, _, _) -> _);

    // Both arms open at once and interleaved in small blocks, so drift, thermal state and the
    // rest of this machine's load hit both equally. Reported on the *minimum* block: the fastest
    // block is the one least interfered with, and interference only ever adds time.
    const BLOCK: usize = 500;
    const BLOCKS: usize = 24;

    async fn arm(
        label: &str,
        migrations: &'static [migrate::Migration],
        durable: bool,
    ) -> SqlitePool {
        let database = scratch(&format!("ab-{label}"));
        let store = Store::open_with_migrations(&database, "kernel:rejections", migrations)
            .await
            .expect("a store");
        drop(store);
        SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(&database)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .synchronous(if durable {
                    sqlx::sqlite::SqliteSynchronous::Full
                } else {
                    sqlx::sqlite::SqliteSynchronous::Off
                })
                .busy_timeout(Duration::from_secs(30)),
        )
        .await
        .expect("a raw pool")
    }

    async fn block(pool: &SqlitePool, base: usize, rows: usize, prev: &mut Option<String>) -> f64 {
        let started = Instant::now();
        for n in 0..rows {
            let seq = base + n;
            let id = format!("{:064x}", seq + 1);
            sqlx::query(
                "INSERT INTO envelopes (stream, seq, id, prev_hash, kind, subject, subject_key, \
                 component, emitted_at, received_at, canonical_json) \
                 VALUES ('gw:bench:0001', ?1, ?2, ?3, 'effect', 's', 'k', 'c', 't', 't', '{}')",
            )
            .bind(seq as i64)
            .bind(&id)
            .bind(prev.as_deref())
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("insert at seq {seq}: {e}"));
            *prev = Some(id);
        }
        started.elapsed().as_secs_f64() / rows as f64 * 1e6
    }

    for durable in [true, false] {
        let with_pool = arm("with", with, durable).await;
        let without_pool = arm("without", without, durable).await;
        let (mut pa, mut pb) = (None, None);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for i in 0..BLOCKS {
            // Alternate which arm goes first inside each block pair too.
            if i % 2 == 0 {
                a.push(block(&with_pool, i * BLOCK, BLOCK, &mut pa).await);
                b.push(block(&without_pool, i * BLOCK, BLOCK, &mut pb).await);
            } else {
                b.push(block(&without_pool, i * BLOCK, BLOCK, &mut pb).await);
                a.push(block(&with_pool, i * BLOCK, BLOCK, &mut pa).await);
            }
        }
        with_pool.close().await;
        without_pool.close().await;
        let min = |v: &[f64]| v.iter().copied().fold(f64::INFINITY, f64::min);
        let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
        let (mina, minb) = (min(&a), min(&b));
        println!(
            "S2-triggers durable={durable} blocks={BLOCKS}x{BLOCK} rows_per_arm={} \
             with: min={mina:.1} mean={:.1} | without: min={minb:.1} mean={:.1} (us/row) \
             overhead_on_min={:+.1}us/row ({:+.1}%)",
            BLOCKS * BLOCK,
            mean(&a),
            mean(&b),
            mina - minb,
            (mina / minb - 1.0) * 100.0
        );
    }
}

/// What the query planner actually does inside the step-4 triggers. A subquery on every insert is
/// only cheap if it is an index seek; this prints the plan rather than assuming one.
#[tokio::test]
async fn s2_trigger_query_plans() {
    let database = scratch("plans");
    let store = Store::open_with_migrations(&database, "kernel:rejections", migrate::MIGRATIONS)
        .await
        .expect("a store");
    drop(store);
    let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
        .await
        .expect("a raw pool");
    for sql in [
        "EXPLAIN QUERY PLAN SELECT 1 FROM envelopes \
         WHERE stream = 'gw:x' AND seq = 41 AND id = 'abc'",
        "EXPLAIN QUERY PLAN SELECT 1 FROM envelopes WHERE stream = 'gw:x'",
    ] {
        let rows = sqlx::query(sql).fetch_all(&pool).await.expect("a plan");
        for row in rows {
            println!("S2-plan [{sql}] -> {}", row.get::<String, _>("detail"));
        }
    }
    pool.close().await;
}

// ---------------------------------------------------------------------------------------------
// Scenario 3 — idempotent retry under concurrency (spec/04 §3).
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s3_identical_bytes_from_many_clients() {
    const CLIENTS: usize = 32;
    let database = scratch("s3");
    let world = Arc::new(world_at(&database).await);
    let envelope = Arc::new(world.effect("github.get_file", "read", json!({})).await);

    let mut tasks = Vec::new();
    for _ in 0..CLIENTS {
        let world = Arc::clone(&world);
        let envelope = Arc::clone(&envelope);
        tasks.push(tokio::spawn(
            async move { world.submit(&envelope, &[]).await },
        ));
    }
    let mut ids = BTreeSet::new();
    let mut fresh = 0usize;
    let mut idempotent = 0usize;
    let mut other: BTreeMap<String, usize> = BTreeMap::new();
    for task in tasks {
        match task.await.expect("a client task") {
            Outcome::Accepted(a) => {
                ids.insert(a.id.clone());
                if a.idempotent {
                    idempotent += 1;
                } else {
                    fresh += 1;
                }
                assert_eq!(a.seq, 0, "every caller must be told the same position");
            }
            Outcome::Rejected { reason, .. } => *other.entry(reason).or_default() += 1,
            Outcome::Unavailable(d) => *other.entry(format!("UNAVAILABLE: {d}")).or_default() += 1,
        }
    }
    println!("S3 clients={CLIENTS} fresh={fresh} idempotent={idempotent} other={other:?}");
    assert!(other.is_empty(), "no caller may get an error: {other:?}");
    assert_eq!(fresh, 1, "exactly one caller writes the row");
    assert_eq!(idempotent, CLIENTS - 1);
    assert_eq!(ids.len(), 1, "every caller must be given the same id");

    // Exactly one row, by counting the table directly.
    let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
        .await
        .expect("a raw connection");
    let count: i64 = sqlx::query("SELECT count(*) FROM envelopes WHERE stream = ?1")
        .bind(EFFECT_STREAM)
        .fetch_one(&pool)
        .await
        .expect("counting")
        .get(0);
    pool.close().await;
    assert_eq!(
        count, 1,
        "{CLIENTS} identical submissions left {count} rows"
    );
}

// ---------------------------------------------------------------------------------------------
// Scenario 4 — checkpoints under load (spec/04 §4).
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s4_checkpoints_while_the_chain_moves() {
    const APPENDS: usize = 300;
    let database = scratch("s4");
    let world = Arc::new(world_at(&database).await);
    let checkpoint_stream = "kernel:checkpoints";

    let stop = Arc::new(AtomicUsize::new(0));
    let emitted = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(std::sync::Mutex::new(BTreeMap::<String, usize>::new()));

    // One checkpointer, the shape `run_interval` runs.
    let checkpointer = {
        let world = Arc::clone(&world);
        let stop = Arc::clone(&stop);
        let emitted = Arc::clone(&emitted);
        let failures = Arc::clone(&failures);
        tokio::spawn(async move {
            while stop.load(Ordering::Relaxed) == 0 {
                match checkpoint::emit(world.ingest(), EFFECT_STREAM, checkpoint_stream).await {
                    Ok(Some(_)) => {
                        emitted.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        *failures
                            .lock()
                            .expect("lock")
                            .entry(e.code().to_owned())
                            .or_default() += 1;
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    };

    let started = Instant::now();
    for n in 0..APPENDS {
        let envelope = world
            .effect(
                "github.get_file",
                "read",
                json!({ "correlation-ref": format!("c/{n}") }),
            )
            .await;
        match world.submit(&envelope, &[]).await {
            Outcome::Accepted(_) => {}
            other => panic!("append {n}: {other:?}"),
        }
    }
    stop.store(1, Ordering::Relaxed);
    checkpointer.await.expect("the checkpointer");
    let elapsed = started.elapsed();

    let store = world.ingest().store();
    assert_chain_is_whole(store, EFFECT_STREAM).await;
    assert_chain_is_whole(store, checkpoint_stream).await;

    // Every checkpoint over the effect stream: its head-hash must be the real head at to-seq, and
    // the ranges must tile [0, ..] contiguously without overlap.
    let (cp_head, _) = store
        .stream_head(checkpoint_stream)
        .await
        .expect("head")
        .expect("checkpoints exist");
    let checkpoints = store
        .range(checkpoint_stream, 0, cp_head)
        .await
        .expect("range");
    let mut expected_from = 0u64;
    let mut checked = 0usize;
    for envelope in &checkpoints {
        let cp = &envelope["checkpoint"];
        if cp["stream"].as_str() != Some(EFFECT_STREAM) {
            continue;
        }
        let from = cp["from-seq"].as_u64().expect("from-seq");
        let to = cp["to-seq"].as_u64().expect("to-seq");
        let head_hash = cp["head-hash"].as_str().expect("head-hash");
        let count = cp["count"].as_u64().expect("count");
        assert_eq!(
            from, expected_from,
            "checkpoint ranges must be contiguous and not overlap"
        );
        assert_eq!(count, to - from + 1, "count must match the range");
        // The head-hash must be the id of the envelope that really sits at to-seq.
        let row = store.range(EFFECT_STREAM, to, to).await.expect("the row");
        assert_eq!(
            row.len(),
            1,
            "checkpoint names to-seq {to}, which does not exist"
        );
        let real = stozher_core::jcs::object_hash(&row[0]).expect("id");
        assert_eq!(
            head_hash, real,
            "checkpoint at to-seq {to} names a head that never existed there"
        );
        expected_from = to + 1;
        checked += 1;
    }
    let failures = failures.lock().expect("lock").clone();
    println!(
        "S4 appends={APPENDS} elapsed={elapsed:?} checkpoints_over_effect_stream={checked} \
         emitted={} emit_failures={failures:?}",
        emitted.load(Ordering::Relaxed)
    );
    assert!(
        checked > 0,
        "the checkpointer never caught up with the writer"
    );
}

/// Two checkpoint emitters at once — the shape a running kernel really has, because
/// `run_interval` and `run_decay_interval` are separate tasks that both call `checkpoint::emit`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s4_two_checkpoint_emitters_race() {
    const ROUNDS: usize = 150;
    let database = scratch("s4-race");
    let world = Arc::new(world_at(&database).await);
    let checkpoint_stream = "kernel:checkpoints";

    const EMITTERS: usize = 16;
    let mut failures: BTreeMap<String, usize> = BTreeMap::new();
    let (mut emitted, mut nothing_to_do) = (0usize, 0usize);
    for n in 0..ROUNDS {
        let envelope = world
            .effect(
                "github.get_file",
                "read",
                json!({ "correlation-ref": format!("r/{n}") }),
            )
            .await;
        world.accept(&envelope, &[]).await;

        // A writer keeps moving the head while the emitters run, so `emit`'s two separate reads of
        // the checkpoint stream's head have a window to straddle.
        let writer = {
            let world = Arc::clone(&world);
            tokio::spawn(async move {
                for k in 0..3 {
                    let envelope = world
                        .effect(
                            "github.get_file",
                            "read",
                            json!({ "correlation-ref": format!("w/{k}") }),
                        )
                        .await;
                    let _ = world.submit(&envelope, &[]).await;
                }
            })
        };
        let mut tasks = Vec::new();
        for _ in 0..EMITTERS {
            let world = Arc::clone(&world);
            tasks.push(tokio::spawn(async move {
                checkpoint::emit(world.ingest(), EFFECT_STREAM, checkpoint_stream).await
            }));
        }
        for task in tasks {
            match task.await.expect("an emitter task") {
                Ok(Some(_)) => emitted += 1,
                Ok(None) => nothing_to_do += 1,
                Err(e) => *failures.entry(e.code().to_owned()).or_default() += 1,
            }
        }
        writer.await.expect("the writer");
    }
    // Whatever the emitters got told, the two chains must still be whole.
    let store = world.ingest().store();
    assert_chain_is_whole(store, EFFECT_STREAM).await;
    let (cp_head, _) = assert_chain_is_whole(store, checkpoint_stream).await;

    // `emit` reads `last_checkpoint` outside any transaction, so two emitters can both compute
    // `from_seq` from the same answer. §04 §4 wants ranges that tile: contiguous, non-overlapping.
    let checkpoints = store
        .range(checkpoint_stream, 0, cp_head)
        .await
        .expect("range");
    let mut expected_from = 0u64;
    let mut overlaps = 0usize;
    let mut gaps = 0usize;
    let mut bad_heads = 0usize;
    let mut covered = 0usize;
    for envelope in &checkpoints {
        let cp = &envelope["checkpoint"];
        if cp["stream"].as_str() != Some(EFFECT_STREAM) {
            continue;
        }
        let from = cp["from-seq"].as_u64().expect("from-seq");
        let to = cp["to-seq"].as_u64().expect("to-seq");
        if from < expected_from {
            overlaps += 1;
        } else if from > expected_from {
            gaps += 1;
        }
        let row = store.range(EFFECT_STREAM, to, to).await.expect("the row");
        let real = row
            .first()
            .map(|e| stozher_core::jcs::object_hash(e).expect("id"));
        if real.as_deref() != cp["head-hash"].as_str() {
            bad_heads += 1;
        }
        expected_from = expected_from.max(to + 1);
        covered += 1;
    }
    println!(
        "S4-race rounds={ROUNDS} emitters_per_round={EMITTERS} emitted={emitted} \
         nothing_to_do={nothing_to_do} failures={failures:?} \
         checkpoints_over_effect_stream={covered} overlapping_ranges={overlaps} \
         gaps_between_ranges={gaps} head_hash_never_existed={bad_heads}"
    );
    assert_eq!(
        bad_heads, 0,
        "a checkpoint names a head that was never at its to-seq"
    );
    assert_eq!(overlaps, 0, "{overlaps} checkpoint ranges overlap");
    assert_eq!(gaps, 0, "{gaps} gaps between checkpoint ranges");
}

/// The same race with a *moving* clock.
///
/// With the fixed clock, concurrent emitters build byte-identical checkpoints and dedup, which
/// hides the contention a running kernel has: `observed-at` differs per emitter, so the envelopes
/// differ and two of them really do want the same position on the checkpoint stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s4_checkpoint_emitters_race_with_a_moving_clock() {
    const ROUNDS: usize = 60;
    const EMITTERS: usize = 8;
    let database = scratch("s4-clock");
    let world = Arc::new(world_at(&database).await);
    let checkpoint_stream = "kernel:checkpoints";

    let mut failures: BTreeMap<String, usize> = BTreeMap::new();
    let (mut emitted, mut nothing_to_do) = (0usize, 0usize);
    for n in 0..ROUNDS {
        let envelope = world
            .effect(
                "github.get_file",
                "read",
                json!({ "correlation-ref": format!("mc/{n}") }),
            )
            .await;
        world.accept(&envelope, &[]).await;

        let ticking = {
            let world = Arc::clone(&world);
            tokio::spawn(async move {
                for _ in 0..50 {
                    world.clock.advance_seconds(1);
                    tokio::task::yield_now().await;
                }
            })
        };
        let mut tasks = Vec::new();
        for _ in 0..EMITTERS {
            let world = Arc::clone(&world);
            tasks.push(tokio::spawn(async move {
                checkpoint::emit(world.ingest(), EFFECT_STREAM, checkpoint_stream).await
            }));
        }
        for task in tasks {
            match task.await.expect("an emitter task") {
                Ok(Some(_)) => emitted += 1,
                Ok(None) => nothing_to_do += 1,
                Err(e) => *failures.entry(e.code().to_owned()).or_default() += 1,
            }
        }
        ticking.await.expect("the ticker");
    }
    println!(
        "S4-clock rounds={ROUNDS} emitters_per_round={EMITTERS} emitted={emitted} \
         nothing_to_do={nothing_to_do} failures={failures:?}"
    );
    // Whatever the emitters were told, the chain the auditor reads must still be whole.
    assert_chain_is_whole(world.ingest().store(), EFFECT_STREAM).await;
    assert_chain_is_whole(world.ingest().store(), checkpoint_stream).await;
}

// ---------------------------------------------------------------------------------------------
// Scenario 5 — decay while writing (spec/04 §5.1).
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s5_decay_concurrent_with_ingest() {
    const ROUNDS: usize = 120;
    let database = scratch("s5");
    let world = Arc::new(world_at(&database).await);
    let checkpoint_stream = "kernel:checkpoints";

    // Signals carry payloads with a retain-until, which is what decay erases.
    let stop = Arc::new(AtomicUsize::new(0));
    let decay_errors = Arc::new(std::sync::Mutex::new(BTreeMap::<String, usize>::new()));
    let deleted = Arc::new(AtomicU64::new(0));
    let decayer = {
        let world = Arc::clone(&world);
        let stop = Arc::clone(&stop);
        let errors = Arc::clone(&decay_errors);
        let deleted = Arc::clone(&deleted);
        tokio::spawn(async move {
            while stop.load(Ordering::Relaxed) == 0 {
                match checkpoint::decay_with_checkpoints(world.ingest(), checkpoint_stream).await {
                    Ok(report) => {
                        deleted.fetch_add(report.payloads_deleted as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        *errors
                            .lock()
                            .expect("lock")
                            .entry(e.code().to_owned())
                            .or_default() += 1;
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };

    let started = Instant::now();
    for n in 0..ROUNDS {
        // Half the payloads are already past their retain-until at the fixed clock's NOW, so decay
        // has real work while ingest is running.
        let retain = if n % 2 == 0 {
            "2026-07-01T00:00:00.000Z"
        } else {
            "2026-08-25T00:00:00.000Z"
        };
        let payload = json!({ "n": n, "body": "x".repeat(256) });
        let hash = stozher_core::jcs::object_hash(&payload).expect("payload hash");
        let envelope = world
            .signal(&payload, json!({ "signal": { "retain-until": retain } }))
            .await;
        let wire = json!({
            "payload-hash": hash,
            "media-type": "application/json",
            "payload": payload
        });
        match world.submit(&envelope, &[wire]).await {
            Outcome::Accepted(_) => {}
            other => panic!("signal {n}: {other:?}"),
        }
    }
    stop.store(1, Ordering::Relaxed);
    decayer.await.expect("the decayer");
    let elapsed = started.elapsed();

    let store = world.ingest().store();
    let (head, head_id) = assert_chain_is_whole(store, stozher_testkit::SIGNAL_STREAM).await;
    let errors = decay_errors.lock().expect("lock").clone();
    println!(
        "S5 signals={ROUNDS} elapsed={elapsed:?} payloads_deleted={} \
         decay_errors={errors:?} head=({head}, {})",
        deleted.load(Ordering::Relaxed),
        &head_id[..12]
    );

    // §5.1: verification must not need payloads. Erase every payload row outright and verify again.
    let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
        .await
        .expect("a raw connection");
    sqlx::query("DELETE FROM payloads")
        .execute(&pool)
        .await
        .expect("erasing payloads");
    let remaining: i64 = sqlx::query("SELECT count(*) FROM payloads")
        .fetch_one(&pool)
        .await
        .expect("counting")
        .get(0);
    pool.close().await;
    assert_eq!(remaining, 0);
    let (head_after, head_id_after) =
        assert_chain_is_whole(store, stozher_testkit::SIGNAL_STREAM).await;
    assert_eq!(
        (head, head_id),
        (head_after, head_id_after),
        "the head moved when payloads went"
    );
}

// ---------------------------------------------------------------------------------------------
// Scenario 6 — the gate queue under load (spec/06 §3, §4.3).
// ---------------------------------------------------------------------------------------------

mod gate {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use stozher_core::jcs;
    use stozher_kernel::http;
    use stozher_testkit::{Ask, TOKEN, World};
    use tower::ServiceExt;

    async fn post_json(world: &World, uri: &str, body: &Value) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(jcs::canonicalize(body).expect("canonicalizing")))
            .expect("a request");
        let response = http::router(Arc::clone(&world.kernel))
            .oneshot(request)
            .await
            .expect("the router responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn get(world: &World, uri: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .expect("a request");
        let response = http::router(Arc::clone(&world.kernel))
            .oneshot(request)
            .await
            .expect("the router responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn request_for(world: &World, action: &str, nth: usize) -> Value {
        let draft = world
            .effect(
                action,
                "consequential",
                json!({ "execution": { "target": format!("repo:acme/n{nth}") } }),
            )
            .await;
        world.action_request(&Ask {
            requester: &world.agent,
            component: "gateway",
            mandate_ref: &world.standing_mandate,
            policy_version: &world.policy_version,
            classification: "consequential",
            action,
            target: draft["execution"]["target"].as_str().expect("target"),
            args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
        })
    }

    /// Many consequential calls parking at once. Not one may be lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn s6_concurrent_parks_lose_nothing() {
        const PARKS: usize = 64;
        let database = scratch("s6-park");
        let world = Arc::new(world_at(&database).await);

        let mut requests = Vec::new();
        for n in 0..PARKS {
            requests.push(request_for(&world, "github.create_issue", n).await);
        }
        let expected: BTreeSet<String> = requests
            .iter()
            .map(|r| jcs::object_hash(r).expect("a request hash"))
            .collect();
        assert_eq!(expected.len(), PARKS, "the fixtures collide");

        let started = Instant::now();
        let mut tasks = Vec::new();
        for request in requests {
            let world = Arc::clone(&world);
            tasks.push(tokio::spawn(async move {
                post_json(&world, "/v1/gate/requests", &request).await
            }));
        }
        let mut statuses: BTreeMap<u16, usize> = BTreeMap::new();
        for task in tasks {
            let (status, _) = task.await.expect("a park task");
            *statuses.entry(status.as_u16()).or_default() += 1;
        }
        let elapsed = started.elapsed();

        let (status, page) = get(&world, "/console/pending").await;
        assert_eq!(status, StatusCode::OK);
        let present = expected.iter().filter(|h| page.contains(*h)).count();
        let accepted = statuses.get(&201).copied().unwrap_or(0);
        println!(
            "S6-park parks={PARKS} elapsed={elapsed:?} statuses={statuses:?} \
             accepted={accepted} in_pending_queue={present} \
             configured_cap={} per {}s",
            world.kernel.config.gate_rate_limit.per_subject,
            world.kernel.config.gate_rate_limit.window_seconds
        );
        // Nothing that was accepted may be missing from the queue. That is the property.
        assert_eq!(
            present,
            accepted,
            "{} accepted parks are not in the queue",
            accepted - present
        );
    }

    /// The per-subject park cap, offered concurrently against offered one at a time.
    ///
    /// `post_gate_request` reads `gate_requests_since` on its own connection and then inserts in a
    /// separate call, so the check and the write are not one transaction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn s6_the_park_rate_limit_under_concurrency() {
        const OFFERED: usize = 64;

        async fn build(world: &World, n: usize) -> Value {
            request_for(world, "github.create_issue", n).await
        }

        // (a) one at a time.
        let database = scratch("s6-rl-serial");
        let world = Arc::new(world_at(&database).await);
        let cap = world.kernel.config.gate_rate_limit.per_subject;
        let mut serial: BTreeMap<u16, usize> = BTreeMap::new();
        for n in 0..OFFERED {
            let request = build(&world, n).await;
            let (status, _) = post_json(&world, "/v1/gate/requests", &request).await;
            *serial.entry(status.as_u16()).or_default() += 1;
        }

        // (b) all at once.
        let database = scratch("s6-rl-concurrent");
        let world = Arc::new(world_at(&database).await);
        let mut requests = Vec::new();
        for n in 0..OFFERED {
            requests.push(build(&world, n).await);
        }
        let mut tasks = Vec::new();
        for request in requests {
            let world = Arc::clone(&world);
            tasks.push(tokio::spawn(async move {
                post_json(&world, "/v1/gate/requests", &request).await
            }));
        }
        let mut concurrent: BTreeMap<u16, usize> = BTreeMap::new();
        for task in tasks {
            let (status, _) = task.await.expect("a park task");
            *concurrent.entry(status.as_u16()).or_default() += 1;
        }
        let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
            .await
            .expect("a raw connection");
        let rows: i64 = sqlx::query("SELECT count(*) FROM gate_requests")
            .fetch_one(&pool)
            .await
            .expect("counting")
            .get(0);
        pool.close().await;
        println!(
            "S6-ratelimit cap={cap} offered={OFFERED} \
             one_at_a_time={serial:?} all_at_once={concurrent:?} parked_rows_when_concurrent={rows}"
        );

        // The assertions, without which this measures rather than guards. It ran for a while as a
        // print-only harness and passed identically before and after the fix it exists for.
        //
        // §09 §7's cap is a limit on how many decisions one subject may put in front of a human.
        // Counted outside the insert's transaction it held only for a caller that waited for each
        // answer: 64 offered one at a time were capped at 30, and the same 64 offered together put
        // 63 rows in the queue, because every one of them read the count before any had written. A
        // limit that yields under concurrency is absent in the one circumstance it exists for.
        assert!(
            rows <= i64::from(cap),
            "the cap is {cap} and {rows} requests were parked when {OFFERED} arrived at once"
        );
        assert_eq!(
            serial.get(&201).copied().unwrap_or_default(),
            cap as usize,
            "the serial arm must reach the cap exactly, or this proves nothing about the other"
        );
    }

    /// Approvals arriving concurrently for one parked request. A decision is a human saying this
    /// once, so exactly one may be recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn s6_concurrent_decisions_on_one_request() {
        const APPROVERS: usize = 16;
        let database = scratch("s6-decide");
        let world = Arc::new(world_at(&database).await);
        let request = request_for(&world, "github.create_issue", 0).await;
        let hash = jcs::object_hash(&request).expect("hash");
        let (status, body) = post_json(&world, "/v1/gate/requests", &request).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let mut tasks = Vec::new();
        for _ in 0..APPROVERS {
            let world = Arc::clone(&world);
            let hash = hash.clone();
            let decision = world.decide(&request, "approve", None, &world.root);
            tasks.push(tokio::spawn(async move {
                let body = json!({
                    "csrf": world.kernel.csrf_token("agent:test-harness", &hash),
                    "decision": decision
                });
                post_json(&world, &format!("/console/pending/{hash}/decide"), &body).await
            }));
        }
        let mut statuses: BTreeMap<u16, usize> = BTreeMap::new();
        for task in tasks {
            let (status, _) = task.await.expect("an approver task");
            *statuses.entry(status.as_u16()).or_default() += 1;
        }

        let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
            .await
            .expect("a raw connection");
        let rows: i64 = sqlx::query("SELECT count(*) FROM gate_decisions WHERE request_hash = ?1")
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .expect("counting")
            .get(0);
        pool.close().await;
        println!("S6-decide approvers={APPROVERS} statuses={statuses:?} decision_rows={rows}");
        assert_eq!(
            rows, 1,
            "{APPROVERS} concurrent approvals recorded {rows} decisions"
        );
    }

    /// Approvals arriving concurrently for *different* parked requests. Every one of them becomes
    /// a `gate-decision` envelope on the single kernel core stream, and `submit_decision` retries
    /// a chain position only eight times — so this is where the queue's throughput ceiling is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn s6_divergent_decisions_contend_for_the_core_stream() {
        // The baseline profile caps a subject at 30 parks per 300s, so 30 is the most this can
        // put on the core stream at once without measuring the rate limiter instead.
        for approvers in [8usize, 16, 24, 30, 16, 16] {
            let database = scratch(&format!("s6-core-{approvers}"));
            let world = Arc::new(world_at(&database).await);

            let mut parked = Vec::new();
            for n in 0..approvers {
                let request = request_for(&world, "github.create_issue", n).await;
                let hash = jcs::object_hash(&request).expect("hash");
                let (status, body) = post_json(&world, "/v1/gate/requests", &request).await;
                assert_eq!(status, StatusCode::CREATED, "park {n}: {body}");
                parked.push((request, hash));
            }

            let started = Instant::now();
            let mut tasks = Vec::new();
            for (request, hash) in parked.clone() {
                let world = Arc::clone(&world);
                let decision = world.decide(&request, "approve", None, &world.root);
                tasks.push(tokio::spawn(async move {
                    let body = json!({
                        "csrf": world.kernel.csrf_token("agent:test-harness", &hash),
                        "decision": decision
                    });
                    post_json(&world, &format!("/console/pending/{hash}/decide"), &body).await
                }));
            }
            let mut statuses: BTreeMap<u16, usize> = BTreeMap::new();
            let mut bodies = Vec::new();
            for task in tasks {
                let (status, body) = task.await.expect("an approver task");
                *statuses.entry(status.as_u16()).or_default() += 1;
                bodies.push((status, body));
            }
            let elapsed = started.elapsed();

            let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
                .await
                .expect("a raw connection");
            let rows: i64 = sqlx::query("SELECT count(*) FROM gate_decisions")
                .fetch_one(&pool)
                .await
                .expect("counting")
                .get(0);
            pool.close().await;
            let mut failures: BTreeMap<String, usize> = BTreeMap::new();
            let mut retryable_flags: BTreeSet<String> = BTreeSet::new();
            for (status, body) in bodies.iter().filter(|(s, _)| !s.is_success()) {
                *failures
                    .entry(format!("{} {}", status.as_u16(), first_code(body)))
                    .or_default() += 1;
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    retryable_flags.insert(format!("retryable={}", v["retryable"]));
                }
            }
            println!(
                "S6-core approvers={approvers} elapsed={elapsed:?} statuses={statuses:?} \
                 decision_rows={rows} lost={} failures={failures:?} {retryable_flags:?}",
                approvers as i64 - rows
            );
            assert_chain_is_whole(world.ingest().store(), stozher_testkit::CORE_STREAM).await;

            // The assertion this test was missing. Losing a decision under contention is tolerable
            // — the approver can press the button again. Telling them it was *permanently* rejected
            // is not: the handler answered 422 with `retryable: false` and a chain code, so a human
            // who had just signed an approval was informed their approval was refused, while the
            // decision went unrecorded. Contention is not a verdict on what they signed.
            for (status, body) in bodies.iter().filter(|(s, _)| !s.is_success()) {
                let code = first_code(body);
                assert!(
                    !code.starts_with("chain-"),
                    "a contended decision was refused with {code} ({status}), which reports \
                     transient contention as a permanent rejection of what the approver signed"
                );
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    assert_ne!(
                        v["retryable"], false,
                        "a decision that was not recorded was reported as not retryable: {body}"
                    );
                }
            }
        }
    }

    /// Two humans answering one request at the same moment, one approving and one denying. The
    /// decision table is keyed on the request, so only one verdict can be in force — and both
    /// approvers must be able to tell which.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn s6_two_humans_answer_one_request_at_once() {
        const RUNS: usize = 10;
        let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
        for run in 0..RUNS {
            let database = scratch(&format!("s6-split-{run}"));
            let world = Arc::new(world_at(&database).await);
            let request = request_for(&world, "github.create_issue", run).await;
            let hash = jcs::object_hash(&request).expect("hash");
            let (status, body) = post_json(&world, "/v1/gate/requests", &request).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");

            let approve = world.decide(&request, "approve", None, &world.root);
            let deny = world.decide(&request, "deny", Some("no"), &world.second_root);
            let mut tasks = Vec::new();
            for decision in [approve, deny] {
                let world = Arc::clone(&world);
                let hash = hash.clone();
                tasks.push(tokio::spawn(async move {
                    let body = json!({
                        "csrf": world.kernel.csrf_token("agent:test-harness", &hash),
                        "decision": decision
                    });
                    post_json(&world, &format!("/console/pending/{hash}/decide"), &body).await
                }));
            }
            let mut told_recorded = 0usize;
            for task in tasks {
                let (status, body) = task.await.expect("an approver task");
                if status.is_success() {
                    told_recorded += 1;
                    let verdict = serde_json::from_str::<Value>(&body)
                        .ok()
                        .and_then(|v| v["decision"].as_str().map(str::to_owned))
                        .unwrap_or_default();
                    *outcomes.entry(format!("201 {verdict}")).or_default() += 1;
                } else {
                    *outcomes
                        .entry(format!("{} {}", status.as_u16(), first_code(&body)))
                        .or_default() += 1;
                }
            }

            let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
                .await
                .expect("a raw connection");
            let stored: Vec<String> =
                sqlx::query("SELECT verdict FROM gate_decisions WHERE request_hash = ?1")
                    .bind(&hash)
                    .fetch_all(&pool)
                    .await
                    .expect("reading")
                    .into_iter()
                    .map(|r| r.get::<String, _>(0))
                    .collect();
            pool.close().await;
            assert_eq!(
                stored.len(),
                1,
                "run {run}: {} verdicts in force",
                stored.len()
            );
            *outcomes
                .entry(format!(
                    "in_force={} told_recorded={told_recorded}",
                    stored[0]
                ))
                .or_default() += 1;
        }
        println!("S6-split runs={RUNS} {outcomes:?}");
    }

    fn first_code(body: &str) -> String {
        serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| {
                v["code"]
                    .as_str()
                    .or_else(|| v["reason"].as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| body.chars().take(40).collect())
    }

    /// One single-use approval, presented by several emitters at once. `gate_request_hashes` is
    /// single-use, so exactly one effect may land and the rest must be told it was replayed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn s6_one_approval_cannot_be_spent_twice() {
        const SPENDERS: usize = 16;
        let database = scratch("s6-replay");
        let world = Arc::new(world_at(&database).await);
        let approved = world.gated_effect("github.create_issue", json!({})).await;

        // Each spender puts the same approval on its own stream, so the only thing they contend
        // for is the approval itself and not a chain position.
        let mut tasks = Vec::new();
        for n in 0..SPENDERS {
            let world = Arc::clone(&world);
            let envelope = stozher_testkit::revise(
                &approved,
                json!({ "stream": format!("gw:spend:{n:04}"), "seq": 0, "prev-hash": Value::Null }),
                &world.agent,
            );
            tasks.push(tokio::spawn(
                async move { world.submit(&envelope, &[]).await },
            ));
        }
        let mut accepted = 0usize;
        let mut codes: BTreeMap<String, usize> = BTreeMap::new();
        for task in tasks {
            match task.await.expect("a spender task") {
                Outcome::Accepted(a) => {
                    accepted += 1;
                    assert!(!a.idempotent);
                }
                Outcome::Rejected { reason, .. } => *codes.entry(reason).or_default() += 1,
                Outcome::Unavailable(d) => {
                    *codes.entry(format!("UNAVAILABLE: {d}")).or_default() += 1;
                }
            }
        }
        // Scoped to *this* approval: the bootstrap's own policy publication carries one too.
        let request_hash =
            jcs::object_hash(&approved["authorization"]["request"]).expect("the request hash");
        let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&database))
            .await
            .expect("a raw connection");
        let uses: i64 =
            sqlx::query("SELECT count(*) FROM gate_request_hashes WHERE request_hash = ?1")
                .bind(&request_hash)
                .fetch_one(&pool)
                .await
                .expect("counting")
                .get(0);
        pool.close().await;
        println!(
            "S6-replay spenders={SPENDERS} accepted={accepted} replay_rows={uses} codes={codes:?}"
        );
        assert_eq!(accepted, 1, "an approval was spent {accepted} times");
        assert_eq!(
            codes
                .get("gate-authorization-replayed")
                .copied()
                .unwrap_or(0),
            SPENDERS - 1,
            "the losers must be told the approval was replayed; got {codes:?}"
        );
        assert_eq!(uses, 1, "the replay set holds {uses} rows for one approval");
    }
}

// ---------------------------------------------------------------------------------------------
// Scenario 7 — what breaks first.
// ---------------------------------------------------------------------------------------------

/// Raise the concurrency on one stream until something other than a chain code comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn s7_push_until_something_breaks() {
    for concurrency in [32usize, 64, 128, 256, 512] {
        let database = scratch(&format!("s7-{concurrency}"));
        let world = Arc::new(world_at(&database).await);
        let base = world.effect("github.get_file", "read", json!({})).await;

        let started = Instant::now();
        let mut tasks = Vec::with_capacity(concurrency);
        for i in 0..concurrency {
            let world = Arc::clone(&world);
            let envelope = revise(
                &base,
                json!({ "correlation-ref": format!("push/{i}") }),
                &world.agent,
            );
            tasks.push(tokio::spawn(
                async move { world.submit(&envelope, &[]).await },
            ));
        }
        let mut codes: BTreeMap<String, usize> = BTreeMap::new();
        let mut accepted = 0usize;
        for task in tasks {
            match task.await.expect("a task") {
                Outcome::Accepted(_) => accepted += 1,
                Outcome::Rejected { reason, .. } => *codes.entry(reason).or_default() += 1,
                Outcome::Unavailable(d) => {
                    let head = d.chars().take(60).collect::<String>();
                    *codes.entry(format!("UNAVAILABLE: {head}")).or_default() += 1;
                }
            }
        }
        let elapsed = started.elapsed();
        println!(
            "S7 concurrency={concurrency} accepted={accepted} elapsed={elapsed:?} codes={codes:?}"
        );
        assert_eq!(accepted, 1);
        assert_chain_is_whole(world.ingest().store(), EFFECT_STREAM).await;
        let unavailable: usize = codes
            .iter()
            .filter(|(k, _)| k.starts_with("UNAVAILABLE"))
            .map(|(_, v)| *v)
            .sum();
        if unavailable > 0 {
            println!("S7 first failure at concurrency={concurrency}: {unavailable} unavailable");
        }
    }
}

/// Sustained sequential append rate against a file-backed store, for the throughput baseline the
/// concurrent numbers are compared to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7_sequential_baseline() {
    const N: usize = 1_000;
    let database = scratch("s7-seq");
    let world = world_at(&database).await;
    let started = Instant::now();
    for n in 0..N {
        let envelope = world
            .effect(
                "github.get_file",
                "read",
                json!({ "correlation-ref": format!("b/{n}") }),
            )
            .await;
        world.accept(&envelope, &[]).await;
    }
    let elapsed = started.elapsed();
    let size = std::fs::metadata(&database).map(|m| m.len()).unwrap_or(0);
    println!(
        "S7-baseline appended={N} elapsed={elapsed:?} throughput={:.0}/s db_bytes={size}",
        N as f64 / elapsed.as_secs_f64()
    );
    assert_chain_is_whole(world.ingest().store(), EFFECT_STREAM).await;
}

/// A silence-check on the value `Value` shape the assertions above assume.
#[allow(dead_code)]
fn _shape(_: &Value) {}

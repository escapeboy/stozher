//! Concurrency: appends to one stream must not interleave into a broken chain.
//!
//! §04 §1 says a stream has exactly one writer, which is what lets `seq` be assigned without
//! coordination. This file assumes that rule is *violated* — by a buggy emitter, a duplicated
//! process, or a retry storm — and requires the store to stay correct anyway. Correct here means: one
//! winner per position, everyone else refused with a chain code, and a chain that still verifies.
//!
//! The guarantee comes from two things working together, and the tests fail if either is removed:
//! every write runs inside `BEGIN IMMEDIATE`, so a writer cannot observe a head another writer is
//! about to move; and `PRIMARY KEY (stream, seq)` means two envelopes cannot occupy one position even
//! if the lock were somehow lost.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::json;
use stozher_core::chain;
use stozher_kernel::Outcome;
use stozher_testkit::{EFFECT_STREAM, revise, world};

/// How many writers race for the same position.
const RACERS: usize = 16;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_one_writer_can_take_a_chain_position() {
    let world = Arc::new(world().await);

    // Sixteen distinct envelopes, all claiming seq 0 of the same stream. Each is individually valid;
    // they are mutually exclusive only because of where they want to sit.
    let base = world.effect("github.get_file", "read", json!({})).await;
    let contenders: Vec<_> = (0..RACERS)
        .map(|index| {
            revise(
                &base,
                json!({ "correlation-ref": format!("racer/{index}") }),
                &world.agent,
            )
        })
        .collect();

    let mut tasks = Vec::with_capacity(RACERS);
    for envelope in contenders {
        let world = Arc::clone(&world);
        tasks.push(tokio::spawn(
            async move { world.submit(&envelope, &[]).await },
        ));
    }

    let mut accepted = Vec::new();
    let mut refusals = Vec::new();
    for task in tasks {
        match task.await.expect("a writer task") {
            Outcome::Accepted(appended) => accepted.push(appended),
            Outcome::Rejected { reason, .. } => refusals.push(reason),
            Outcome::Unavailable(detail) => panic!("store unavailable under contention: {detail}"),
        }
    }

    assert_eq!(
        accepted.len(),
        1,
        "exactly one writer may take a position; {} did, refusals were {refusals:?}",
        accepted.len()
    );
    assert_eq!(refusals.len(), RACERS - 1);
    for reason in &refusals {
        assert_eq!(
            reason, "chain-seq-duplicate",
            "a loser must be told its position was taken, not something vaguer"
        );
    }

    // And the chain is a chain.
    let store = world.ingest().store();
    let (head_seq, head_id) = store
        .stream_head(EFFECT_STREAM)
        .await
        .expect("reading the head")
        .expect("a populated stream");
    assert_eq!(head_seq, 0, "only one envelope landed");
    assert_eq!(head_id, accepted[0].id);
    let range = store
        .range(EFFECT_STREAM, 0, 0)
        .await
        .expect("reading the range");
    assert_eq!(
        chain::verify_chain(&range, EFFECT_STREAM, None)
            .expect("the chain verifies after the race")
            .head_hash,
        head_id
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sequential_writer_under_contention_still_builds_an_unbroken_chain() {
    let world = Arc::new(world().await);

    // A well-behaved writer racing against a crowd of stale retries: the retries must never break the
    // chain the good writer is building. This is the realistic shape of the failure — a queue that
    // re-submits, not sixteen coordinated attackers.
    let mut landed = Vec::new();
    for round in 0..12u32 {
        let envelope = world.effect("github.get_file", "read", json!({})).await;
        let stale = landed.last().cloned();

        let good = {
            let world = Arc::clone(&world);
            let envelope = envelope.clone();
            tokio::spawn(async move { world.submit(&envelope, &[]).await })
        };
        // Concurrent retries of the *previous* envelope, which is already in the chain. These are the
        // realistic noise — a queue that re-delivers — and they contend for a position that is taken,
        // not for the one the good writer is claiming. Contention for the *same* position is a
        // different property, proven in `only_one_writer_can_take_a_chain_position`.
        let mut retries = Vec::new();
        for _ in 0..3 {
            if let Some(previous) = stale.clone() {
                let world = Arc::clone(&world);
                retries.push(tokio::spawn(
                    async move { world.submit(&previous, &[]).await },
                ));
            }
        }

        match good.await.expect("the good writer") {
            Outcome::Accepted(appended) => {
                assert!(
                    !appended.idempotent,
                    "a fresh envelope must not be reported as already present"
                );
                assert_eq!(appended.seq, u64::from(round));
                landed.push(envelope);
            }
            other => panic!("the good writer was refused in round {round}: {other:?}"),
        }
        // A byte-identical retry is idempotent, not a conflict (§04 §3).
        for task in retries {
            match task.await.expect("a retry") {
                Outcome::Accepted(appended) => assert!(
                    appended.idempotent,
                    "re-submitting identical bytes must not create a second row"
                ),
                other => panic!("an identical retry must succeed idempotently: {other:?}"),
            }
        }
    }

    let store = world.ingest().store();
    let range = store
        .range(EFFECT_STREAM, 0, 11)
        .await
        .expect("reading the range");
    assert_eq!(range.len(), 12);
    let result = chain::verify_chain(&range, EFFECT_STREAM, None)
        .expect("the chain must verify after twelve contended rounds");
    assert_eq!(result.count, 12);
    // No gaps, no reuse: the positions are exactly 0..12.
    let positions: BTreeSet<u64> = range.iter().filter_map(|e| e["seq"].as_u64()).collect();
    assert_eq!(positions, (0..12).collect::<BTreeSet<u64>>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_approval_cannot_be_consumed_twice_however_the_requests_race() {
    let world = Arc::new(world().await);

    // The replay set's PRIMARY KEY is the enforcement, so this holds no matter how the pre-checks
    // interleave: eight tasks submit eight *different* envelopes carrying the *same* approval.
    let gated = world.gated_effect("github.create_issue", json!({})).await;
    let contenders: Vec<_> = (0..8usize)
        .map(|index| {
            revise(
                &gated,
                json!({ "correlation-ref": format!("replay/{index}") }),
                &world.agent,
            )
        })
        .collect();

    let mut tasks = Vec::new();
    for envelope in contenders {
        let world = Arc::clone(&world);
        tasks.push(tokio::spawn(
            async move { world.submit(&envelope, &[]).await },
        ));
    }

    let mut accepted = 0usize;
    let mut reasons = Vec::new();
    for task in tasks {
        match task.await.expect("a submitter") {
            Outcome::Accepted(_) => accepted += 1,
            Outcome::Rejected { reason, .. } => reasons.push(reason),
            Outcome::Unavailable(detail) => panic!("store unavailable: {detail}"),
        }
    }

    assert_eq!(
        accepted, 1,
        "one signature is one action; {accepted} were applied, refusals were {reasons:?}"
    );
    for reason in &reasons {
        assert!(
            // They all wanted seq 0 as well, so either refusal is correct — and either way the
            // approval was consumed exactly once.
            reason == "gate-authorization-replayed" || reason == "chain-seq-duplicate",
            "unexpected refusal {reason}"
        );
    }
    assert!(
        reasons.iter().any(|r| r == "gate-authorization-replayed"),
        "at least one loser must be refused for the replay itself, not only for the position"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_streams_do_not_block_each_other() {
    // Streams are independent: there is no global total order and none is needed (§04 §1). Writers on
    // different streams must all succeed.
    let world = Arc::new(world().await);
    let mut tasks = Vec::new();
    for index in 0..8u32 {
        let world = Arc::clone(&world);
        tasks.push(tokio::spawn(async move {
            let stream = format!("gw:worker-{index}:0001");
            let envelope = world
                .effect(
                    "github.get_file",
                    "read",
                    json!({ "stream": stream, "seq": 0, "prev-hash": null }),
                )
                .await;
            world.submit(&envelope, &[]).await
        }));
    }
    for task in tasks {
        match task.await.expect("a writer") {
            Outcome::Accepted(appended) => assert_eq!(appended.seq, 0),
            other => panic!("an independent stream was blocked: {other:?}"),
        }
    }
    let streams = world
        .ingest()
        .store()
        .streams()
        .await
        .expect("listing streams");
    let workers = streams
        .iter()
        .filter(|s| {
            s["stream"]
                .as_str()
                .is_some_and(|name| name.starts_with("gw:worker-"))
        })
        .count();
    assert_eq!(workers, 8);
}

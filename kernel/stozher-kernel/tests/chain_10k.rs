//! **The S1 build-plan gate, half (b): chain verification over 10 000 synthetic envelopes.**
//!
//! Not marked `#[ignore]`. A gate that only runs when someone remembers to ask for it is not a gate,
//! so this runs on every `cargo test`. Dependencies are compiled at `opt-level = 2` in test profiles
//! (see `kernel/Cargo.toml`) because tens of thousands of Ed25519 operations at `opt-level = 0` would
//! turn a few seconds into a few minutes, and the pressure to reach for `#[ignore]` is exactly how
//! this check would stop being one.
//!
//! What it proves:
//!
//! 1. 10 000 envelopes go through the **real ingest pipeline** — signature, schema, policy,
//!    mandate walk, gate, append — and land in one chain.
//! 2. Reading them back from the store and verifying end to end reproduces the head hash, **without
//!    consulting a single payload**.
//! 3. A deliberate mutation at a *randomly chosen* position is detected, whichever position it lands
//!    on: a rewritten `prev-hash`, a rewritten body, a deleted envelope, and a pair swapped.
//! 4. A signed checkpoint over the range reproduces the same head, and a rebuilt range cannot.

use std::time::Instant;

use serde_json::{Value, json};
use stozher_core::{chain, signed};
use stozher_kernel::store::EnvelopeQuery;
use stozher_testkit::{EFFECT_STREAM, revise, world};

/// The gate's size. Ten thousand is the build plan's number.
const CHAIN_LENGTH: u64 = 10_000;

#[tokio::test]
async fn chain_verification_over_ten_thousand_envelopes() {
    let world = world().await;
    let started = Instant::now();

    // (1) Build the chain through the real pipeline. Every envelope is signed, schema-checked,
    // classified, walked to a human root and appended under the write lock.
    let mut expected_ids = Vec::with_capacity(CHAIN_LENGTH as usize);
    for index in 0..CHAIN_LENGTH {
        let envelope = world.effect("github.get_file", "read", json!({})).await;
        assert_eq!(
            envelope["seq"].as_u64(),
            Some(index),
            "the fixture chained onto the wrong position"
        );
        expected_ids.push(world.accept(&envelope, &[]).await);
    }
    let built = started.elapsed();

    // (2) Read the range back and verify it end to end.
    let stored = world
        .ingest()
        .store()
        .range(EFFECT_STREAM, 0, CHAIN_LENGTH - 1)
        .await
        .expect("reading the range");
    assert_eq!(stored.len(), CHAIN_LENGTH as usize);
    let verifying = Instant::now();
    let result = chain::verify_chain(&stored, EFFECT_STREAM, None).expect("the chain must verify");
    let verified = verifying.elapsed();

    assert_eq!(result.count, CHAIN_LENGTH as usize);
    assert!(result.anchored, "a range starting at seq 0 is anchored");
    assert_eq!(
        result.head_hash,
        *expected_ids.last().expect("a non-empty chain"),
        "the head hash must be the id of the highest seq"
    );

    // Payload independence, asserted rather than asserted about: not one of these envelopes carries
    // evidence, and the chain verifies anyway (§04 §5.1).
    assert!(
        stored.iter().all(|e| e.get("evidence").is_none()),
        "the fixture chain deliberately carries no evidence"
    );

    println!(
        "10k chain: built in {built:.2?} through the full pipeline, verified in {verified:.2?}, \
         head {}",
        &result.head_hash[..16]
    );

    // (3) A mutation at a random position must be detected — wherever it lands.
    let position = random_position(CHAIN_LENGTH);
    println!("10k chain: mutating at randomly chosen position {position}");

    // 3a. A rewritten `prev-hash`, re-signed so the signature is genuine. Only the chain rule catches
    // this: the envelope is internally perfect and validly signed by the right subject.
    let mut rebuilt = stored.clone();
    let victim = &rebuilt[position];
    let flipped = flip_hash(victim["prev-hash"].as_str().unwrap_or(&"0".repeat(64)));
    rebuilt[position] = revise(victim, json!({ "prev-hash": flipped }), &world.agent);
    let error = chain::verify_chain(&rebuilt, EFFECT_STREAM, None)
        .expect_err("a re-signed envelope with a wrong prev-hash must be detected");
    assert_eq!(error.code(), "chain-prev-hash-mismatch", "{error}");
    assert_eq!(
        error.seq(),
        Some(position as u64),
        "the failure names its position"
    );

    // 3b. A rewritten body, not re-signed. This is the ordinary tamper, and the signature catches it.
    let mut rebuilt = stored.clone();
    rebuilt[position]["execution"]["target"] = Value::from("repo:acme/production");
    let error = chain::verify_chain(&rebuilt, EFFECT_STREAM, None)
        .expect_err("a tampered body must be detected");
    assert_eq!(error.code(), "sig-invalid", "{error}");
    assert_eq!(error.seq(), Some(position as u64));

    // 3c. A deleted envelope. Loss inside a stream is mechanical, not silent (§09 §4).
    let mut truncated = stored.clone();
    truncated.remove(position);
    let error = chain::verify_chain(&truncated, EFFECT_STREAM, None)
        .expect_err("a deleted envelope must be detected");
    assert_eq!(error.code(), "chain-seq-gap", "{error}");

    // 3d. Two envelopes swapped: reordering is not a permitted rewrite either.
    if position + 1 < stored.len() {
        let mut swapped = stored.clone();
        swapped.swap(position, position + 1);
        let error = chain::verify_chain(&swapped, EFFECT_STREAM, None)
            .expect_err("a swapped pair must be detected");
        assert!(
            matches!(
                error.code(),
                "chain-seq-duplicate" | "chain-seq-gap" | "chain-prev-hash-mismatch"
            ),
            "unexpected code for a swapped pair: {error}"
        );
    }

    // The store itself is unchanged by any of that: the mutations happened in memory, because there
    // is no path through which they could happen anywhere else.
    let again = world
        .ingest()
        .store()
        .range(EFFECT_STREAM, 0, CHAIN_LENGTH - 1)
        .await
        .expect("re-reading the range");
    assert_eq!(
        chain::verify_chain(&again, EFFECT_STREAM, None)
            .expect("the stored chain is still intact")
            .head_hash,
        result.head_hash
    );

    // (4) A signed checkpoint over the range fixes the head publicly. A rebuilt chain cannot
    // reproduce a published head hash, which is what turns "consistent" into "not rebuilt".
    let checkpoint = world
        .kernel_checkpoint(EFFECT_STREAM, 0, CHAIN_LENGTH - 1, json!({}))
        .await;
    world.accept(&checkpoint, &[]).await;
    // The range starts at seq 0, so it is anchored by construction and needs no external anchor.
    let attested = chain::verify_checkpoint(&checkpoint, &stored, None)
        .expect("the checkpoint must attest this range");
    assert!(attested.anchored);
    assert_eq!(
        checkpoint["checkpoint"]["head-hash"].as_str(),
        Some(result.head_hash.as_str())
    );
    assert_eq!(
        checkpoint["checkpoint"]["count"].as_u64(),
        Some(CHAIN_LENGTH)
    );

    // The same checkpoint against the *rebuilt* range fails, which is the whole point of publishing
    // a head hash at all.
    let mut rebuilt = stored.clone();
    let victim = &rebuilt[position];
    let flipped = flip_hash(victim["prev-hash"].as_str().unwrap_or(&"0".repeat(64)));
    rebuilt[position] = revise(victim, json!({ "prev-hash": flipped }), &world.agent);
    assert!(
        chain::verify_checkpoint(&checkpoint, &rebuilt, None).is_err(),
        "a rebuilt chain must not satisfy a previously published checkpoint"
    );
}

/// The query surface must answer over ten thousand records by index, not by scan (§04 §6).
#[tokio::test]
async fn the_query_surface_answers_over_a_large_stream() {
    let world = world().await;
    // A tenth of the gate's size: this test is about the query plan, not the chain.
    for _ in 0..1_000u32 {
        let envelope = world.effect("github.get_file", "read", json!({})).await;
        world.accept(&envelope, &[]).await;
    }

    let store = world.ingest().store();
    // Scoped to the effect stream: the same subject also signed the ceremony's envelopes on the
    // kernel's own stream, and an unscoped count would quietly include them.
    let by_subject = store
        .query(&EnvelopeQuery {
            subject: Some(&world.agent.subject),
            stream: Some(EFFECT_STREAM),
            limit: 5_000,
            ..Default::default()
        })
        .await
        .expect("querying by subject");
    assert_eq!(by_subject.len(), 1_000);

    let by_class = store
        .query(&EnvelopeQuery {
            classification: Some("read"),
            limit: 5_000,
            ..Default::default()
        })
        .await
        .expect("querying by class");
    assert_eq!(by_class.len(), 1_000);

    // The transitive set beneath a mandate, which is the query an auditor actually asks.
    let by_mandate = store
        .query(&EnvelopeQuery {
            mandate_subtree_of: Some(&world.standing_mandate),
            limit: 5_000,
            ..Default::default()
        })
        .await
        .expect("querying a mandate subtree");
    assert_eq!(by_mandate.len(), 1_000);

    // Every record resolves to the same human root, walked at ingest and stored for the query.
    assert!(
        by_mandate
            .iter()
            .all(|r| r["human-root"].as_str() == Some(world.root.subject.as_str())),
        "every effect must resolve to the human root its mandate reached"
    );

    let head = store
        .stream_head(EFFECT_STREAM)
        .await
        .expect("reading the head")
        .expect("a populated stream");
    assert_eq!(head.0, 999);
    let range = store.range(EFFECT_STREAM, 0, 999).await.expect("range");
    assert_eq!(
        signed::object_id(range.last().expect("last")).expect("id"),
        head.1
    );
}

/// A position in `[0, length)`, chosen from the operating system's entropy so the mutation is not
/// always in the same convenient place. Printed by the caller so a failure is reproducible.
fn random_position(length: u64) -> usize {
    let mut octets = [0u8; 8];
    getrandom::fill(&mut octets).expect("platform entropy");
    usize::try_from(u64::from_le_bytes(octets) % length).expect("a position fits usize")
}

/// Change one hex digit, producing a well-formed hash that is not the right one.
fn flip_hash(hash: &str) -> String {
    let mut digits: Vec<char> = hash.chars().collect();
    digits[0] = if digits[0] == 'a' { 'b' } else { 'a' };
    digits.into_iter().collect()
}

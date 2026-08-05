//! "Lawfully deleted" and "never recorded" must not look the same to an auditor. DEF-17.
//!
//! Found by the clinical design partner on 2026-08-04, evaluating this for a regulated trial:
//! `GET /v1/payloads/<hash>` returned a byte-identical `410 decayed` for a hash that had never
//! existed. So the route said *"this content was recorded and its retention has passed"* about
//! something the kernel had never seen — a confident answer to a question it could not answer, which
//! is the one thing this system is not supposed to give.
//!
//! It matters most exactly where the product claims to be strongest. `README.md` sells retention as
//! *"closed loops decay to signed hashes"*: the hash stays as the commitment, so an auditor holding
//! the content can still prove it is the content that was recorded. That argument only works if
//! `410` means the commitment exists. If it also means "no idea", the commitment proves nothing —
//! and a subject asking whether their data was ever processed gets the same page either way.
//!
//! # The fix needed no new bookkeeping
//!
//! `payload_refs` is written when an envelope commits to a payload and is **never deleted** — the
//! decay sweep removes rows from `payloads` alone, which is why chain verification is unaffected.
//! So the tombstone was already there and nothing was reading it. The route now asks.

use serde_json::json;
use stozher_core::jcs;
use stozher_kernel::clock::Clock;
use stozher_testkit::{World, world};

/// An accepted effect carrying a payload, returning its hash.
async fn effect_with_payload(world: &World, title: &str, retain_until: &str) -> String {
    let body = json!({ "title": title });
    let hash = jcs::object_hash(&body).expect("payload hash");
    let envelope = world
        .gated_effect(
            "github.create_issue",
            json!({ "evidence": {
                "schema": "github.create_issue.v1",
                "media-type": "application/json",
                "payload-hash": hash,
                "retain-until": retain_until
            } }),
        )
        .await;
    world
        .accept(
            &envelope,
            &[json!({
                "payload-hash": hash,
                "media-type": "application/json",
                "payload": body
            })],
        )
        .await;
    hash
}

#[tokio::test]
async fn a_hash_that_was_never_recorded_is_unknown_and_not_decayed() {
    let world = world().await;
    let never = "f".repeat(64);

    assert!(
        !world
            .ingest()
            .store()
            .payload_was_committed(&never)
            .await
            .expect("reading the commitment record"),
        "a hash no envelope ever cited reads as committed"
    );
}

#[tokio::test]
async fn a_decayed_payload_is_still_recorded_as_having_existed() {
    let world = world().await;
    let hash = effect_with_payload(&world, "expired", "2026-08-01T00:00:00.000Z").await;

    // The control first: without this the assertion below could pass on a store that records
    // everything as committed, including the hash in the test above.
    assert!(
        world
            .ingest()
            .store()
            .payload(&hash)
            .await
            .expect("reading a payload")
            .is_some(),
        "the payload should be stored before the sweep; otherwise this test proves nothing"
    );

    world.clock.advance_seconds(60 * 60 * 24 * 30);
    let decayed = world
        .ingest()
        .store()
        .decay_payloads(world.clock.now().as_str())
        .await
        .expect("the sweep");
    assert!(
        decayed.contains(&hash),
        "the payload did not decay: {decayed:?}"
    );

    assert!(
        world
            .ingest()
            .store()
            .payload(&hash)
            .await
            .expect("reading a payload")
            .is_none(),
        "the bytes survived the sweep"
    );
    assert!(
        world
            .ingest()
            .store()
            .payload_was_committed(&hash)
            .await
            .expect("reading the commitment record"),
        "a decayed payload reads as one that never existed — the commitment the hash is supposed to \
         be has nothing behind it, and a subject asking whether their data was processed gets the \
         same answer as one whose data never was"
    );
}

//! Append-only enforcement, and decay to hash.
//!
//! Two claims that are easy to make and easy to make falsely, so both are attacked here rather than
//! asserted:
//!
//! * **Append-only is enforced by the storage engine.** The test opens the kernel's own database with
//!   an ordinary database client — no kernel code in the way — and tries to UPDATE and DELETE the
//!   chain. If the guarantee lived in this crate's good manners, that would succeed.
//! * **Chain integrity does not depend on payload presence.** The test records the head hash, erases
//!   every payload, and verifies the chain again. The head must be byte-identical, and verification
//!   must not have read anything from the payload store to get it.

use std::path::PathBuf;

use serde_json::json;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};
use stozher_core::{chain, jcs};
use stozher_kernel::checkpoint;
use stozher_testkit::{EFFECT_STREAM, World, tamper, world_at};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stozher-store-{}-{name}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("stozher.db")
}

/// An envelope whose signature covers different bytes, so submitting it is refused and recorded.
fn effect_without_signature(world: &World) -> serde_json::Value {
    // Built from a fixture the world already produced; mutated after signing.
    tamper(
        &world.last_effect_draft(),
        json!({ "policy-version": "2026.07.99" }),
    )
}

/// A connection to the database that bypasses every line of kernel code.
async fn raw(database: &PathBuf) -> SqlitePool {
    let options = SqliteConnectOptions::new().filename(database);
    SqlitePool::connect_with(options)
        .await
        .expect("opening the database directly")
}

#[tokio::test]
async fn the_storage_engine_refuses_to_rewrite_history() {
    let database = scratch("append-only");
    let world = world_at(&database).await;
    let effect = world.effect("github.get_file", "read", json!({})).await;
    let id = world.accept(&effect, &[]).await;

    // Put a row in every protected table first. A `BEFORE DELETE` trigger fires per row, so a DELETE
    // that matches nothing succeeds trivially — testing an empty table would prove nothing.
    world
        .reject(&effect_without_signature(&world), &[], "sig-invalid")
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

    let pool = raw(&database).await;
    for statement in [
        "SELECT COUNT(*) AS n FROM envelopes",
        "SELECT COUNT(*) AS n FROM rejections",
        "SELECT COUNT(*) AS n FROM checkpoints",
        "SELECT COUNT(*) AS n FROM policies",
        "SELECT COUNT(*) AS n FROM manifests",
        "SELECT COUNT(*) AS n FROM gate_request_hashes",
    ] {
        let count: i64 = sqlx::query(statement)
            .fetch_one(&pool)
            .await
            .expect("counting rows")
            .get("n");
        assert!(
            count > 0,
            "{statement} returned 0; the test would prove nothing"
        );
    }

    // Every statement that would rewrite the chain, attempted directly. §04 §3 requires this to be
    // enforced "at the storage layer (SQLite triggers / Postgres rules), not merely in application
    // code" — so an ordinary client must fail too.
    let attempts = [
        "UPDATE envelopes SET canonical_json = '{}' WHERE id = ?1",
        "UPDATE envelopes SET prev_hash = NULL WHERE id = ?1",
        "UPDATE envelopes SET seq = 99 WHERE id = ?1",
        "DELETE FROM envelopes WHERE id = ?1",
    ];
    for statement in attempts {
        let error = sqlx::query(statement)
            .bind(&id)
            .execute(&pool)
            .await
            .expect_err(&format!("the engine allowed: {statement}"));
        let message = error.to_string();
        assert!(
            message.contains("append-only"),
            "{statement} failed for the wrong reason: {message}"
        );
    }

    // The same protection covers the rejection chain, the checkpoints, published policy versions,
    // registered manifests, and the gate replay set — everything whose forgetting would matter.
    let protected = [
        ("DELETE FROM rejections", "append-only"),
        ("DELETE FROM checkpoints", "append-only"),
        ("DELETE FROM policies", "retained forever"),
        ("DELETE FROM manifests", "retained forever"),
        ("DELETE FROM gate_request_hashes", "append-only"),
        ("UPDATE policies SET document_json = '{}'", "immutable"),
        (
            "UPDATE gate_request_hashes SET single_use = 0",
            "append-only",
        ),
    ];
    for (statement, expected) in protected {
        let error = sqlx::query(statement)
            .execute(&pool)
            .await
            .expect_err(&format!("the engine allowed: {statement}"));
        assert!(
            error.to_string().contains(expected),
            "{statement} failed for the wrong reason: {error}"
        );
    }

    // And the chain is still exactly what it was.
    let stored = world
        .ingest()
        .store()
        .range(EFFECT_STREAM, 0, 0)
        .await
        .expect("reading the range");
    assert_eq!(
        chain::verify_chain(&stored, EFFECT_STREAM, None)
            .expect("the chain verifies")
            .head_hash,
        id
    );

    pool.close().await;
    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn payload_decay_leaves_the_hash_and_the_chain_position_intact() {
    let database = scratch("decay");
    let world = world_at(&database).await;

    // A chain of gated effects, each with an evidence payload, plus one without — so the range mixes
    // envelopes that will decay with envelopes that never had a payload.
    let mut payload_hashes = Vec::new();
    for index in 0..5u32 {
        let body = json!({ "title": format!("issue {index}") });
        let hash = jcs::object_hash(&body).expect("payload hash");
        let envelope = world
            .gated_effect(
                "github.create_issue",
                json!({ "evidence": {
                    "schema": "github.create_issue.v1",
                    "media-type": "application/json",
                    "payload-hash": hash,
                    "retain-until": "2026-08-01T00:00:00.000Z"
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
        payload_hashes.push(hash);
    }
    let bare = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&bare, &[]).await;

    let store = world.ingest().store();
    let (head_seq, _) = store
        .stream_head(EFFECT_STREAM)
        .await
        .expect("reading the head")
        .expect("a populated stream");

    // Every payload is present, and the chain has a head.
    for hash in &payload_hashes {
        assert!(
            store
                .payload(hash)
                .await
                .expect("reading a payload")
                .is_some(),
            "payload {hash} should be stored"
        );
    }
    let before = store
        .range(EFFECT_STREAM, 0, head_seq)
        .await
        .expect("reading the range");
    let head_before = chain::verify_chain(&before, EFFECT_STREAM, None)
        .expect("the chain verifies with payloads present")
        .head_hash;

    // Move past every `retain-until` and run the decay, which checkpoints first (§04 §4.6).
    world.clock.advance_seconds(60 * 60 * 24 * 30);
    let report = checkpoint::decay_with_checkpoints(world.ingest(), "kernel:checkpoints")
        .await
        .expect("the decay run");
    assert_eq!(
        report.payloads_deleted,
        payload_hashes.len(),
        "every expired payload must be erased"
    );
    assert!(
        !report.streams_checkpointed.is_empty(),
        "deletion must be preceded by a checkpoint of every affected stream"
    );

    // The payloads are gone.
    for hash in &payload_hashes {
        assert!(
            store
                .payload(hash)
                .await
                .expect("reading a payload")
                .is_none(),
            "payload {hash} should have decayed"
        );
    }

    // The chain is byte-identical. This is the GDPR property: deleting a payload changes no byte of
    // any envelope, so no `id()`, no `prev-hash`, no `sig` and no head hash changes (§04 §5.1).
    let after = store
        .range(EFFECT_STREAM, 0, head_seq)
        .await
        .expect("re-reading the range");
    assert_eq!(
        before, after,
        "not one envelope byte may change when a payload is erased"
    );
    let head_after = chain::verify_chain(&after, EFFECT_STREAM, None)
        .expect("the chain still verifies with every payload erased")
        .head_hash;
    assert_eq!(
        head_before, head_after,
        "the head hash must be identical before and after decay"
    );

    // The commitment survives: an auditor who independently holds the content can still prove it is
    // the content that was recorded (§04 §5.4).
    for (index, hash) in payload_hashes.iter().enumerate() {
        let envelope = &after[index];
        assert_eq!(
            envelope["evidence"]["payload-hash"].as_str(),
            Some(hash.as_str()),
            "the hash must remain in the envelope after the payload is gone"
        );
    }

    // The pre-deletion head is publicly fixed, so a later attempt to replace the tail contradicts a
    // published checkpoint.
    let checkpoint = store
        .last_checkpoint(EFFECT_STREAM)
        .await
        .expect("reading the checkpoint")
        .expect("a checkpoint was emitted before deletion");
    assert_eq!(checkpoint.2, head_after);

    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn a_payload_survives_while_any_referencing_envelope_still_needs_it() {
    // Deduplication is by hash, so deletion has to be reference-counted: a payload two envelopes
    // share must outlive the shorter retention (§04 §5.2).
    let database = scratch("refcount");
    let world = world_at(&database).await;

    let body = json!({ "title": "shared evidence" });
    let hash = jcs::object_hash(&body).expect("payload hash");
    let payload = json!({
        "payload-hash": hash,
        "media-type": "application/json",
        "payload": body
    });

    // The first reference expires soon; the second holds it for a year.
    for retain_until in ["2026-08-01T00:00:00.000Z", "2027-07-01T00:00:00.000Z"] {
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
            .accept(&envelope, std::slice::from_ref(&payload))
            .await;
    }

    world.clock.advance_seconds(60 * 60 * 24 * 30);
    let report = checkpoint::decay_with_checkpoints(world.ingest(), "kernel:checkpoints")
        .await
        .expect("the first decay run");
    assert_eq!(
        report.payloads_deleted, 0,
        "a payload must not be deleted while a referencing envelope still needs it"
    );
    assert!(
        world
            .ingest()
            .store()
            .payload(&hash)
            .await
            .expect("reading the payload")
            .is_some()
    );

    // Past the longer retention, it goes.
    world.clock.advance_seconds(60 * 60 * 24 * 365);
    let report = checkpoint::decay_with_checkpoints(world.ingest(), "kernel:checkpoints")
        .await
        .expect("the second decay run");
    assert_eq!(report.payloads_deleted, 1);

    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

#[tokio::test]
async fn rejections_are_chained_records_and_are_queryable() {
    // §04 §7: a rejection carries the reason code, the hash of the rejected bytes, the submitting
    // subject and the timestamp; it is appended to the kernel's own stream, chained, and visible.
    let database = scratch("rejections");
    let world = world_at(&database).await;

    let gated = world.gated_effect("github.create_issue", json!({})).await;
    let bare = stozher_testkit::without(&gated, "authorization", &world.agent);
    world.reject(&bare, &[], "gate-authorization-missing").await;
    world
        .ingest()
        .submit(b"{not json", Some("agent:test-harness"))
        .await;

    let store = world.ingest().store();
    let records = store
        .rejections(None, 100)
        .await
        .expect("reading rejections");
    assert!(records.len() >= 2, "both refusals must be recorded");
    let first = records
        .iter()
        .find(|r| r["reason"].as_str() == Some("gate-authorization-missing"))
        .expect("the gate refusal is recorded");
    assert_eq!(first["submitted-by"].as_str(), Some("agent:test-harness"));
    assert_eq!(first["claimed-kind"].as_str(), Some("effect"));
    assert!(
        first["object-hash"].as_str().is_some_and(|h| h.len() == 64),
        "the hash of the rejected bytes identifies what was refused"
    );

    // Filtering by reason is the query an operator actually runs: "what is this component doing?"
    let filtered = store
        .rejections(Some("gate-authorization-missing"), 100)
        .await
        .expect("filtering by reason");
    assert_eq!(filtered.len(), 1);

    // The rejection stream is a chain, so the refusal history is as tamper-evident as the data.
    let chain_records = store.rejection_chain().await.expect("reading the chain");
    let head =
        stozher_kernel::store::verify_rejection_chain(&chain_records, store.rejection_stream())
            .expect("the rejection chain verifies")
            .expect("a non-empty chain");
    assert_eq!(head.len(), 64);

    // A rejected envelope is never in the subject's chain.
    let appended = store
        .query(&stozher_kernel::store::EnvelopeQuery {
            stream: Some(EFFECT_STREAM),
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("querying the effect stream");
    assert!(
        appended.is_empty(),
        "a rejected envelope must not be appended to any subject chain"
    );

    let pool = raw(&database).await;
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM rejections")
        .fetch_one(&pool)
        .await
        .expect("counting rejections")
        .get("n");
    assert!(count >= 2);
    pool.close().await;

    let _ = std::fs::remove_dir_all(database.parent().expect("a parent directory"));
}

//! The kernel owns the decay schedule — `docs/product-completion-design.md` §3 (v0.3).
//!
//! # What was wrong
//!
//! `POST /v1/maintenance/decay` was implemented, authenticated and working, and **nothing called
//! it**. The root README sells "closed loops decay to signed hashes" as a property of the system; an
//! install nobody wrote a crontab entry for kept every payload for ever, so the property was one the
//! operator was providing rather than one they were receiving. `deploy/README.md` §5 documented that
//! gap as an interim measure and named the kernel-owned timer as the right fix. This is it.
//!
//! # Why the tests are shaped like this
//!
//! The claim is not "decay works" — `append_only_and_decay.rs` already establishes that by calling
//! the endpoint. The claim here is narrower and is exactly the one that was false: **it happens
//! without anyone calling anything.** So the tests spawn the loop and then touch nothing.
//!
//! The paired negative is what stops the positive being satisfiable by a sweep that deletes whatever
//! it finds — that would pass the first test and be a data-loss bug. Both wait the same way and for
//! the same length of time, so the only difference between them is whether the kernel's clock has
//! passed the payload's `retain-until`.
//!
//! These run on a one-second interval and real time. Tokio's paused clock would be faster and is the
//! wrong tool: an idle runtime auto-advances to the next deadline, which trips the connection pool's
//! own acquire timeout and reports a store outage instead of a sweep.

use std::time::Duration;

use serde_json::json;
use stozher_core::jcs;
use stozher_kernel::checkpoint;
use stozher_testkit::{World, world};

/// Short enough to keep the test quick, and a real value the shipped loop accepts: the interval is
/// clamped at one second, so this is the fastest sweep a deployment could configure rather than a
/// test-only path.
const INTERVAL_SECONDS: i64 = 1;

/// Long enough for several sweeps at that interval, so "still there" means the sweep looked and
/// declined rather than that it had not run yet.
const OBSERVATION: Duration = Duration::from_millis(4_000);

/// Accept a gated effect carrying an evidence payload that may be kept until `retain_until`.
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

/// Whether the payload is still stored.
async fn stored(world: &World, hash: &str) -> bool {
    world
        .ingest()
        .store()
        .payload(hash)
        .await
        .expect("reading a payload")
        .is_some()
}

/// Watch for [`OBSERVATION`], returning as soon as the payload is gone.
///
/// Both tests call this, so neither can pass because it was given more time than the other.
async fn watch_for_decay(world: &World, hash: &str) -> bool {
    let deadline = std::time::Instant::now() + OBSERVATION;
    while std::time::Instant::now() < deadline {
        if !stored(world, hash).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test]
async fn the_kernel_decays_expired_payloads_without_anyone_calling_the_endpoint() {
    let world = world().await;
    let hash = effect_with_payload(&world, "expired", "2026-08-01T00:00:00.000Z").await;
    assert!(
        stored(&world, &hash).await,
        "the payload should be stored before the sweep; otherwise this test proves nothing"
    );

    // Past every `retain-until`. Nothing calls the endpoint from here on; the only thing that
    // happens is the loop reaching its next tick.
    world.clock.advance_seconds(60 * 60 * 24 * 30);
    let sweep = tokio::spawn(checkpoint::run_decay_interval(
        world.ingest().clone(),
        "kernel:checkpoints".to_owned(),
        INTERVAL_SECONDS,
    ));

    let decayed = watch_for_decay(&world, &hash).await;
    sweep.abort();
    assert!(
        decayed,
        "the payload outlived its retention: the kernel is still not the owner of the schedule"
    );
}

/// The one above proves the *loop* decays. This proves the **service starts it** — which is the
/// claim that was actually false, and the one a loop nobody spawned would still satisfy.
///
/// It calls `spawn_maintenance`, which is what `main`'s `serve` calls, with the interval coming from
/// the configuration rather than from an argument this test chose. What is left unbound is the
/// single call inside `serve`; `deploy/gate/clean-install.sh` runs that binary for real.
#[tokio::test]
async fn starting_the_service_starts_the_sweep() {
    let world = world().await;
    let hash = effect_with_payload(&world, "expired", "2026-08-01T00:00:00.000Z").await;
    world.clock.advance_seconds(60 * 60 * 24 * 30);

    let maintenance = world.kernel.spawn_maintenance();
    let decayed = watch_for_decay(&world, &hash).await;
    maintenance.abort();
    assert!(
        decayed,
        "the service started without its decay sweep: the timer exists and nothing runs it"
    );
}

#[tokio::test]
async fn the_sweep_leaves_a_payload_that_is_still_within_its_retention() {
    let world = world().await;
    let hash = effect_with_payload(&world, "still retained", "2026-08-01T00:00:00.000Z").await;

    // The clock is *not* advanced: the sweep runs, repeatedly, over a payload it must not touch.
    let sweep = tokio::spawn(checkpoint::run_decay_interval(
        world.ingest().clone(),
        "kernel:checkpoints".to_owned(),
        INTERVAL_SECONDS,
    ));

    let decayed = watch_for_decay(&world, &hash).await;
    sweep.abort();
    assert!(
        !decayed,
        "the sweep erased a payload that was still inside its retention"
    );
}

//! Getting a checkpoint out of the box it attests — `spec/04 §4.7`.
//!
//! The kernel has signed checkpoints since v0.2 and had no way to publish one. That gap is not
//! cosmetic: a checkpoint stored beside the records it attests answers "has this store been
//! *edited*?" and does not answer "was this store *rebuilt*?", because a party who can rebuild the
//! records can rebuild the checkpoints with them. A compliance evaluator ran the product, read the
//! console's "Anchored to a signed checkpoint: yes", and found on inspection that the sentence was
//! about a head nothing had ever published.
//!
//! So these tests hold two things: the heads can be taken out, and the console does not describe an
//! internal checkpoint as though it were an external one.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_kernel::{checkpoint, http};
use stozher_testkit::{TOKEN, World, world};
use tower::ServiceExt;

const EFFECT_STREAM: &str = "gw:dev:0001";

struct Answer {
    status: StatusCode,
    body: String,
}

async fn get(world: &World, uri: &str) -> Answer {
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
        .expect("collecting the body")
        .to_bytes();
    Answer {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn anchor(world: &World) -> Value {
    let answer = get(world, "/v1/checkpoints/heads").await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    serde_json::from_str(&answer.body).expect("the anchor is a JSON document")
}

/// Append `count` ordinary effects, so a stream has a head worth checkpointing.
async fn fill(world: &World, count: usize) {
    for _ in 0..count {
        let effect = world.effect("github.get_file", "read", json!({})).await;
        world.accept(&effect, &[]).await;
    }
}

#[tokio::test]
async fn a_deployment_with_no_checkpoint_says_so_rather_than_producing_an_empty_anchor() {
    // The honesty case, and the one most likely to be skipped. The failure this whole surface
    // exists to remove is a page that stays quiet when it has nothing good to say — a blank
    // anchor reads as "checked, all clear" to exactly the reader who cannot tell the difference.
    let world = world().await;
    fill(&world, 3).await;

    let document = anchor(&world).await;
    assert_eq!(
        document["heads"].as_array().map(Vec::len),
        Some(0),
        "a store with no checkpoint reported heads"
    );

    let page = get(&world, &format!("/console/streams/{EFFECT_STREAM}/verify")).await;
    assert!(
        page.body
            .contains("Attested by a signed checkpoint: <b class=\"quiet\">no"),
        "the verify page did not say the range is unattested: {}",
        page.body
    );
}

#[tokio::test]
async fn the_anchor_carries_every_checkpointed_stream_with_the_envelope_that_attests_it() {
    let world = world().await;
    fill(&world, 5).await;
    checkpoint::emit(world.ingest(), EFFECT_STREAM, "kernel:checkpoints")
        .await
        .expect("emitting a checkpoint")
        .expect("a checkpoint was emitted");

    let document = anchor(&world).await;
    let heads = document["heads"].as_array().expect("heads");
    let head = heads
        .iter()
        .find(|h| h["stream"] == EFFECT_STREAM)
        .expect("the checkpointed stream is in the anchor");

    // A bare head hash is a number to compare. The envelope id is what lets an outsider come back
    // later and establish that the number was *attested* rather than asserted by whoever sent them
    // the file — so the anchor is worth taking only if it carries one.
    let attesting = head["checkpoint-envelope"]
        .as_str()
        .expect("an envelope id");
    let envelope = get(&world, &format!("/v1/envelopes/{attesting}")).await;
    assert_eq!(envelope.status, StatusCode::OK, "{}", envelope.body);
    assert!(
        envelope
            .body
            .contains(head["head-hash"].as_str().expect("a head hash")),
        "the named envelope does not commit to the head the anchor reports"
    );
    assert!(
        document["taken-at"].is_string(),
        "an anchor states when it was taken"
    );
}

#[tokio::test]
async fn a_later_anchor_moves_and_does_not_serve_the_first_one_again() {
    // The compliance evaluator's real finding was an anchor whose heads covered seq 0..1 while the
    // records an auditor most wanted — a denial and a revocation — sat beyond it, unattested. An
    // anchor that never advances is worse than none: it is a document that ages into a false claim.
    let world = world().await;
    fill(&world, 3).await;
    checkpoint::emit(world.ingest(), EFFECT_STREAM, "kernel:checkpoints")
        .await
        .expect("emitting a checkpoint")
        .expect("a checkpoint was emitted");
    let first = anchor(&world).await;
    let first_to = first["heads"][0]["to-seq"].as_u64().expect("to-seq");

    fill(&world, 4).await;
    checkpoint::emit(world.ingest(), EFFECT_STREAM, "kernel:checkpoints")
        .await
        .expect("emitting a checkpoint")
        .expect("a second checkpoint was emitted");
    let second = anchor(&world).await;
    let second_head = second["heads"]
        .as_array()
        .expect("heads")
        .iter()
        .find(|h| h["stream"] == EFFECT_STREAM)
        .expect("the stream is still in the anchor");

    assert!(
        second_head["to-seq"].as_u64().expect("to-seq") > first_to,
        "the anchor did not advance past {first_to}: {second_head}"
    );
    // One row per stream, not one per checkpoint ever taken: an anchor is the current position.
    assert_eq!(
        second["heads"]
            .as_array()
            .expect("heads")
            .iter()
            .filter(|h| h["stream"] == EFFECT_STREAM)
            .count(),
        1,
    );
}

#[tokio::test]
async fn the_console_does_not_offer_an_internal_checkpoint_as_outside_assurance() {
    // The page used to end "a rebuilt store would contradict a published head, which is what makes
    // the anchor worth having" — while nothing in the product published one. The claim was true of
    // a published head and the page was not entitled to it.
    let world = world().await;
    fill(&world, 3).await;
    checkpoint::emit(world.ingest(), EFFECT_STREAM, "kernel:checkpoints")
        .await
        .expect("emitting a checkpoint")
        .expect("a checkpoint was emitted");

    let page = get(&world, &format!("/console/streams/{EFFECT_STREAM}/verify")).await;
    assert_eq!(page.status, StatusCode::OK);
    // Specific: "yes" alone also matches the rooted-range line above it, which is the conflation
    // this whole change exists to undo.
    assert!(
        page.body
            .contains("Attested by a signed checkpoint: <b class=\"ok\">yes"),
        "the checkpoint exists and the page should say so: {}",
        page.body
    );
    assert!(
        page.body.contains("attests this head to no one"),
        "the page presents an internal checkpoint without saying what it does not prove: {}",
        page.body
    );
    assert!(
        page.body.contains("stozher-anchor"),
        "the page names the gap without naming the command that closes it"
    );
}

#[tokio::test]
async fn the_anchor_is_not_readable_without_a_credential() {
    let world = world().await;
    let request = Request::builder()
        .method("GET")
        .uri("/v1/checkpoints/heads")
        .body(Body::empty())
        .expect("a request");
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(request)
        .await
        .expect("the router responds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

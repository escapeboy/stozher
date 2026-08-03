//! Kernel-side evidence for defects that are **open**. Ignored, not deleted.
//!
//! Run them with `cargo test --manifest-path kernel/Cargo.toml --test open_defects -- --ignored`.
//! Each asserts the behaviour the design requires, so while its defect is open it fails and the
//! failure carries the observed numbers.
//!
//! Nothing here weakens the gate: a queued request grants nothing, and these tests only submit
//! questions and count rows.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use stozher_core::jcs;
use stozher_kernel::http;
use stozher_testkit::{Ask, TOKEN, World, world};
use tower::ServiceExt;

struct Answer {
    status: StatusCode,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn call(world: &World, method: &str, uri: &str, body: Option<String>) -> Answer {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let request = builder
        .body(body.map_or_else(Body::empty, Body::from))
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

/// The action request a gateway builds for one specific `github.create_issue` call.
async fn request_for(world: &World, action: &str) -> Value {
    let draft = world.effect(action, "consequential", serde_json::json!({})).await;
    let args_hash = draft["execution"]["args-hash"]
        .as_str()
        .expect("args-hash")
        .to_owned();
    let target = draft["execution"]["target"]
        .as_str()
        .expect("target")
        .to_owned();
    world.action_request(&Ask {
        requester: &world.agent,
        component: "gateway",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action,
        target: &target,
        args_hash: &args_hash,
    })
}

async fn park(world: &World, request: &Value) -> Answer {
    call(
        world,
        "POST",
        "/v1/gate/requests",
        Some(jcs::canonicalize(request).expect("canonicalizing")),
    )
    .await
}

/// DEF-1, kernel side: the queue deduplicates by `request-hash` and by nothing else.
///
/// Observed: `POST /v1/gate/requests` is idempotent by `request-hash` exactly as §06 §4.3 rule 1
/// requires (`http.rs:449-452`, `store.rs:942-1005`), and `nonce` is inside the hashed object
/// (`gatequeue.rs:48-63`). So two submissions of one logical call that differ only in the 128 bits
/// the gateway mints per park (`gateway/src/stozher_gateway/gate.py:87-105`) are two different
/// objects and become two rows the same human has to read.
///
/// This test is why the defect survived a green suite: `stozher_testkit`'s `action_request`
/// derives `nonce` deterministically from the call's own fields (`stozher-testkit/src/lib.rs:441`),
/// so every kernel test re-parks the *same* object and observes the idempotency working. The
/// gateway is the only caller that mints fresh entropy, and no kernel test ever had two.
///
/// Expected: one undecided question per logical call in the queue an approver reads — whether by
/// the route collapsing them, or by the component never submitting the second (see the gateway
/// half in `gateway/tests/test_open_defects.py`). The queue-depth bound of §09 §7 is a flood
/// control and is not this: refusing the duplicate as a flood also refuses the honest re-park.
#[tokio::test]
#[ignore = "DEF-1 open"]
async fn def1_one_call_parked_twice_becomes_two_questions_for_one_human() {
    let world = world().await;

    // The same object twice: this is the idempotency the spec mandates, and it holds.
    let request = request_for(&world, "github.create_issue").await;
    assert_eq!(park(&world, &request).await.status, StatusCode::CREATED);
    // `200 OK` rather than `201 Created`: the route recognised the request it already holds.
    assert_eq!(park(&world, &request).await.status, StatusCode::OK);
    let queued = call(&world, "GET", "/v1/gate/requests", None).await;
    assert_eq!(
        queued.json()["count"].as_u64(),
        Some(1),
        "re-submitting a byte-identical request duplicated it: {}",
        queued.body
    );

    // The same *call*, asked a second time the way the gateway asks it — every field identical
    // except the nonce, which it mints fresh on every park.
    let mut re_asked = request.clone();
    re_asked["nonce"] = Value::from("9f".repeat(16));
    assert_eq!(park(&world, &re_asked).await.status, StatusCode::CREATED);

    let queued = call(&world, "GET", "/v1/gate/requests", None).await;
    let rows = queued.json();
    let count = rows["count"].as_u64().unwrap_or_default();
    let first = rows["requests"][0].clone();
    let second = rows["requests"][1].clone();
    assert_eq!(
        count, 1,
        "one call is queued as {count} questions; the two rows differ only in their nonce \
         ({} vs {}) and describe the same action {} on {} with args-hash {}",
        first["request"]["nonce"],
        second["request"]["nonce"],
        first["action"],
        first["target"],
        first["args-hash"]
    );
}

//! Kernel-side evidence for reported defects. A test here is `#[ignore]`d while its defect is
//! open — the failure is the defect stating itself, with the observed numbers in the message — and
//! is un-ignored, into the default run, on the day it is closed. Kept either way:
//! `gateway/tests/test_defect_register.py` binds this file to `docs/open-defects.md` in both
//! directions, and evidence that stops being executed is evidence nobody will notice rotting.
//!
//! The ignored ones run with
//! `cargo test --manifest-path kernel/Cargo.toml --test open_defects -- --ignored`.
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
    let draft = world
        .effect(action, "consequential", serde_json::json!({}))
        .await;
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

/// DEF-1, kernel side, closed: the half the component's rule stands on, and the half it cannot.
///
/// **What this side guarantees.** `POST /v1/gate/requests` is idempotent by `request-hash` exactly
/// as §06 §4.3 rule 1 requires (`http.rs`, `"the route recognised the request it already holds"`),
/// so a component that resolves to a request it already holds may re-submit that same object on
/// every retry — which the gateway now does, because a park held locally against an unreachable
/// kernel is invisible to every human until some later attempt gets it queued.
///
/// **What it does not, and must not.** `nonce` is inside the hashed object (§06 §1.1), so a second
/// ask carrying fresh entropy is a genuinely different object and becomes a second row. Collapsing
/// the two here would be this kernel deciding that an approval of one is an approval of the other,
/// which is the one thing `nonce` exists to prevent. The duty therefore lands on the component and
/// §06 §4.2 now states it: match field-wise, resolve to the request already held, never enqueue a
/// duplicate. The gateway half is `gateway/tests/test_def1_replay_idempotence.py`.
///
/// This test is also why the defect survived a green suite, and the reason it is kept rather than
/// deleted: `stozher_testkit`'s `action_request` derives `nonce` deterministically from the call's
/// own fields, so every kernel test re-parked the *same* object and watched idempotency work. Only
/// the gateway mints entropy, and no kernel test ever had two. A fixture that imitates the producer
/// does not bind to it.
#[tokio::test]
async fn def1_the_queue_is_idempotent_for_one_request_and_cannot_be_for_one_call() {
    let world = world().await;

    // The same object twice: this is the idempotency the spec mandates, and what a component's
    // retry of a request it already holds costs.
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

    // The same *call*, asked the way a component asked it before §06 §4.2 said not to — every field
    // identical except the nonce it minted fresh on every park.
    let mut re_asked = request.clone();
    re_asked["nonce"] = Value::from("9f".repeat(16));
    assert_eq!(park(&world, &re_asked).await.status, StatusCode::CREATED);

    let queued = call(&world, "GET", "/v1/gate/requests", None).await;
    let rows = queued.json();
    assert_eq!(
        rows["count"].as_u64(),
        Some(2),
        "the two asks were collapsed into one row. They differ in `nonce`, which §06 §1.1 makes \
         part of the hashed object precisely so that an approval of one is not an approval of the \
         other; a kernel that merges them has decided otherwise on the approver's behalf: {}",
        queued.body
    );
    assert_ne!(
        rows["requests"][0]["request"]["nonce"], rows["requests"][1]["request"]["nonce"],
        "two rows that are not two nonces would mean the queue rewrote a request, which §06 §4.3 \
         rule 5 forbids"
    );
}

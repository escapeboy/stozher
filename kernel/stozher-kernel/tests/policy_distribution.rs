//! Versioned policy pull — `spec/05-policy-distribution.md` §2, §6.
//!
//! Components pull; the kernel does not push. What the endpoints must guarantee: the current document
//! is served with its version as the ETag, **every** version ever published resolves forever, both
//! require authentication, and `revoke-cached` travels in the document because that is the only place
//! a component can learn of it.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_core::jcs;
use stozher_kernel::{http, policy};
use stozher_testkit::{NOW, TOKEN, World, world};

async fn get(
    world: &World,
    uri: &str,
    credential: Option<&str>,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = credential {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder.body(Body::empty()).expect("a request");
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(request)
        .await
        .expect("the router responds");
    let status = response.status();
    let etag = response
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collecting the body")
        .to_bytes();
    (
        status,
        etag,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

use tower::ServiceExt;

#[tokio::test]
async fn the_current_policy_is_served_with_its_version_as_the_etag() {
    let world = world().await;
    let (status, etag, document) = get(&world, "/v1/policy/current", Some(TOKEN)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(etag.as_deref(), Some("\"2026.07.1\""));
    assert_eq!(document["policy-version"].as_str(), Some("2026.07.1"));

    // The document is served verbatim, so a component can verify the signature it was published
    // under — re-serializing from parsed columns would invite exactly the canonicalization drift §01
    // exists to prevent.
    let verified = policy::Policy::parse(&document, &world.policy_key.id)
        .expect("the served document must verify against the enrolled policy key");
    assert_eq!(verified.version(), "2026.07.1");
}

#[tokio::test]
async fn every_published_version_resolves_forever() {
    let mut world = world().await;
    for version in ["2026.07.2", "2026.07.3", "2026.07.4"] {
        let document = world.policy_key.sign(&policy::baseline_conservative(
            version,
            NOW,
            &[world.root.subject.as_str()],
        ));
        world.publish_policy(&document).await;
    }

    // The newest is current…
    let (_, etag, current) = get(&world, "/v1/policy/current", Some(TOKEN)).await;
    assert_eq!(etag.as_deref(), Some("\"2026.07.4\""));
    assert_eq!(current["policy-version"].as_str(), Some("2026.07.4"));

    // …and every earlier one still resolves, so an envelope's `policy-version` is never a dangling
    // reference no matter how old the envelope is (§05 §2.2).
    for version in ["2026.07.1", "2026.07.2", "2026.07.3", "2026.07.4"] {
        let (status, _, document) =
            get(&world, &format!("/v1/policy/{version}"), Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{version} stopped resolving");
        assert_eq!(document["policy-version"].as_str(), Some(version));
    }

    // A version that was never published is a 404, not an empty document.
    let (status, _, body) = get(&world, "/v1/policy/2030.01.1", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason-code"].as_str(), Some("policy-not-published"));
}

#[tokio::test]
async fn both_policy_endpoints_require_authentication() {
    let world = world().await;
    for uri in ["/v1/policy/current", "/v1/policy/2026.07.1"] {
        let (status, _, body) = get(&world, uri, None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{uri} answered anonymously"
        );
        assert_eq!(
            body["reason-code"].as_str(),
            Some("x-caller-unauthenticated")
        );
    }
}

#[tokio::test]
async fn revoke_cached_travels_in_the_document_it_tightens() {
    // §05 §6: the flag lives in the *new* document, so a component learns of it only by pulling.
    // Tightening is therefore not instantaneous, and the residual window is real and bounded — the
    // spec names it honestly rather than describing it as solved, and so does this test.
    let mut world = world().await;
    let (_, _, before) = get(&world, "/v1/policy/current", Some(TOKEN)).await;
    assert_eq!(
        before["revoke-cached"].as_bool(),
        Some(false),
        "the baseline does not tighten anything"
    );

    let mut tightened =
        policy::baseline_conservative("2026.08.1", NOW, &[world.root.subject.as_str()]);
    tightened["revoke-cached"] = Value::from(true);
    // A class raised: `github.get_file` moves from `read` to `consequential`.
    tightened["classification"]["by-action"]["github.get_file"] = Value::from("consequential");
    let document = world.policy_key.sign(&tightened);
    world.publish_policy(&document).await;

    let (_, etag, after) = get(&world, "/v1/policy/current", Some(TOKEN)).await;
    assert_eq!(etag.as_deref(), Some("\"2026.08.1\""));
    assert_eq!(after["revoke-cached"].as_bool(), Some(true));

    // The tightening is in force at the kernel immediately: an effect stamped with the *old* version
    // and the old class is now refused, because classification is the organization's, not the
    // emitter's (§05 §3 step 1, §08 §1.2).
    let stale = world
        .effect(
            "github.get_file",
            "read",
            json!({ "policy-version": "2026.07.1" }),
        )
        .await;
    world
        .reject(&stale, &[], "policy-component-override-attempt")
        .await;

    // Stamped with the new version and the new class, it is accepted — once it carries the approval
    // the raised class now demands.
    let gated = world.gated_effect("github.get_file", json!({})).await;
    world.accept(&gated, &[]).await;
}

#[tokio::test]
async fn a_policy_change_binds_the_exact_document_bytes() {
    // §05 §5.3: swap the payload for a different document and the change no longer commits to what it
    // publishes. The approval signature covers `args-hash`, so this is not a check the kernel could
    // choose to skip — the binding is what the human signed.
    let world = world().await;
    let intended = world.policy_key.sign(&policy::baseline_conservative(
        "2026.09.1",
        NOW,
        &[world.root.subject.as_str()],
    ));
    let (envelope, _) = world.policy_change(&intended).await;

    let mut substituted =
        policy::baseline_conservative("2026.09.1", NOW, &[world.root.subject.as_str()]);
    substituted["gate-rules"] = json!([{ "classes": ["read", "benign", "consequential", "prohibited"], "decision": "allow" }]);
    let substituted = world.policy_key.sign(&substituted);
    let payload = json!({
        "payload-hash": jcs::object_hash(&intended).expect("hash"),
        "media-type": "application/json",
        "payload": substituted
    });

    world
        .reject(&envelope, &[payload], "payload-hash-mismatch")
        .await;

    // The document that was never bound was never published.
    let (status, _, _) = get(&world, "/v1/policy/2026.09.1", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

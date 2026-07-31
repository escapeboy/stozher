//! Evidence payloads are data, and must be served as data.
//!
//! `media-type` is chosen by the emitter, stored verbatim, and reflected as the response
//! `Content-Type` by `GET /payload/:hash`. The kernel's own console is server-rendered HTML on that
//! same origin, and `deploy/bin/stozher-console` proxies browser `GET`s to it with the kernel
//! credential injected — so a payload declaring `text/html` was script the browser would run with
//! the console's origin, able to read every console page the proxy could fetch.
//!
//! Two independent barriers, because either alone is one mistake away from the same hole: the type
//! is checked at ingest, and the response is served inert whatever is in the store. The second half
//! also covers payloads written before the first existed.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use stozher_core::crypto;
use stozher_kernel::http;
use stozher_kernel::ingest::Outcome;
use stozher_testkit::{TOKEN, World, world};
use tower::ServiceExt;

/// An effect citing one evidence payload of `media_type`, plus the payload record itself.
///
/// A non-JSON payload is a lowercase hex octet string whose `payload-hash` is `sha256(bytes)`.
async fn effect_with_payload(world: &World, media_type: &str, body: &[u8]) -> (Value, Value) {
    let payload_hash = crypto::sha256_hex(body);
    let envelope = world
        .effect(
            "github.get_file",
            "read",
            json!({
                "evidence": {
                    "schema": "github.get_file.v1",
                    "media-type": media_type,
                    "payload-hash": payload_hash,
                    "retain-until": "2026-08-26T00:00:00.000Z"
                }
            }),
        )
        .await;
    let payload = json!({
        "payload-hash": payload_hash,
        "media-type": media_type,
        "payload": hex::encode(body)
    });
    (envelope, payload)
}

async fn fetch_payload(world: &World, hash: &str) -> axum::http::HeaderMap {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/v1/payloads/{hash}"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .expect("a request");
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(request)
        .await
        .expect("the router responds");
    assert_eq!(response.status(), StatusCode::OK);
    response.headers().clone()
}

const SCRIPT: &[u8] = b"<script>fetch('/console/queue').then(r=>r.text())</script>";

#[tokio::test]
async fn a_payload_declaring_html_is_refused_at_ingest() {
    let world = world().await;
    let (envelope, payload) = effect_with_payload(&world, "text/html", SCRIPT).await;

    match world.submit(&envelope, &[payload]).await {
        Outcome::Rejected { reason, .. } => assert_eq!(reason, "payload-media-type-not-allowed"),
        Outcome::Accepted(appended) => {
            panic!("an HTML evidence payload was accepted as {}", appended.id)
        }
        Outcome::Unavailable(e) => panic!("the store was unavailable: {e}"),
    }
}

#[tokio::test]
async fn the_ordinary_evidence_types_are_still_accepted() {
    // The allowlist is a defence, not a narrowing of what evidence may be. If it refuses the types
    // components actually emit, it will be widened in a hurry by someone who has stopped reading.
    for media_type in [
        "application/json",
        "application/octet-stream",
        "text/plain",
        "application/pdf",
        "image/png",
    ] {
        let world = world().await;
        let body = format!("evidence bytes for {media_type}").into_bytes();
        let (envelope, payload) = if media_type == "application/json" {
            let value = json!({ "note": "evidence" });
            let hash = stozher_core::jcs::object_hash(&value).expect("object hash");
            let envelope = world
                .effect(
                    "github.get_file",
                    "read",
                    json!({ "evidence": {
                        "schema": "github.get_file.v1",
                        "media-type": media_type,
                        "payload-hash": hash,
                        "retain-until": "2026-08-26T00:00:00.000Z"
                    }}),
                )
                .await;
            let payload =
                json!({ "payload-hash": hash, "media-type": media_type, "payload": value });
            (envelope, payload)
        } else {
            effect_with_payload(&world, media_type, &body).await
        };

        match world.submit(&envelope, &[payload]).await {
            Outcome::Accepted(_) => {}
            Outcome::Rejected { reason, detail, .. } => {
                panic!("{media_type} evidence was refused: {reason} — {detail}")
            }
            Outcome::Unavailable(e) => panic!("the store was unavailable: {e}"),
        }
    }
}

#[tokio::test]
async fn a_stored_payload_is_served_inert() {
    let world = world().await;
    // A `consequential` action: policy retains its evidence for P365D, where class `read` is `P0D`
    // and nothing is stored to serve.
    let hash = crypto::sha256_hex(SCRIPT);
    let envelope = world
        .gated_effect(
            "github.create_issue",
            json!({ "evidence": {
                "schema": "github.create_issue.v1",
                "media-type": "application/pdf",
                "payload-hash": hash,
                "retain-until": "2026-08-01T00:00:00.000Z"
            }}),
        )
        .await;
    let payload = json!({
        "payload-hash": hash,
        "media-type": "application/pdf",
        "payload": hex::encode(SCRIPT)
    });
    world.accept(&envelope, &[payload]).await;

    let headers = fetch_payload(&world, &hash).await;

    // Even an allowlisted type is served as an opaque download. The allowlist keeps active content
    // out of the store; these headers mean that a type which slipped past it — or one written
    // before the allowlist existed — still cannot execute on this origin.
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "without nosniff the browser may sniff the bytes and ignore the declared type"
    );
    let disposition = headers
        .get(axum::http::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        disposition.starts_with("attachment"),
        "expected an attachment disposition, got {disposition:?}"
    );
    assert_eq!(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream"),
        "a payload is bytes an auditor downloads, never a document this origin renders"
    );
}

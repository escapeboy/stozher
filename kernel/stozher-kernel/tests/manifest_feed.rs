//! `GET /v1/manifests` — the tier-A classification source (§08, §10 §3).
//!
//! # What was missing
//!
//! Registration worked: `kernel.register_component` is a gated action, `spec/08 §3.3`'s "no green
//! conformance run, no registration" is enforced, and the manifest is retained forever. What no
//! route did was **hand the manifest back**, so the one consumer that wanted it — a gateway trying
//! to classify a component it did not write — had no way to read what that component had declared
//! about itself, and fell through to guessing from the tool's shape.
//!
//! # What these tests hold to
//!
//! * a registered manifest is served, and its declared actions survive the round trip verbatim;
//! * a component that registered twice appears **once**, as its newest version — a classifier that
//!   saw two would have to pick, and picking is not its job;
//! * the route is authenticated like every other read, because "public within the deployment" is
//!   not the same as public.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_kernel::http;
use stozher_testkit::{TOKEN, World, manifest_object, world};
use tower::ServiceExt;

async fn get(world: &World, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(builder.body(Body::empty()).expect("a request"))
        .await
        .expect("the router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collecting the body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// One declared action, with every member `spec/08 §1` requires.
fn action(identifier: &str, class: &str) -> Value {
    let mut declared = json!({
        "action": identifier,
        "class": class,
        "evidence-schema": format!("{identifier}.v1"),
        "idempotent": false,
        "target-kind": "repo"
    });
    // §02 §7: a `read` action is the one that aggregates, so a manifest that declares one without
    // saying how it samples is refused. The kernel is right to insist; the fixture has to comply.
    if class == "read" {
        declared["aggregate"] = json!({ "sampling": "first-and-last", "max-samples": 8 });
    }
    declared
}

/// Register a component through the real gated path: a signed manifest, a green conformance run,
/// and a root approval. Nothing here is a shortcut around §08 §3.3.
async fn register(world: &World, name: &str, version: &str, actions: Value) {
    let manifest = world
        .component
        .sign(&manifest_object(name, version, actions));
    let (registration, payloads) = world.register_component(&manifest, true).await;
    world.accept(&registration, &payloads).await;
}

#[tokio::test]
async fn a_registered_manifest_is_served_with_its_declared_actions_intact() {
    let world = world().await;
    register(
        &world,
        "github",
        "1.0.0",
        // `create_issue` rather than an invented name: a manifest must define every evidence
        // schema its actions reference, and the fixture's schema map defines these two. The class
        // is overridden to `prohibited` — the point here is that whatever the component declared
        // survives the round trip, not what it happened to declare.
        json!({ "actions": [
            action("github.get_file", "read"),
            action("github.create_issue", "prohibited")
        ] }),
    )
    .await;

    let (status, body) = get(&world, "/v1/manifests", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let manifests = body["manifests"].as_array().expect("manifests");
    assert_eq!(body["count"].as_u64(), Some(manifests.len() as u64));
    let github = manifests
        .iter()
        .find(|m| m["name"] == "github")
        .expect("the registered component is missing from the feed");

    // The declared classes are the whole point: a feed that returned names would leave a classifier
    // exactly where it started.
    let classes: Vec<(&str, &str)> = github["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .map(|a| {
            (
                a["action"].as_str().unwrap_or_default(),
                a["class"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert!(
        classes.contains(&("github.get_file", "read")),
        "{classes:?}"
    );
    assert!(
        classes.contains(&("github.create_issue", "prohibited")),
        "{classes:?}"
    );
}

#[tokio::test]
async fn a_component_that_registered_twice_is_served_once_as_its_newest_version() {
    let world = world().await;
    register(
        &world,
        "github",
        "1.0.0",
        json!({ "actions": [action("github.get_file", "read")] }),
    )
    .await;
    register(
        &world,
        "github",
        "2.0.0",
        json!({ "actions": [action("github.get_file", "consequential")] }),
    )
    .await;

    let (status, body) = get(&world, "/v1/manifests", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let github: Vec<&Value> = body["manifests"]
        .as_array()
        .expect("manifests")
        .iter()
        .filter(|m| m["name"] == "github")
        .collect();

    // Both versions are retained forever (§08 §3.5) and both are readable by version. What a
    // classifier asks is what the component *is*, and two answers to that is not an answer.
    assert_eq!(
        github.len(),
        1,
        "the feed served {} versions of one component",
        github.len()
    );
    assert_eq!(github[0]["version"].as_str(), Some("2.0.0"));
    assert_eq!(
        github[0]["actions"][0]["class"].as_str(),
        Some("consequential"),
        "the newest registration did not win"
    );
}

#[tokio::test]
async fn the_feed_is_authenticated_like_every_other_read() {
    let world = world().await;
    register(
        &world,
        "github",
        "1.0.0",
        json!({ "actions": [action("github.get_file", "read")] }),
    )
    .await;

    let (status, _) = get(&world, "/v1/manifests", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the manifest feed answered an unauthenticated caller"
    );
    let (status, _) = get(&world, "/v1/manifests", Some("not-the-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_deployment_with_no_registered_component_gets_an_empty_list_not_an_error() {
    // An empty answer is an answer here, unlike an empty *store* at `verify`: a deployment that has
    // registered nothing is the ordinary state on day one, and a classifier must be able to tell
    // that from a feed it could not read. The gateway's side asserts the same distinction.
    let world = world().await;
    let (status, body) = get(&world, "/v1/manifests", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"].as_u64(), Some(0));
    assert_eq!(body["manifests"].as_array().map(Vec::len), Some(0));
}

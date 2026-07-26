//! **No ambient approval — attempted, not asserted.**
//!
//! §06 §2 lists the bypasses an implementation MUST NOT provide, and then says the conformance
//! harness "MUST test for the last one directly by attempting it". So this file attempts them. Every
//! test here tries to get a gated envelope into the chain without a valid `authorization`, through a
//! different door each time, and proves the door is not there.
//!
//! ADR-0002 records why: FleetQ re-executed approved proposals by flipping an ambient container
//! binding (`app('integration_gate.bypass')`) — an unauditable side channel any code could set. The
//! point of this file is that the equivalent mistake is *unrepresentable* here, and that the claim is
//! backed by an attempt rather than by a paragraph.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_core::jcs;
use stozher_kernel::store::EnvelopeQuery;
use stozher_kernel::{Outcome, http};
use stozher_testkit::{EFFECT_STREAM, TOKEN, World, without, world};
use tower::ServiceExt;

/// Send a request to the real router and return `(status, body)`.
async fn call(world: &World, request: Request<Body>) -> (StatusCode, Value) {
    let router = http::router(Arc::clone(&world.kernel));
    let response = router.oneshot(request).await.expect("the router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collecting the body")
        .to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn authenticated(method: &str, uri: &str, body: Option<&Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json");
    match body {
        Some(value) => builder
            .body(Body::from(
                jcs::canonicalize(value).expect("canonical body"),
            ))
            .expect("a request"),
        None => builder.body(Body::empty()).expect("a request"),
    }
}

/// How many envelopes are in the store, so an attempt can be shown to have appended nothing.
async fn envelope_count(world: &World) -> u64 {
    world
        .ingest()
        .store()
        .envelope_count()
        .await
        .expect("counting envelopes")
}

#[tokio::test]
async fn a_gated_envelope_without_authorization_is_refused_through_the_only_write_route() {
    let world = world().await;
    let gated = world.gated_effect("github.create_issue", json!({})).await;
    let bare = without(&gated, "authorization", &world.agent);
    let before = envelope_count(&world).await;

    let (status, body) = call(
        &world,
        authenticated(
            "POST",
            "/v1/ingest",
            Some(&json!({ "envelope": bare, "payloads": [] })),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["reason-code"].as_str(),
        Some("gate-authorization-missing")
    );
    assert_eq!(
        body["retryable"].as_bool(),
        Some(false),
        "a refusal is terminal"
    );
    assert_eq!(envelope_count(&world).await, before, "nothing was appended");
    // The refusal is itself a record (§04 §7).
    assert!(
        body["rejection-id"].is_string(),
        "the rejection was recorded"
    );
}

#[tokio::test]
async fn no_header_query_parameter_or_body_member_marks_a_call_approved() {
    let world = world().await;
    let gated = world.gated_effect("github.create_issue", json!({})).await;
    let bare = without(&gated, "authorization", &world.agent);
    let before = envelope_count(&world).await;

    // Headers a hopeful integrator might invent. §06 §2 forbids "a request header or gRPC metadata
    // field that marks a call approved"; none of these is read anywhere, and that is the point.
    let headers = [
        ("x-stozher-approved", "true"),
        ("x-stozher-bypass", "1"),
        ("x-stozher-trusted-component", "gateway"),
        ("x-approved-by", "human:ivan"),
        ("x-stozher-gate", "skip"),
        ("x-admin", "true"),
    ];
    for (name, value) in headers {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/ingest")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header(name, value)
            .body(Body::from(
                jcs::canonicalize(&json!({ "envelope": bare, "payloads": [] })).expect("body"),
            ))
            .expect("a request");
        let (status, body) = call(&world, request).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name} changed the outcome"
        );
        assert_eq!(
            body["reason-code"].as_str(),
            Some("gate-authorization-missing"),
            "{name} changed the reason"
        );
    }

    // Query parameters, same idea.
    for query in [
        "?approved=true",
        "?bypass=1",
        "?trusted=true",
        "?gate=skip",
        "?force=true",
        "?admin=1",
    ] {
        let uri = format!("/v1/ingest{query}");
        let (status, body) = call(
            &world,
            authenticated(
                "POST",
                &uri,
                Some(&json!({ "envelope": bare, "payloads": [] })),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{query} changed the outcome"
        );
        assert_eq!(
            body["reason-code"].as_str(),
            Some("gate-authorization-missing"),
            "{query} changed the reason"
        );
    }

    // A body member alongside the envelope. The request object is a closed schema, so this is not
    // ignored — it is refused, which is stronger.
    let (status, body) = call(
        &world,
        authenticated(
            "POST",
            "/v1/ingest",
            Some(&json!({ "envelope": bare, "payloads": [], "approved": true })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["reason-code"].as_str(), Some("schema-unknown-member"));

    // A member inside the envelope, which would have to survive the signature *and* the closed
    // envelope schema. It survives neither.
    let smuggled = stozher_testkit::revise(&bare, json!({ "approved": true }), &world.agent);
    let (status, body) = call(
        &world,
        authenticated(
            "POST",
            "/v1/ingest",
            Some(&json!({ "envelope": smuggled, "payloads": [] })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["reason-code"].as_str(), Some("schema-unknown-member"));

    assert_eq!(envelope_count(&world).await, before, "nothing was appended");
}

#[tokio::test]
async fn no_administrative_route_appends_an_envelope() {
    let world = world().await;
    let gated = world.gated_effect("github.create_issue", json!({})).await;
    let bare = without(&gated, "authorization", &world.agent);
    let request_body = json!({ "envelope": bare, "payloads": [] });
    let before = envelope_count(&world).await;

    // §06 §2's last item: "an admin endpoint that appends a gated envelope without `authorization`".
    // The attempt is to find such an endpoint at all — including the two routes that look
    // administrative, and a spread of names an implementation might plausibly have grown.
    // Routes that do not exist must not be findable by guessing at a name.
    let invented = [
        ("POST", "/v1/admin/append"),
        ("POST", "/v1/admin/envelopes"),
        ("POST", "/v1/envelopes"),
        ("PUT", "/v1/envelopes"),
        ("POST", "/v1/internal/append"),
        ("POST", "/v1/streams/gw:dev:0001/append"),
        ("POST", "/v1/ingest/force"),
        ("POST", "/v1/ingest/trusted"),
        ("POST", "/v1/gate/approve"),
        ("POST", "/v1/policy/current"),
        ("DELETE", "/v1/envelopes/anything"),
    ];
    for (method, uri) in invented {
        let (status, _) = call(&world, authenticated(method, uri, Some(&request_body))).await;
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
            "{method} {uri} exists (status {status})"
        );
        assert_eq!(
            envelope_count(&world).await,
            before,
            "{method} {uri} changed the store"
        );
    }

    // The two routes that *do* look administrative, handed the gated envelope as their body. Neither
    // reads it: the checkpoint route builds its own envelope, the decay route takes no body at all.
    for uri in ["/v1/checkpoints", "/v1/maintenance/decay"] {
        let (status, body) = call(&world, authenticated("POST", uri, Some(&request_body))).await;
        assert_eq!(status, StatusCode::OK, "{uri} answered {status}: {body}");
        assert!(
            world
                .ingest()
                .store()
                .envelope_by_id(&stozher_core::signed::object_id(&bare).expect("id"))
                .await
                .expect("looking the envelope up")
                .is_none(),
            "{uri} appended the gated envelope it was handed"
        );
    }

    // `/v1/checkpoints` does append — checkpoint envelopes, through the ingest pipeline, refused
    // unless the kernel's own key signed them over a head the store can reproduce. What it can never
    // do is append an *effect*: after driving it, the effect streams hold nothing gated.
    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    let (status, body) = call(&world, authenticated("POST", "/v1/checkpoints", None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let consequential = world
        .ingest()
        .store()
        .query(&EnvelopeQuery {
            classification: Some("consequential"),
            stream: Some(EFFECT_STREAM),
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("querying");
    assert!(
        consequential.is_empty(),
        "the checkpoint route must not have appended a consequential effect"
    );
    // And every checkpoint it did append is signed by the kernel's checkpoint key, not by a caller.
    let checkpoints = world
        .ingest()
        .store()
        .query(&EnvelopeQuery {
            stream: Some("kernel:checkpoints"),
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("querying checkpoints");
    assert!(!checkpoints.is_empty(), "the route did emit checkpoints");
    for record in &checkpoints {
        assert_eq!(
            record["envelope"]["sig"]["key"].as_str(),
            Some(world.ingest().kernel_key().id().as_str()),
            "a checkpoint must be signed by the kernel's own key"
        );
    }
}

#[tokio::test]
async fn every_read_route_requires_a_credential_and_none_of_them_writes() {
    let world = world().await;
    let before = envelope_count(&world).await;

    let routes = [
        "/v1/policy/current",
        "/v1/policy/2026.07.1",
        "/v1/envelopes",
        "/v1/streams",
        "/v1/rejections",
        "/v1/rejections/verify",
    ];
    for uri in routes {
        // Unauthenticated: an audit trail readable by anyone who can reach the port is a different
        // product (§05 §2.2).
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("a request");
        let (status, body) = call(&world, request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{uri} answered without a credential"
        );
        assert_eq!(
            body["reason-code"].as_str(),
            Some("x-caller-unauthenticated")
        );

        // A wrong credential is refused the same way, and says nothing more.
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", "Bearer not-the-token")
            .body(Body::empty())
            .expect("a request");
        let (status, _) = call(&world, request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{uri} accepted a wrong credential"
        );

        // With the credential it answers, and still writes nothing.
        let (status, _) = call(&world, authenticated("GET", uri, None)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{uri} did not answer an authenticated caller"
        );
        assert_eq!(
            envelope_count(&world).await,
            before,
            "{uri} changed the store"
        );
    }
}

#[tokio::test]
async fn a_re_execution_path_cannot_proceed_on_a_remembered_approval() {
    // §06 §3: "The permission is data that travels with the work. If the job is lost, requeued, or
    // retried after `not-after`, it needs a fresh approval; it cannot proceed on the strength of a
    // remembered fact." So an envelope emitted after the approval expired is refused even though the
    // approval was, at the time, entirely genuine.
    let world = world().await;
    let gated = world.gated_effect("github.create_issue", json!({})).await;

    // The approval is valid now.
    let outcome = world.submit(&gated, &[]).await;
    assert!(matches!(outcome, Outcome::Accepted(_)), "{outcome:?}");

    // The same work, requeued and retried after the window. A fresh envelope, same authorization.
    world.clock.advance_seconds(60 * 60 * 12);
    let (next, prev) = world.head(EFFECT_STREAM).await;
    let retried = stozher_testkit::revise(
        &gated,
        json!({ "seq": next, "prev-hash": prev, "emitted-at": stozher_kernel::clock::Clock::now(world.clock.as_ref()) }),
        &world.agent,
    );
    match world.submit(&retried, &[]).await {
        Outcome::Rejected { reason, .. } => assert!(
            // Either refusal is correct and both are terminal: the approval was single-use, and it
            // had also expired. Neither leaves a path to "proceed anyway".
            reason == "gate-approval-expired" || reason == "gate-authorization-replayed",
            "unexpected reason {reason}"
        ),
        other => panic!("a remembered approval must not carry the work: {other:?}"),
    }
}

#[tokio::test]
async fn the_source_contains_no_ambient_approval_surface() {
    // A structural check to catch the mistake being *reintroduced*: the sort of name that would
    // appear if someone added a flag, a trusted-component list, or a DI binding that suppresses the
    // gate. Comments and test names are excluded — this looks for identifiers.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offences = Vec::new();
    let forbidden = [
        "bypass_gate",
        "skip_gate",
        "gate_bypass",
        "allow_unapproved",
        "trusted_components",
        "is_approved",
        "force_append",
        "assume_approved",
    ];
    visit(&root, &mut |path, contents| {
        for line in contents.lines() {
            let code = line.split("//").next().unwrap_or(line);
            for needle in forbidden {
                if code.contains(needle) {
                    offences.push(format!("{}: {needle}", path.display()));
                }
            }
        }
    });
    assert!(
        offences.is_empty(),
        "an ambient-approval surface appeared in the source: {offences:?}"
    );
}

fn visit(directory: &std::path::Path, seen: &mut impl FnMut(&std::path::Path, &str)) {
    for entry in std::fs::read_dir(directory).expect("reading the source tree") {
        let entry = entry.expect("a directory entry");
        let path = entry.path();
        if path.is_dir() {
            visit(&path, seen);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let contents = std::fs::read_to_string(&path).expect("reading a source file");
            seen(&path, &contents);
        }
    }
}

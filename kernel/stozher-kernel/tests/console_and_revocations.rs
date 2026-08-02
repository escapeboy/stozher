//! The S3 surfaces: the read-only console and the revocation feed.
//!
//! Two properties are load-bearing here and are asserted rather than described.
//!
//! **The console cannot write.** Not "does not": the route table registers `get` and nothing else,
//! so every write verb against every console path is refused by the router itself, before any
//! handler runs. `spec/06 §2` names an administrative append as a conformance failure; this is the
//! console's half of the claim `tests/no_ambient_approval.rs` makes for ingest.
//!
//! **The revocation feed answers the question the gateway hot path asks.** Before it existed, a
//! revoked mandate was caught at ingest — after the effect had already reached the world (ADR-0007
//! §1). The feed is shaped like policy pull so a component can hold it, poll it cheaply, and
//! evaluate it locally.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_kernel::http;
use stozher_testkit::{EFFECT_STREAM, NOW, TOKEN, World, world};
use tower::ServiceExt;

/// The response of one request: status, `ETag`, and the body as text.
struct Answer {
    status: StatusCode,
    etag: Option<String>,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn request(world: &World, method: &str, uri: &str, headers: &[(&str, String)]) -> Answer {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(builder.body(Body::empty()).expect("a request"))
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
    Answer {
        status,
        etag,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn get(world: &World, uri: &str) -> Answer {
    request(
        world,
        "GET",
        uri,
        &[("authorization", format!("Bearer {TOKEN}"))],
    )
    .await
}

/// Every console path, so a new page cannot quietly skip the checks below.
const PAGES: [&str; 8] = [
    "/console",
    "/console/audit",
    "/console/attempts",
    "/console/pending",
    "/console/mandates",
    "/console/streams",
    "/console/rejections",
    "/console/audit/export",
];

#[tokio::test]
async fn no_console_page_is_readable_without_a_credential() {
    let world = world().await;
    for page in PAGES {
        let answer = request(&world, "GET", page, &[]).await;
        assert_eq!(
            answer.status,
            StatusCode::UNAUTHORIZED,
            "{page} served something to an unauthenticated caller"
        );
        let answer = request(
            &world,
            "GET",
            page,
            &[("authorization", "Bearer not-the-token".to_owned())],
        )
        .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{page}");
    }
}

#[tokio::test]
async fn the_console_has_no_write_verb_on_any_path() {
    let world = world().await;
    // Including `/console/envelopes/{id}` and the verify path, which take a path parameter and are
    // therefore the easiest place for a write route to be added by accident later.
    let paths: Vec<String> = PAGES
        .iter()
        .map(|p| (*p).to_owned())
        .chain([
            format!("/console/envelopes/{}", "0".repeat(64)),
            format!("/console/streams/{EFFECT_STREAM}/verify"),
        ])
        .collect();
    for path in &paths {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let answer = request(
                &world,
                method,
                path,
                &[("authorization", format!("Bearer {TOKEN}"))],
            )
            .await;
            assert_eq!(
                answer.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path} was routed somewhere"
            );
        }
    }
}

#[tokio::test]
async fn the_audit_explorer_shows_an_attempted_prohibited_action_and_walks_it_to_a_human() {
    let world = world().await;
    let attempt = world
        .effect(
            "github.delete_repo",
            "prohibited",
            json!({ "execution": { "outcome": "attempted" } }),
        )
        .await;
    let id = world.accept(&attempt, &[]).await;

    let audit = get(&world, "/console/audit?outcome=attempted").await;
    assert_eq!(audit.status, StatusCode::OK);
    assert!(audit.body.contains("github.delete_repo"), "{}", audit.body);
    assert!(
        audit.body.contains(&id[..12]),
        "the row links to the envelope"
    );

    // The attempt is front and centre on its own page and on the overview, because an action
    // nothing could have authorized is the most audit-valuable record in the system.
    for page in ["/console", "/console/attempts"] {
        let answer = get(&world, page).await;
        assert_eq!(answer.status, StatusCode::OK, "{page}");
        assert!(answer.body.contains("github.delete_repo"), "{page}");
    }

    // One click from the row to the human root.
    let detail = get(&world, &format!("/console/envelopes/{id}")).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert!(detail.body.contains("On whose authority"));
    assert!(
        detail.body.contains(&world.root.subject),
        "the walk must name the enrolled human, not the agent"
    );
    // The evidence commitment and the signed bytes are both on the page: an auditor can reproduce
    // `id()` from what is rendered.
    assert!(detail.body.contains("The signed bytes"));
    // Escaped, not raw: the canonical JSON reaches the page through the templating layer's
    // escaper like every other value, so a payload containing markup cannot become markup.
    assert!(
        detail.body.contains("&#34;kind&#34;:&#34;effect&#34;"),
        "{}",
        detail.body
    );
    assert!(
        !detail.body.contains("\"kind\":\"effect\""),
        "nothing is rendered raw"
    );
}

#[tokio::test]
async fn a_policy_violation_is_surfaced_as_the_confession_it_is() {
    let world = world().await;
    // A `prohibited` action reported as *applied* is a component confessing it did the thing
    // nothing could have permitted (§05 §3 step 2). The kernel appends and flags it rather than
    // refusing, because refusing would delete the only record that it happened.
    let confession = world
        .effect("github.delete_repo", "prohibited", json!({}))
        .await;
    world.accept(&confession, &[]).await;

    let attempts = get(&world, "/console/attempts").await;
    assert_eq!(attempts.status, StatusCode::OK);
    assert!(attempts.body.contains("Policy violations"));
    assert!(
        attempts.body.contains("prohibited-applied"),
        "{}",
        attempts.body
    );

    let filtered = get(&world, "/console/audit?violations-only=true").await;
    assert!(
        filtered.body.contains("github.delete_repo"),
        "{}",
        filtered.body
    );
    assert!(
        filtered.body.contains("violation"),
        "the row is marked, not merely listed"
    );
}

#[tokio::test]
async fn the_console_verifies_a_chain_and_reports_a_broken_one_as_a_finding() {
    let world = world().await;
    world
        .accept(
            &world.effect("github.get_file", "read", json!({})).await,
            &[],
        )
        .await;

    let page = get(&world, &format!("/console/streams/{EFFECT_STREAM}/verify")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("VALID"), "{}", page.body);
    assert!(!page.body.contains("INVALID"), "{}", page.body);

    // A stream that holds nothing cannot be verified, and the console says which stream and why
    // rather than rendering an empty success.
    let empty = get(&world, "/console/streams/gw:dev:9999/verify").await;
    assert_eq!(empty.status, StatusCode::OK);
    assert!(empty.body.contains("INVALID"), "{}", empty.body);
    assert!(empty.body.contains("chain-empty-range"), "{}", empty.body);
}

#[tokio::test]
async fn quiet_streams_are_a_finding_not_a_null_result() {
    let world = world().await;
    world
        .accept(
            &world.effect("github.get_file", "read", json!({})).await,
            &[],
        )
        .await;

    let fresh = get(&world, "/console/streams").await;
    assert!(fresh.body.contains(EFFECT_STREAM));
    assert!(
        !fresh.body.contains("class=\"quiet\""),
        "nothing is quiet yet"
    );

    // Move the clock past the policy's checkpoint interval without appending anything.
    world.clock.advance_seconds(7_200);
    let later = get(&world, "/console/streams").await;
    assert!(later.body.contains("class=\"quiet\""), "{}", later.body);
    let overview = get(&world, "/console").await;
    assert!(overview.body.contains("Quiet streams"));
    assert!(overview.body.contains(EFFECT_STREAM), "{}", overview.body);
}

#[tokio::test]
async fn the_mandate_registry_surfaces_expiry_and_revocation() {
    let world = world().await;
    let registry = get(&world, "/console/mandates").await;
    assert_eq!(registry.status, StatusCode::OK);
    assert!(registry.body.contains(&world.standing_mandate[..12]));
    assert!(registry.body.contains("standing"));
    assert!(
        registry.body.contains(&world.root.subject),
        "the grantor is named"
    );

    let revocation = world
        .revocation(&world.root, &world.standing_mandate, NOW)
        .await;
    world.accept(&revocation, &[]).await;

    let after = get(&world, "/console/mandates").await;
    assert!(after.body.contains("revoked"), "{}", after.body);
    assert!(after.body.contains("laptop lost"), "the reason is shown");
    // The mandate is not removed: the audit records what was permitted at the time.
    assert!(after.body.contains(&world.standing_mandate[..12]));
}

#[tokio::test]
async fn the_export_is_the_signed_bytes_not_a_rendering_of_them() {
    let world = world().await;
    let id = world
        .accept(
            &world.effect("github.get_file", "read", json!({})).await,
            &[],
        )
        .await;

    let export = get(&world, "/console/audit/export?stream=gw:dev:0001").await;
    assert_eq!(export.status, StatusCode::OK);
    let lines: Vec<&str> = export.body.lines().collect();
    assert_eq!(lines.len(), 1, "one line per record");
    let record: Value = serde_json::from_str(lines[0]).expect("each line is a JSON document");
    assert_eq!(record["id"].as_str(), Some(id.as_str()));
    // The envelope inside the export is the object that was signed, so `id()` recomputes from the
    // file alone — an export a regulator cannot re-verify is an assertion, not evidence.
    let recomputed = stozher_core::signed::object_id(&record["envelope"]).expect("hashing");
    assert_eq!(recomputed, id);
}

#[tokio::test]
async fn the_pending_page_shows_blocked_effects_and_names_them_as_terminated() {
    let world = world().await;
    let blocked = world
        .effect(
            "github.create_issue",
            "consequential",
            json!({ "execution": { "outcome": "blocked" } }),
        )
        .await;
    world.accept(&blocked, &[]).await;

    let page = get(&world, "/console/pending").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("github.create_issue"), "{}", page.body);
    // S3's version of this test asserted the page carried no form, because there was nothing a
    // human could sign. S4 makes the queue kernel-native, so the assertion that matters now is the
    // opposite one and lives in `gate_queue_and_console_decisions.rs`. What is still true here is
    // that a `blocked` *effect envelope* is not a queue entry — it already terminated — and the
    // page must not present it as something that can still be answered.
    assert!(
        page.body.contains("Did not reach the world"),
        "a blocked effect must not be presented as answerable: {}",
        page.body
    );
}

// -- the revocation feed --------------------------------------------------------------------

#[tokio::test]
async fn the_revocation_feed_lists_revocations_and_is_cheap_to_poll() {
    let world = world().await;

    let empty = get(&world, "/v1/revocations").await;
    assert_eq!(empty.status, StatusCode::OK);
    assert_eq!(empty.json()["count"].as_u64(), Some(0));
    let first_epoch = empty.etag.clone().expect("the epoch is the ETag");

    // A poll that changes nothing costs a conditional request and reads no document.
    let unchanged = request(
        &world,
        "GET",
        "/v1/revocations",
        &[
            ("authorization", format!("Bearer {TOKEN}")),
            ("if-none-match", first_epoch.clone()),
        ],
    )
    .await;
    assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
    assert!(unchanged.body.is_empty());

    let revocation = world
        .revocation(&world.root, &world.standing_mandate, NOW)
        .await;
    world.accept(&revocation, &[]).await;

    let after = get(&world, "/v1/revocations").await;
    assert_eq!(after.json()["count"].as_u64(), Some(1));
    assert_ne!(
        after.etag.as_deref(),
        Some(first_epoch.as_str()),
        "the epoch must move when the set does — a poller keyed on it would otherwise never re-read"
    );
    let listed = &after.json()["revocations"][0];
    assert_eq!(
        listed["revokes"].as_str(),
        Some(world.standing_mandate.as_str())
    );
    // The document is served as signed, so the poller verifies it rather than trusting the kernel.
    assert!(listed["sig"]["value"].is_string());

    // Stale conditional: the set changed, so the full document is served.
    let stale = request(
        &world,
        "GET",
        "/v1/revocations",
        &[
            ("authorization", format!("Bearer {TOKEN}")),
            ("if-none-match", first_epoch),
        ],
    )
    .await;
    assert_eq!(stale.status, StatusCode::OK);
}

#[tokio::test]
async fn the_revocation_feed_requires_a_credential() {
    let world = world().await;
    let answer = request(&world, "GET", "/v1/revocations", &[]).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn envelopes_can_be_filtered_by_kind() {
    let world = world().await;
    world
        .accept(
            &world
                .revocation(&world.root, &world.standing_mandate, NOW)
                .await,
            &[],
        )
        .await;

    let answer = get(&world, "/v1/envelopes?kind=revocation").await;
    assert_eq!(answer.status, StatusCode::OK);
    let records = answer.json();
    assert_eq!(records["count"].as_u64(), Some(1));
    assert_eq!(
        records["records"][0]["envelope"]["kind"].as_str(),
        Some("revocation")
    );
}

/// The envelope's copy of a revocation and the signed object it carries may not disagree.
///
/// §03 §7 duplicates `revokes`, `revoked-at` and `reason` out of the signed object so the store can
/// index a revocation without opening it — the same shape `decision-of` has beside `decision`.
/// Duplication is only safe while the two cannot diverge: otherwise an emitter chooses which reader
/// agrees with it, and a revocation is the last record in this system that may be ambiguous.
///
/// The attack this refuses: sign an object revoking a mandate nobody minds losing, then project a
/// different `revokes` into the envelope. A reader that indexed the projection and a reader that
/// re-checked the signature would then disagree about which mandate is dead.
#[tokio::test]
async fn a_revocation_envelope_cannot_disagree_with_the_object_it_carries() {
    let world = world().await;
    let honest = world
        .revocation(&world.root, &world.standing_mandate, NOW)
        .await;
    // The control: the honest one is accepted, so what follows is about the mismatch and not about
    // the fixture being malformed.
    world.accept(&honest, &[]).await;

    for member in ["revokes", "revoked-at", "reason"] {
        let mut forged = honest.clone();
        forged[member] = json!(match member {
            "revokes" => "f".repeat(64),
            // Deliberately not `NOW`: the honest fixture already carries that, so a "forgery"
            // setting it would produce byte-identical bytes and be accepted as an idempotent
            // retry — a green test proving nothing. Caught by printing the outcome instead of
            // trusting the fixture.
            "revoked-at" => "2026-07-26T08:59:00.000Z".to_owned(),
            _ => "a different reason".to_owned(),
        });
        // Re-sign so the envelope itself verifies: the point is that a *valid* envelope whose
        // projection contradicts its object is still refused, not that tampering breaks a signature.
        let forged = world.root.sign(&forged);
        // `reject` asserts the reason code; the rejection record is where the detail lands, and it
        // must name which member disagreed — "they differ" sends an operator to read both objects.
        // `reject` asserts the code; the detail must also name *which* member disagreed, because
        // "they differ" sends an operator to diff two objects by hand.
        world
            .reject(&forged, &[], "revocation-object-mismatch")
            .await;
    }
}

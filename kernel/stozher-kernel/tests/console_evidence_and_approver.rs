//! What the console has to be right about: the evidence it hands a regulator, and the question it
//! puts to an approver.
//!
//! These are not cosmetic assertions. An export that silently drops records is the worst defect
//! available to a product sold on provable auditability — the file arrives named, dated and
//! incomplete, and neither the regulator nor the operator who sent it can tell. A queue that cannot
//! answer "on whose authority" asks a human to sign for authority they were never shown.
//!
//! The rest of `docs/design/console.md`'s claims are asserted in `console_and_revocations.rs`; this
//! file holds the ones where the page was making a claim it could not keep.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_kernel::http;
use stozher_testkit::{TOKEN, World, world};
use tower::ServiceExt;

struct Answer {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

async fn request(world: &World, uri: &str, headers: &[(&str, String)]) -> Answer {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(builder.body(Body::empty()).expect("a request"))
        .await
        .expect("the router responds");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collecting the body")
        .to_bytes();
    Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn get(world: &World, uri: &str) -> Answer {
    request(world, uri, &[("authorization", format!("Bearer {TOKEN}"))]).await
}

/// Append `count` ordinary read effects, so a filter has more than a page of rows to match.
async fn fill(world: &World, count: usize) {
    for _ in 0..count {
        let effect = world.effect("github.get_file", "read", json!({})).await;
        world.accept(&effect, &[]).await;
    }
}

#[tokio::test]
async fn the_regulator_export_carries_every_matching_record_whatever_the_page_limit_says() {
    // The export used to build its query from the audit page's filter string, which always carries
    // `limit` — 200 by default. `export?limit=2` returned two lines out of a full store, with no
    // header, no marker and no trailing line to say so, while `Content-Disposition` presented the
    // result as a finished file.
    let world = world().await;
    fill(&world, 12).await;

    let all = get(&world, "/console/audit/export").await;
    assert_eq!(all.status, StatusCode::OK);
    let complete = all.body.lines().count();
    assert!(
        complete >= 12,
        "the store holds fewer rows than we appended"
    );

    // A `limit` supplied by hand does not shrink the evidence either. It is the page's row cap and
    // the export does not read it.
    let capped = get(&world, "/console/audit/export?limit=2").await;
    assert_eq!(
        capped.body.lines().count(),
        complete,
        "the export honoured a page limit and dropped evidence"
    );
    assert_eq!(
        capped
            .headers
            .get("x-stozher-export-records")
            .map(|v| v.to_str().expect("an ASCII header").to_owned()),
        Some(complete.to_string())
    );

    // Still NDJSON, still exactly as signed: every line parses as a record with an envelope in it,
    // so nothing was prepended to announce completeness at the cost of the format.
    for line in capped.body.lines() {
        let record: Value = serde_json::from_str(line).expect("each line is one JSON object");
        assert!(record["envelope"]["sig"]["value"].is_string(), "{line}");
    }
}

#[tokio::test]
async fn the_audit_page_says_how_many_matched_as_well_as_how_many_it_drew() {
    // `count: records.len()` reported rows *returned*, rendered as "N record(s)" — so a filter
    // matching five thousand read as one matching two hundred, and nothing on the page distinguished
    // the two.
    let world = world().await;
    fill(&world, 12).await;

    let page = get(&world, "/console/audit?limit=3").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains("<b>3</b> shown below"),
        "the page does not say how many rows it drew: {}",
        page.body
    );
    assert!(
        page.body.contains("This table is not the whole answer"),
        "a truncated table does not say so: {}",
        page.body
    );
    // And the export link the page renders carries no limit for the export to inherit.
    assert!(
        !page.body.contains("/console/audit/export?limit"),
        "the export href carries the page's row cap: {}",
        page.body
    );
}

#[tokio::test]
async fn the_pending_queue_answers_on_whose_authority() {
    // `docs/design/console.md` requires the mandate chain, "one click to human root", on the queue.
    // The parked block rendered `mandate_short` as plain text with no anchor and had no human root
    // at all — while the blocked table two sections down had both.
    let world = world().await;
    let draft = world
        .effect("github.create_issue", "consequential", json!({}))
        .await;
    let request_object = world.action_request(&stozher_testkit::Ask {
        requester: &world.agent,
        component: "gateway",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "github.create_issue",
        target: draft["execution"]["target"].as_str().expect("target"),
        args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
    });
    let parked = Request::builder()
        .method("POST")
        .uri("/v1/gate/requests")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(
            stozher_core::jcs::canonicalize(&request_object).expect("canonicalizing"),
        ))
        .expect("a request");
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(parked)
        .await
        .expect("the router responds");
    assert_eq!(response.status(), StatusCode::CREATED);

    let page = get(&world, "/console/pending").await;
    assert!(
        page.body
            .contains(&format!("/console/mandates#{}", world.standing_mandate)),
        "the parked mandate is not a link: {}",
        page.body
    );
    assert!(
        page.body.contains("on whose authority"),
        "the queue does not ask the question: {}",
        page.body
    );
    // The human the chain terminates at, by name — `human:ivan` granted the standing mandate.
    assert!(
        page.body.contains(&world.root.subject),
        "the human root is not named: {}",
        page.body
    );
    // This submission carried no arguments, and the page says so in those words (§06 §4.4 rule 8)
    // rather than presenting the hash as if it were the arguments, and rather than rendering the
    // absence as an empty argument list — which is what a call that genuinely took none looks like.
    assert!(
        page.body.contains("The arguments were not supplied"),
        "the missing arguments are not named as missing: {}",
        page.body
    );
}

#[tokio::test]
async fn the_operator_client_can_find_its_csrf_token_on_the_page_the_console_actually_renders() {
    // `bin/stozher-approve` submits through `stozher-kernel answer`, which fetches this page and
    // reads the token out of it. The parser was written against a `<form>`; when the form came out
    // of the template — the route is `Bearer`-authenticated, so a browser form could never have
    // reached it — every unit test kept passing, because each one builds its own page with a form
    // in it. Nothing compared the parser to the template, so the only signal was an operator
    // getting `console-csrf-invalid` for a request that was sitting right there.
    let world = world().await;
    let draft = world
        .effect("github.create_issue", "consequential", json!({}))
        .await;
    let request_object = world.action_request(&stozher_testkit::Ask {
        requester: &world.agent,
        component: "gateway",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "github.create_issue",
        target: draft["execution"]["target"].as_str().expect("target"),
        args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
    });
    let parked = Request::builder()
        .method("POST")
        .uri("/v1/gate/requests")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(
            stozher_core::jcs::canonicalize(&request_object).expect("canonicalizing"),
        ))
        .expect("a request");
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(parked)
        .await
        .expect("the router responds");
    assert_eq!(response.status(), StatusCode::CREATED);
    let request_hash = serde_json::from_slice::<Value>(
        &response
            .into_body()
            .collect()
            .await
            .expect("collecting the body")
            .to_bytes(),
    )
    .expect("a JSON answer")["request-hash"]
        .as_str()
        .expect("a request hash")
        .to_owned();

    let page = get(&world, "/console/pending").await;
    let found = stozher_kernel::operator::csrf_for(&page.body, &request_hash);
    assert_eq!(
        found.as_deref(),
        // The token the kernel would accept from this caller for this request. Asserting only
        // "some token was found" would pass on a parser that read a neighbouring row's.
        Some(
            world
                .kernel
                .csrf_token("agent:test-harness", &request_hash)
                .as_str()
        ),
        "the operator client cannot read its token off the rendered page: {}",
        page.body
    );
}

#[tokio::test]
async fn an_unauthenticated_console_page_answers_in_the_consoles_own_voice() {
    // Same rule as everywhere else (§05 §2.2) and the same status. What changes is that a person who
    // opened this in a browser now gets a page that says what to do, and the browser gets a
    // `WWW-Authenticate` header it can act on — instead of a raw JSON body and neither.
    let world = world().await;
    let answer = request(&world, "/console/pending", &[]).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        answer
            .headers
            .get(axum::http::header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().expect("an ASCII header")),
        Some("Bearer realm=\"stozher console\"")
    );
    assert!(
        answer.body.contains("<!doctype html>"),
        "still answering a browser with JSON: {}",
        answer.body
    );
    assert!(answer.body.contains("Bearer"), "{}", answer.body);

    // The API's own routes are untouched: they still answer JSON with a reason code.
    let api = request(&world, "/v1/envelopes?limit=1", &[]).await;
    assert_eq!(api.status, StatusCode::UNAUTHORIZED);
    assert!(api.body.contains("caller-unauthenticated"), "{}", api.body);
}

#[tokio::test]
async fn every_console_page_carries_a_dark_palette_and_marks_the_page_it_is_on() {
    // `color-scheme: light dark` opts every page into the browser's dark canvas; without a dark
    // palette the semantic tokens land at 2.5:1–3.3:1 on it, which is below AA for the colours a
    // verdict, a prohibited class and a violation are carried in.
    let world = world().await;
    let page = get(&world, "/console/pending").await;
    assert!(
        page.body.contains("@media (prefers-color-scheme: dark)"),
        "no dark palette: {}",
        page.body
    );
    assert!(
        page.body
            .contains("<a href=\"/console/pending\" aria-current=\"page\">"),
        "no active-page indicator: {}",
        page.body
    );
}

/// An effect whose evidence payload holds the call's arguments, as the gateway emits it.
async fn effect_with_arguments(world: &World, amount: u64) -> String {
    let body = json!({ "server": "github", "tool": "create_issue", "arguments": { "title": "refund ORD-88214", "amount_cents": amount } });
    let hash = stozher_core::jcs::object_hash(&body).expect("payload hash");
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
            &[json!({ "payload-hash": hash, "media-type": "application/json", "payload": body })],
        )
        .await;
    hash
}

#[tokio::test]
async fn the_export_says_where_the_argument_values_are_without_putting_them_in_the_file() {
    // An incident responder exported an applied refund, found `args-hash` and no amount, and
    // reported that applied effects retain no arguments. They are retained — the payload is
    // `{server, tool, arguments}` — and nothing between the export and them said so.
    let world = world().await;
    let hash = effect_with_arguments(&world, 4_999_000).await;

    let export = get(&world, "/console/audit/export").await;
    assert_eq!(export.status, StatusCode::OK);
    assert_eq!(
        export
            .headers
            .get("x-stozher-payload-route")
            .map(|v| v.to_str().expect("an ASCII header")),
        Some("/v1/payloads/{payload-hash}"),
    );

    // The guard, and the more important half: nothing was added to the bytes. Every line is still
    // one envelope a verifier re-derives `id()` over, and the amount is *not* in the file — an
    // export that started carrying argument values would breach the payload's retention ceiling by
    // copying it into a document with none.
    assert!(
        !export.body.contains("4999000"),
        "argument values leaked into the signed export"
    );
    for line in export.body.lines() {
        let record: Value = serde_json::from_str(line).expect("each line is one JSON object");
        let recomputed = stozher_core::signed::object_id(&record["envelope"]).expect("hashing");
        assert_eq!(record["id"].as_str(), Some(recomputed.as_str()));
    }

    // And the advertised route answers for a hash taken out of the export.
    let payload = get(&world, &format!("/v1/payloads/{hash}")).await;
    assert_eq!(payload.status, StatusCode::OK);
    assert!(
        payload.body.contains("4999000"),
        "the route the export advertises did not serve the arguments: {}",
        payload.body
    );
}

#[tokio::test]
async fn the_export_renders_as_a_document_that_says_it_is_not_the_record() {
    // "NDJSON is not a document" — a compliance officer hand-wrote the cover memo for their auditor
    // because the product emitted no artefact a lawyer reads.
    let world = world().await;
    effect_with_arguments(&world, 4_999_000).await;

    let document = get(
        &world,
        "/console/audit/export?classification=consequential&format=html",
    )
    .await;
    assert_eq!(document.status, StatusCode::OK);
    assert!(
        document.body.contains("github.create_issue"),
        "the document does not carry the record it is a reading of"
    );
    // It says which question it answers. A rendering that drops the filters is a file that looks
    // like the answer to a question nobody asked.
    assert!(
        document.body.contains("classification=consequential"),
        "the document does not restate the filters that produced it: {}",
        document.body
    );
    // And it says what it is not.
    assert!(
        document.body.contains("not the record"),
        "the document does not disclaim itself"
    );
}

#[tokio::test]
async fn the_default_export_is_still_the_signed_bytes() {
    // The paired negative for the format switch: adding a rendering must not change what an
    // existing caller — a regulator's verifier, or the console's own link — receives.
    let world = world().await;
    effect_with_arguments(&world, 4_999_000).await;

    let default = get(&world, "/console/audit/export").await;
    assert_eq!(
        default
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().expect("an ASCII header")),
        Some("application/x-ndjson; charset=utf-8"),
    );
    assert!(
        !default.body.contains("<html"),
        "the default turned into a page"
    );
    let explicit = get(&world, "/console/audit/export?format=ndjson").await;
    assert_eq!(explicit.body, default.body, "naming the default changed it");
}

#[tokio::test]
async fn an_unknown_export_format_is_refused_rather_than_quietly_defaulted() {
    // The same rule the unknown-*filter* guard already enforces, for the same reason: a silent
    // fallback hands back a file that looks like the answer to the question that was asked.
    let world = world().await;
    let refused = get(&world, "/console/audit/export?format=csv").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(
        refused.body.contains("No such format: csv"),
        "{}",
        refused.body
    );
}

#[tokio::test]
async fn the_document_keeps_every_envelope_that_is_not_an_effect() {
    // A compliance officer exported six human decisions and received six identical blank rows: the
    // table was built from `execution.*`, and a mandate, a policy change and a gate decision have
    // none. The `kind` column — which the ordinary audit page has always had — is what tells them
    // apart, and without it the artefact built for auditors was worse than the page built for the
    // operator.
    let world = world().await;
    effect_with_arguments(&world, 4_999_000).await;

    let document = get(&world, "/console/audit/export?format=html").await;
    assert_eq!(document.status, StatusCode::OK);
    assert!(
        document.body.contains("<th>kind</th>"),
        "the document has no kind column, so non-effect envelopes are indistinguishable"
    );
    // The ceremony's own mandate is in every store, carries no `execution`, and is exactly the
    // shape that rendered as dashes.
    assert!(
        document.body.contains("<td>mandate</td>"),
        "a mandate envelope is not named in the document: {}",
        document.body
    );
    // And the effect still renders its action, so naming the kinds did not cost the rows that
    // always worked.
    assert!(document.body.contains("github.create_issue"));
}

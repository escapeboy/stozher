//! Keyset paging over the audit log — `docs/product-completion-design.md` §3 (v0.3).
//!
//! # What was wrong
//!
//! The audit explorer drew the first `limit` rows, said so honestly, and offered no way to reach the
//! second page: `offset` was hard-coded to zero. The export *did* page, by `OFFSET`, which is stable
//! only while nothing sorts into the region already discarded — and `emitted-at` is the emitter's
//! clock, not arrival order, so a concurrent append lands ahead of rows a reader has passed and
//! shifts every later row down by one.
//!
//! # What that costs, stated precisely
//!
//! **Duplication, not loss.** The store is append-only and enforced so by triggers, so no row can
//! vanish from under an offset. `no_record_is_lost_or_repeated_when_the_log_grows_mid_walk` asserts
//! both halves rather than only the one that sounds worse, because a test that only checked for
//! loss would pass against the defect that was actually there.
//!
//! # Why the fixed clock makes these tests harder, not easier
//!
//! The testkit's clock is fixed, so every envelope here carries the **same** `emitted-at`. The
//! ordering's leading column is therefore constant and the entire cursor rests on the `(stream, seq)`
//! tie-break — which is the case a cursor over a non-unique key gets wrong, by either skipping the
//! rest of a tie or repeating it. These tests run against that case by default.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_kernel::http;
use stozher_testkit::{TOKEN, World, world};
use tower::ServiceExt;

async fn get(world: &World, uri: &str) -> (StatusCode, String) {
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collecting the body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn json_get(world: &World, uri: &str) -> Value {
    let (status, body) = get(world, uri).await;
    assert_eq!(status, StatusCode::OK, "{uri} answered {status}: {body}");
    serde_json::from_str(&body).expect("a JSON body")
}

/// Accept `count` further effects, so the log is longer than one page.
async fn append_effects(world: &World, count: usize) {
    for _ in 0..count {
        let effect = world.effect("github.get_file", "read", json!({})).await;
        world.accept(&effect, &[]).await;
    }
}

/// Walk `/v1/envelopes` from the start, following `next`, and return the ids in the order seen.
///
/// Bounded: a cursor that failed to advance would otherwise loop for ever, and a hanging test says
/// far less than a failing one.
async fn walk(world: &World, base: &str, limit: usize) -> Vec<String> {
    let mut ids = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..64 {
        let uri = match &after {
            None => format!("{base}?limit={limit}"),
            Some(cursor) => format!("{base}?limit={limit}&after={}", urlencode(cursor)),
        };
        let page = json_get(world, &uri).await;
        for record in page["records"].as_array().expect("records") {
            ids.push(record["id"].as_str().expect("an id").to_owned());
        }
        match page["next"].as_str() {
            Some(next) => after = Some(next.to_owned()),
            None => return ids,
        }
    }
    panic!("the walk did not terminate: the cursor is not advancing");
}

/// Enough of an encoder for the two characters a cursor can carry that a query string reads.
fn urlencode(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            ':' => "%3A".to_owned(),
            '+' => "%2B".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

#[tokio::test]
async fn paging_visits_every_record_exactly_once() {
    let world = world().await;
    append_effects(&world, 7).await;

    let whole = walk(&world, "/v1/envelopes", 1_000).await;
    assert!(
        whole.len() > 3,
        "the log is too short for paging to be under test: {} records",
        whole.len()
    );

    for limit in [1, 2, 3] {
        let paged = walk(&world, "/v1/envelopes", limit).await;
        assert_eq!(
            paged, whole,
            "paging at limit={limit} did not reproduce the unpaged order"
        );
        let unique: BTreeSet<&String> = paged.iter().collect();
        assert_eq!(
            unique.len(),
            paged.len(),
            "paging at limit={limit} returned a record more than once"
        );
    }
}

#[tokio::test]
async fn no_record_is_lost_or_repeated_when_the_log_grows_mid_walk() {
    let world = world().await;
    append_effects(&world, 5).await;

    // Page one, then let the log grow before page two — the window `OFFSET` could not survive.
    let first = json_get(&world, "/v1/envelopes?limit=3").await;
    let mut seen: Vec<String> = first["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|r| r["id"].as_str().expect("an id").to_owned())
        .collect();
    assert_eq!(seen.len(), 3);
    let before: BTreeSet<String> = seen.iter().cloned().collect();

    append_effects(&world, 4).await;

    let mut after = first["next"].as_str().expect("a next cursor").to_owned();
    for _ in 0..64 {
        let page = json_get(
            &world,
            &format!("/v1/envelopes?limit=3&after={}", urlencode(&after)),
        )
        .await;
        for record in page["records"].as_array().expect("records") {
            seen.push(record["id"].as_str().expect("an id").to_owned());
        }
        match page["next"].as_str() {
            Some(next) => after = next.to_owned(),
            None => break,
        }
    }

    // Not repeated: nothing from page one came back. This is the half that was actually broken.
    let unique: BTreeSet<&String> = seen.iter().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "a record was returned twice across a walk the log grew during"
    );

    // Not lost: every record that existed when the walk started is in the result. The store is
    // append-only so this could not have failed under `OFFSET` either — it is asserted so that a
    // future cursor whose predicate is too strict cannot trade one defect for the worse one.
    let collected: BTreeSet<String> = seen.into_iter().collect();
    for id in &before {
        assert!(collected.contains(id), "the walk lost {id}");
    }
    let remaining = walk(&world, "/v1/envelopes", 1_000).await;
    for id in &remaining {
        assert!(
            collected.contains(id) || !before.contains(id),
            "a record present at the start of the walk is missing from it: {id}"
        );
    }
}

#[tokio::test]
async fn the_last_page_offers_no_cursor() {
    let world = world().await;
    append_effects(&world, 2).await;

    let all = json_get(&world, "/v1/envelopes?limit=1000").await;
    assert!(
        all["next"].is_null(),
        "a page that returned everything still offered a next cursor"
    );
}

#[tokio::test]
async fn a_cursor_this_kernel_did_not_write_is_refused_rather_than_ignored() {
    let world = world().await;
    append_effects(&world, 3).await;

    // Silently starting over is the failure under test: it answers a request for a later page with
    // the first one, and looks like success. Every one of these is a plausible hand-edit.
    for bad in [
        "nonsense",
        "2026-07-26T09:00:00.000Z",           // no seq, no stream
        "2026-07-26T09:00:00.000Z/1",         // no stream
        "2026-07-26T09:00:00.000Z/notaseq/s", // seq is not a number
        "2026-07-26T09:00:00.000Z/1/",        // empty stream
        "26-07-2026/1/gw:dev:0001",           // not the one timestamp form
    ] {
        let (status, body) = get(
            &world,
            &format!("/v1/envelopes?limit=1&after={}", urlencode(bad)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the API accepted {bad:?} as a cursor: {body}"
        );

        let (status, body) = get(&world, &format!("/console/audit?after={}", urlencode(bad))).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the console accepted {bad:?} as a cursor: {body}"
        );
    }
}

#[tokio::test]
async fn the_console_offers_the_next_page_rather_than_only_naming_the_truncation() {
    let world = world().await;
    append_effects(&world, 4).await;

    let (status, first) = get(&world, "/console/audit?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        first.contains("This table is not the whole answer"),
        "the page did not say it was truncated"
    );
    // The defect was that it said so and stopped there. Saying "raise the limit" is not a way to
    // read a log that is larger than any limit an operator would type.
    let link = first
        .split("href=\"")
        .find(|part| part.starts_with("/console/audit?") && part.contains("after="))
        .map(|part| part.split('"').next().unwrap_or_default().to_owned())
        .expect("the page offers no link to the next page");

    // A browser decodes the entity before it requests the URL; this harness has to do it by hand.
    // `&#38;` rather than `&amp;` is what askama's escaper writes, and getting it wrong is not
    // harmless: the `#` starts a fragment, so the request silently loses every parameter after it
    // and comes back as a perfectly healthy page one.
    let (status, second) = get(&world, &link.replace("&#38;", "&").replace("&amp;", "&")).await;
    assert_eq!(status, StatusCode::OK, "the next-page link 404ed: {second}");
    assert!(
        second.contains("continuing from an earlier page"),
        "the second page does not say it is one"
    );

    // And it is genuinely a different page: no envelope link from the first appears on the second.
    for id in first
        .split("/console/envelopes/")
        .skip(1)
        .filter_map(|part| part.split('"').next())
    {
        assert!(
            !second.contains(&format!("/console/envelopes/{id}")),
            "the next page repeated {id} from the previous one"
        );
    }
}

#[tokio::test]
async fn the_export_carries_every_envelope_once_and_ignores_the_page_cursor() {
    let world = world().await;
    append_effects(&world, 6).await;

    let (status, body) = get(&world, "/console/audit/export").await;
    assert_eq!(status, StatusCode::OK);
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    let ids = walk(&world, "/v1/envelopes", 1_000).await;
    assert_eq!(
        lines.len(),
        ids.len(),
        "the export and the log disagree about how many records there are"
    );
    let unique: BTreeSet<&str> = lines.iter().copied().collect();
    assert_eq!(unique.len(), lines.len(), "the export repeated a record");

    // An export requested from page four must still be the whole audit trail. Carrying `limit` into
    // it is the defect the export's own documentation was written about; `after` would do the same
    // thing one page further in, and the resulting file would still call itself the audit trail.
    let cursor = json_get(&world, "/v1/envelopes?limit=1")
        .await
        .get("next")
        .and_then(Value::as_str)
        .expect("a cursor")
        .to_owned();
    let (status, from_page_two) = get(
        &world,
        &format!("/console/audit/export?after={}", urlencode(&cursor)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        from_page_two.lines().filter(|l| !l.is_empty()).count(),
        lines.len(),
        "an export taken from a later page dropped the records before it"
    );
}

/// An export asked for a filter that does not exist is refused, not widened.
///
/// `Filters::from_params` reads the names it knows and ignores the rest, which is right for a page
/// an operator is browsing: a typo in the address bar should not be an error. It is wrong for the
/// artefact that leaves the building. An auditor asked for `?class=consequential` — the field is
/// spelled `classification` — and was handed every record, with a header confirming the count and
/// nothing saying the filter had been dropped. A regulator-facing export that silently widens is
/// worse than one that refuses, because the file looks like the answer to the question that was
/// asked, and nobody downstream can tell that it is not.
#[tokio::test]
async fn an_export_refuses_a_filter_it_does_not_recognise() {
    let world = world().await;
    append_effects(&world, 3).await;

    let (status, body) = get(&world, "/console/audit/export?class=consequential").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body was: {body}");
    assert!(
        body.contains("class"),
        "the refusal must name the filter it did not recognise: {body}"
    );
    assert!(
        body.contains("classification"),
        "and the ones it does, so the reader can see the near-miss: {body}"
    );

    // The correctly-spelled filter still works, so this refuses a typo rather than the feature.
    let (status, _) = get(&world, "/console/audit/export?classification=read").await;
    assert_eq!(status, StatusCode::OK);
}

/// The browsed page keeps the typo and stops asserting the filter held.
///
/// The sibling of the export refusal above, and the half that was missing. `Filters::from_params`
/// ignoring a name it does not know is right for a page someone is browsing — but the sentence
/// under it reads "N record(s) match these filters", which is the assertion that just became false.
/// An incident responder typed `?class=consequential`, was handed all 87 records under that
/// sentence, and read the number as a finding. `?banana=zzz` did the same. Refusing here would make
/// a typo in the address bar an error page; saying so costs a line and keeps the page usable.
#[tokio::test]
async fn the_audit_page_names_a_filter_it_ignored_rather_than_widening_in_silence() {
    let world = world().await;
    append_effects(&world, 3).await;

    for typo in ["class=consequential", "banana=zzz"] {
        let (status, body) = get(&world, &format!("/console/audit?{typo}")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "browsing must not become an error page"
        );
        let name = typo.split('=').next().unwrap();
        assert!(
            body.contains("Not a filter:") && body.contains(name),
            "the page did not say it had ignored {name:?}: {body}"
        );
    }

    // The paired negative: a page whose filters all exist says nothing of the kind. Without this,
    // a banner rendered unconditionally would satisfy every assertion above.
    let (status, body) = get(&world, "/console/audit?classification=read").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("Not a filter:"),
        "a page with only real filters claimed one had been ignored: {body}"
    );
    // `after` rides along from the paging links and is not a filter, so it must not be named either.
    let (status, body) = get(&world, "/console/audit?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("Not a filter:"), "{body}");
}

//! Budget accounting — `spec/03 §4.3`, `docs/product-completion-design.md` §4.2.
//!
//! # What was missing
//!
//! Mandates carried budget dimensions, cognition envelopes carried `cost`, and `budget_within`
//! enforced narrowing at **grant** time. Nothing accumulated spend, so a budget was a declaration
//! the system never checked: an organisation could write `money-eur: "50.00"` on a mandate and the
//! kernel would never once compare anything to it.
//!
//! # The two claims, and the counterfactual for each
//!
//! * **Spend accrues, exactly, and reaches every ancestor.** Without the ancestry half, a chain of
//!   delegations multiplies an organisation's limit by its own depth — each hop carrying its own
//!   untouched cap. `spend_reaches_the_root_that_granted_the_delegation` is the test; the one below
//!   it shows the figure is a *fold*, by dropping the table and recomputing it from the log.
//! * **An over-budget applied effect is flagged, not refused.** The effect already happened, and
//!   refusing the record would delete the only evidence of it. The paired assertion is that a
//!   *within*-budget effect carries no flag — otherwise "flag everything" would pass.

use std::collections::BTreeMap;

use serde_json::json;
use stozher_kernel::{Outcome, codes};
use stozher_testkit::{EFFECT_STREAM, World, world};

/// Accrued spend under one mandate, as the store holds it.
async fn spend(world: &World, mandate: &str) -> BTreeMap<String, String> {
    world
        .ingest()
        .store()
        .spend(mandate)
        .await
        .expect("reading spend")
}

/// The `policy-violation` the store recorded for an envelope, if any.
async fn violation(world: &World, id: &str) -> Option<String> {
    world
        .ingest()
        .store()
        .envelope_by_id(id)
        .await
        .expect("reading the envelope")
        .expect("the envelope is stored")
        .policy_violation
}

#[tokio::test]
async fn an_applied_effect_accrues_one_request_and_a_blocked_one_accrues_nothing() {
    let world = world().await;
    let mandate = world.standing_mandate.clone();
    assert!(
        spend(&world, &mandate).await.is_empty(),
        "a mandate nothing has been done under starts at nothing"
    );

    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    assert_eq!(
        spend(&world, &mandate)
            .await
            .get("requests")
            .map(String::as_str),
        Some("1")
    );

    // A blocked effect is a record that nothing happened. Charging it would make the gate a budget
    // leak: an agent blocked a thousand times would exhaust the cap having done nothing at all.
    let blocked = world
        .effect(
            "github.get_file",
            "read",
            json!({ "execution": { "outcome": "blocked" } }),
        )
        .await;
    world.accept(&blocked, &[]).await;
    assert_eq!(
        spend(&world, &mandate)
            .await
            .get("requests")
            .map(String::as_str),
        Some("1"),
        "a blocked effect was charged as spend"
    );
}

#[tokio::test]
async fn cognition_cost_accrues_exactly_where_binary64_would_drift() {
    let world = world().await;
    let mandate = world.standing_mandate.clone();

    // Ten tenths. In binary64 the running total is 0.9999999999999999.
    for _ in 0..10 {
        let cognition = world
            .cognition(json!({ "cost": { "money-eur": "0.1", "tokens-in": 100 } }))
            .await;
        world.accept(&cognition, &[]).await;
    }

    let accrued = spend(&world, &mandate).await;
    let money = accrued.get("money-eur").expect("money accrued");
    assert_eq!(
        stozher_core::decimal::compare(money, "1").expect("decimal strings"),
        std::cmp::Ordering::Equal,
        "ten additions of 0.1 came to {money}"
    );
    assert_eq!(accrued.get("tokens-in").map(String::as_str), Some("1000"));
}

#[tokio::test]
async fn the_charge_walks_from_the_cited_mandate_to_every_ancestor() {
    // The property: a cost charged under a delegated mandate must also reach the mandate that
    // granted it. Without it, a delegation chain multiplies the organisation's limit by its own
    // depth — every hop carrying an untouched cap, and the root that authorised the whole thing
    // reading zero however much its delegates spend.
    //
    // What is asserted here is the walk that produces the charge list, not an end-to-end two-level
    // spend. §03 §1 forbids a self-grant, so a delegated mandate necessarily has a second grantee,
    // and acting under this fixture's one needs a gated action and an approval — machinery that
    // would make this test about the gate. ADR-0015 records the residual gap.
    let world = world().await;
    let delegated = world.delegated_grant().await;
    world.accept(&delegated, &[]).await;
    // `core_envelope` merges the extra members into the envelope body, so the signed mandate sits
    // at the top level. Its id is `object_id` of that object — the same derivation `grant_standing`
    // uses, rather than a second one that could drift from it.
    let child = stozher_core::signed::object_id(&delegated["mandate"])
        .expect("the grant carries a signed mandate");

    let line = world
        .ingest()
        .store()
        .mandate_line(&child)
        .await
        .expect("walking the line");
    assert!(line.contains(&child), "the line omits the mandate itself");
    assert!(
        line.contains(&world.standing_mandate),
        "the line omits the parent that granted it: {line:?}"
    );

    // And the line is what the store charges: every entry in it, not just the first. A root mandate
    // walks to itself alone, which is the degenerate case the other tests exercise.
    let root_line = world
        .ingest()
        .store()
        .mandate_line(&world.standing_mandate)
        .await
        .expect("walking the line");
    assert_eq!(root_line, vec![world.standing_mandate.clone()]);
}

#[tokio::test]
async fn the_projection_is_a_fold_and_recomputes_to_the_same_figures() {
    // Maxim 9, executed rather than asserted: drop the table, replay the log, get the same numbers.
    // This is what makes a budget figure an answer *about* the chain rather than a second place the
    // truth lives — and it is the operator's way to settle a suspicion about the totals without
    // having to trust them.
    let world = world().await;
    let mandate = world.standing_mandate.clone();
    for _ in 0..3 {
        let effect = world.effect("github.get_file", "read", json!({})).await;
        world.accept(&effect, &[]).await;
    }
    let cognition = world
        .cognition(json!({ "cost": { "money-eur": "1.25" } }))
        .await;
    world.accept(&cognition, &[]).await;

    let before = spend(&world, &mandate).await;
    assert!(
        !before.is_empty(),
        "nothing accrued; the test proves nothing"
    );

    let folded = world
        .ingest()
        .store()
        .rebuild_spend()
        .await
        .expect("rebuilding the projection");
    assert!(folded > 0, "the rebuild folded no envelopes");
    assert_eq!(
        spend(&world, &mandate).await,
        before,
        "the projection did not recompute to what it held"
    );
}

#[tokio::test]
async fn an_over_budget_applied_effect_is_flagged_and_kept_rather_than_refused() {
    let world = world().await;
    // The budgeted mandate caps `requests` at 10.
    let mandate = world.budgeted_mandate.clone();

    let mut flagged = None;
    let mut accepted = 0;
    for _ in 0..12 {
        let effect = world
            .effect("github.get_file", "read", json!({ "mandate-ref": mandate }))
            .await;
        let id = world.accept(&effect, &[]).await;
        accepted += 1;
        if let Some(marker) = violation(&world, &id).await {
            flagged = Some((marker, accepted));
            break;
        }
    }

    let (marker, at) = flagged.expect("no effect was ever flagged as over budget");
    assert_eq!(marker, codes::BUDGET_EXCEEDED_APPLIED);
    // The eleventh is the first one past a cap of ten — the boundary is `at most`, not `less than`.
    assert_eq!(at, 11, "the cap fired at request {at}, not at 11");

    // Every one of them is still in the chain. A budget that deleted records would be a worse
    // defect than a budget that did nothing: the effects happened either way.
    let (head, _) = world.head(EFFECT_STREAM).await;
    assert!(head >= 10, "the chain lost records: head is {head}");
}

#[tokio::test]
async fn an_effect_within_budget_carries_no_violation() {
    // The counterfactual for the test above: without this, "flag everything" would pass.
    let world = world().await;
    let effect = world.effect("github.get_file", "read", json!({})).await;
    let id = world.accept(&effect, &[]).await;
    assert_eq!(violation(&world, &id).await, None);
}

#[tokio::test]
async fn the_budget_route_reports_the_whole_chain_so_a_component_can_block_before_it_spends() {
    // §03 §4.3 puts the blocking on the emitter, and a component cannot block on a figure it has no
    // way to read. Without this route the kernel could only *record* an over-budget effect after the
    // fact, which is detection rather than prevention.
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use stozher_kernel::http;
    use stozher_testkit::TOKEN;
    use tower::ServiceExt;

    let world = world().await;
    let mandate = world.budgeted_mandate.clone();
    for _ in 0..3 {
        let effect = world
            .effect("github.get_file", "read", json!({ "mandate-ref": mandate }))
            .await;
        world.accept(&effect, &[]).await;
    }

    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/mandates/{mandate}/budget"))
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collecting")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    let chain = body["chain"].as_array().expect("chain");
    let entry = chain
        .iter()
        .find(|e| e["mandate"] == mandate.as_str())
        .expect("the mandate itself is in its own chain");
    assert_eq!(entry["resolved"].as_bool(), Some(true));
    assert_eq!(entry["budget"]["requests"].as_i64(), Some(10));
    // The accrued figure is what makes the cap actionable: a cap without a total is a number a
    // component can do nothing with.
    assert_eq!(entry["spent"]["requests"].as_str(), Some("3"));
}

/// §03 §5: a `cognition` envelope is matched on the one scope dimension it can supply.
///
/// Until 2026-08-04 the check was skipped whole because three of §03 §4.2's four dimensions are
/// absent from a cognition envelope — and the fourth, `resource`, is present. The consequence was
/// that `resources` in a mandate's scope constrained every effect and no cognition, so a mandate
/// could not bound what an agent spends on at all. That is the opposite of what an operator writing
/// `resources` naming one model intends, and it failed open.
#[tokio::test]
async fn a_mandate_that_does_not_cover_the_model_refuses_the_spend_on_it() {
    let world = world().await;

    // A mandate whose scope names one model. Everything else about it is the standing mandate the
    // fixture already grants, so the only variable is `resources`.
    let narrow = world
        .grant_standing(
            &"c0".repeat(16),
            json!({
                "scope": {
                    "components": ["*"],
                    "actions": ["*"],
                    "classes": ["read", "benign", "consequential"],
                    "resources": ["model:claude-haiku-4-5"]
                }
            }),
        )
        .await;

    let permitted = world
        .cognition(json!({
            "mandate-ref": narrow,
            "resource": { "kind": "model", "name": "claude-haiku-4-5" }
        }))
        .await;
    world.accept(&permitted, &[]).await;

    // The paired negative, and the whole point: a different model under the same mandate.
    let refused = world
        .cognition(json!({
            "mandate-ref": narrow,
            "resource": { "kind": "model", "name": "claude-opus-5" }
        }))
        .await;
    match world.submit(&refused, &[]).await {
        Outcome::Rejected { reason, .. } => assert_eq!(
            reason, "mandate-scope-not-permitted",
            "refused, but not for the scope"
        ),
        other => panic!("spend on a model the mandate does not name was accepted: {other:?}"),
    }
}

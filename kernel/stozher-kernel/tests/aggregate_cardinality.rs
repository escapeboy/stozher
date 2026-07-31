//! One aggregate envelope must not be an unbounded amount of kernel work.
//!
//! `counts.by-action` is the only member of any envelope kind whose length drives a *per-entry*
//! authorization check: `effect_requests` maps every key to a request and each is matched against
//! the citing mandate's scope. `spec/02 §7` bounds `sample-hashes` at 16 but leaves `by-action`
//! unbounded, so before `AGGREGATE_MAX_ACTIONS` a single submission could ask the kernel for as
//! many mandate checks as the emitter cared to type.
//!
//! The bound is enforced in `envelope::validate`, which ingest runs at step (3) — before
//! `validate_effect_kind` reaches `effect_requests` at all. That ordering is what this test pins:
//! the refusal carries the *structural* code, so no mandate work happened.

use serde_json::{Map, Value, json};
use stozher_core::envelope::AGGREGATE_MAX_ACTIONS;
use stozher_kernel::ingest::Outcome;
use stozher_testkit::world;

/// `counts` overrides for a window folding exactly `count` distinct actions.
///
/// The testkit's overrides are a deep *merge*, so the two actions its default aggregate carries
/// survive unless they are named again — they are, so `count` is the cardinality the kernel sees
/// rather than `count + 2`.
fn counts(count: usize) -> Value {
    let by_action: Map<String, Value> = ["github.get_file", "github.list_issues"]
        .iter()
        .map(|name| ((*name).to_owned(), json!(1)))
        .chain((2..count).map(|i| (format!("github.action_{i}"), json!(1))))
        .collect();
    assert_eq!(by_action.len(), count, "the override must be exact");
    json!({ "counts": { "total": count, "by-action": Value::Object(by_action) } })
}

#[tokio::test]
async fn a_window_folding_more_actions_than_the_bound_is_refused_before_any_mandate_work() {
    let world = world().await;
    let envelope = world.aggregate(counts(AGGREGATE_MAX_ACTIONS + 1)).await;

    match world.submit(&envelope, &[]).await {
        Outcome::Rejected { reason, record, .. } => {
            assert_eq!(reason, "x-aggregate-cardinality");
            assert!(record.is_some(), "the refusal must itself be recorded");
        }
        Outcome::Accepted(appended) => panic!(
            "a {}-action window was accepted as {}",
            AGGREGATE_MAX_ACTIONS + 1,
            appended.id
        ),
        Outcome::Unavailable(e) => panic!("the store was unavailable: {e}"),
    }
}

#[tokio::test]
async fn a_window_at_the_bound_is_judged_on_its_merits_not_its_size() {
    let world = world().await;
    let envelope = world.aggregate(counts(AGGREGATE_MAX_ACTIONS)).await;

    // The bound is a resource limit, not a policy, so it must not be what answers a window that
    // sits exactly on it. This fixture's standing mandate covers one action, so 1024 distinct ones
    // are refused — but for *classification*, which is the kernel reading the window rather than
    // declining to. `envelope::validate` accepting the same shape is asserted in
    // `stozher-core/tests/aggregate_arithmetic.rs`.
    match world.submit(&envelope, &[]).await {
        Outcome::Rejected { reason, .. } => assert_ne!(
            reason, "x-aggregate-cardinality",
            "a window at the bound must not be refused by the bound"
        ),
        Outcome::Accepted(_) => {}
        Outcome::Unavailable(e) => panic!("the store was unavailable: {e}"),
    }
}

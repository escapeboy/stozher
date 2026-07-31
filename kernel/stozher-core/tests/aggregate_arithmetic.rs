//! `counts.by-action` arithmetic and cardinality — `spec/02-envelope.md` §7.
//!
//! These live in an integration test rather than beside `validate_aggregate` because the defect
//! they pin only exists in one build configuration. `check_numbers` bounds each individual count at
//! `MAX_SAFE_INTEGER`, so a *sum* can only leave `i64` by accumulating many of them; in a debug
//! build that accumulation panics, and in a release build without `overflow-checks` it wraps
//! silently onto whatever `counts.total` the emitter chose. The suite therefore has to be run in
//! both profiles to mean anything, which is why `[profile.release] overflow-checks` is part of the
//! fix and not a nicety.

use serde_json::{Map, Value, json};
use stozher_core::envelope;

const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const MAX_SAFE: i64 = 9_007_199_254_740_991;

/// A structurally valid `aggregate` envelope carrying the supplied counts.
///
/// The signature is not verified by [`envelope::validate`], so a well-formed `sig` object with an
/// arbitrary value is enough: this exercises the structural validator, which is the layer the
/// arithmetic lives in.
fn aggregate(total: i64, by_action: Map<String, Value>) -> Value {
    json!({
        "v": "stozher/0.1",
        "kind": "aggregate",
        "emitted-at": "2026-07-26T09:05:00.000Z",
        "stream": "kernel:core",
        "seq": 108,
        "prev-hash": DIGEST,
        "identity": {
            "subject": "agent:claude-code/ivan-mbp",
            "key": "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
            "component": "gateway"
        },
        "mandate-ref": DIGEST,
        "policy-version": "2026.07.1",
        "classification": "read",
        "window": { "from": "2026-07-26T09:00:00.000Z", "to": "2026-07-26T09:05:00.000Z" },
        "counts": { "total": total, "by-action": by_action },
        "sample-hashes": [DIGEST],
        "sig": { "alg": "ed25519", "key": "ed25519:0000000000000000000000000000000000000000000000000000000000000000", "value": "00" }
    })
}

fn counts(values: &[i64]) -> Map<String, Value> {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("github.action_{i}"), json!(v)))
        .collect()
}

/// 2049 counts that truly sum to 2^64 + 1, in an envelope declaring `total: 1`.
///
/// `2048 * MAX_SAFE + 2049 == 18446744073709551617 == 2^64 + 1`, so an `i64` accumulator wraps
/// twice and lands on exactly 1 — the declared total. This is the shape that made
/// `aggregate-count-mismatch` bypassable: an emitter records "1 read" for a window that folded
/// 1.8e19 of them, and the one envelope kind whose arithmetic *is* the audit claim says so.
fn wrapping_window() -> Value {
    let mut values = vec![MAX_SAFE; 2048];
    values.push(2049);
    aggregate(1, counts(&values))
}

#[test]
fn a_window_whose_counts_wrap_onto_the_declared_total_is_refused() {
    let error = envelope::validate(&wrapping_window())
        .expect_err("a window summing to 2^64+1 must not validate as total 1");
    // Which code fires depends on which barrier is hit first; both are refusals, and the point of
    // the test is that neither build profile accepts it.
    assert!(
        matches!(
            error.code(),
            "x-aggregate-cardinality" | "aggregate-count-mismatch"
        ),
        "unexpected code {}",
        error.code()
    );
}

#[test]
fn the_cardinality_bound_is_1024_distinct_actions() {
    let at_bound = aggregate(1024, counts(&vec![1; 1024]));
    envelope::validate(&at_bound).expect("1024 distinct actions is within the bound");

    let over_bound = aggregate(1025, counts(&vec![1; 1025]));
    let error = envelope::validate(&over_bound).expect_err("1025 distinct actions exceeds it");
    assert_eq!(error.code(), "x-aggregate-cardinality");
}

/// The bound is chosen so that `i64` accumulation cannot leave its range even in principle:
/// `1024 * MAX_SAFE_INTEGER` is 9223372036854774784, which is below `i64::MAX`, while 1025 of them
/// is not. The two halves of the fix are therefore not redundant — the bound is what makes the
/// arithmetic's correctness independent of the accumulator width.
#[test]
fn the_bound_keeps_the_widest_admissible_window_inside_i64() {
    assert!((1024_i128 * i128::from(MAX_SAFE)) <= i128::from(i64::MAX));
    assert!((1025_i128 * i128::from(MAX_SAFE)) > i128::from(i64::MAX));
}

/// The widest window the bound admits must still be summed exactly rather than saturated: a real
/// total is capped at `MAX_SAFE_INTEGER` by `check_numbers`, so a sum of 9223372036854774784 can
/// never equal a declared total and must be reported as the mismatch it is.
#[test]
fn the_widest_admissible_window_is_summed_exactly() {
    let env = aggregate(MAX_SAFE, counts(&vec![MAX_SAFE; 1024]));
    let error = envelope::validate(&env).expect_err("1024 * MAX_SAFE is not MAX_SAFE");
    assert_eq!(error.code(), "aggregate-count-mismatch");
    assert!(
        error.detail().contains("9223372036854774784"),
        "the true sum must be reported, got {:?}",
        error.detail()
    );
}

/// `[profile.release] overflow-checks = true` must stay in the workspace manifest.
///
/// This is a configuration assertion rather than a behavioural one, deliberately, and it is here
/// because a mutation test showed that **nothing else binds it**: deleting the setting leaves the
/// whole suite green in both profiles. That is not a gap in the suite — the 1024-action bound makes
/// `i64` accumulation unreachable at this site, so there is no aggregate input left that can
/// overflow. The setting earns its place by guarding the *class*: every other arithmetic site in the
/// workspace, including ones not written yet.
///
/// A guard that no test binds is a guard that a future edit removes silently, which is precisely how
/// this defect class stayed invisible to 153 tests in the first place — debug panicked, release
/// wrapped, and nothing ran release. So the manifest line itself is the thing pinned.
#[test]
fn the_release_profile_still_traps_arithmetic_overflow() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml"),
    )
    .expect("reading the workspace manifest");

    let release_section = manifest
        .split("\n[")
        .find(|section| section.starts_with("profile.release]"))
        .expect("[profile.release] is missing from the workspace manifest");

    assert!(
        release_section
            .lines()
            .any(|line| line.trim() == "overflow-checks = true"),
        "[profile.release] must set overflow-checks = true, so that the profile which ships \
         agrees with the profile the tests run in about what an overflowing sum does:\n{release_section}"
    );
}

/// The other way to make the sum agree without the window being what it says.
///
/// Overflow needs a thousand entries; cancellation needs two. `check_numbers` bounds each count and
/// the fold is now exact, but neither says a count of calls that happened cannot be negative — so
/// `1000000` bulk exports and `-999999` file reads sum to exactly the declared `total: 1`, and the
/// one envelope kind whose arithmetic *is* the audit claim reports a million-record window as one.
#[test]
fn counts_cannot_cancel_each_other_out() {
    let mut by_action = Map::new();
    by_action.insert("github.bulk_export".to_owned(), json!(1_000_000));
    by_action.insert("github.get_file".to_owned(), json!(-999_999));
    let error = envelope::validate(&aggregate(1, by_action))
        .expect_err("a million exports must not record as one read");
    assert_eq!(error.code(), "x-aggregate-count-negative");
}

#[test]
fn a_negative_total_is_refused_too() {
    let error = envelope::validate(&aggregate(-1, counts(&[-1])))
        .expect_err("a window cannot have folded a negative number of calls");
    assert_eq!(error.code(), "x-aggregate-count-negative");
}

#[test]
fn a_window_that_folded_nothing_is_still_arithmetically_sound() {
    // Zero is not negative: an emitter closing an empty window states a true fact about it, and the
    // sign check must not turn that into a refusal.
    let mut by_action = Map::new();
    by_action.insert("github.get_file".to_owned(), json!(0));
    envelope::validate(&aggregate(0, by_action)).expect("a window of zero reads is a real window");
}

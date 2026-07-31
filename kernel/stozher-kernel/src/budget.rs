//! Budget accounting — `spec/03 §4.3`, `docs/product-completion-design.md` §4.2.
//!
//! # What was missing
//!
//! Mandates carried budget dimensions, cognition envelopes carried `cost`, and `budget_within`
//! enforced narrowing at **grant** time. Nothing accumulated spend, so a budget was a declaration
//! the system never checked — an organisation could write `money-eur: "50.00"` on a mandate and the
//! kernel would never once compare anything to it. The console's budgets page was correctly not
//! built rather than invent numbers to put on it.
//!
//! # Where enforcement lives, and why it is not a rejection
//!
//! `spec/03 §4.3` is explicit: "Exhausted budget blocks like an expired mandate: `outcome:
//! "blocked"`, envelope still emitted." So the *blocking* belongs to the emitter, which declines to
//! act and records that it declined.
//!
//! What the kernel does with an effect that reports `outcome: "applied"` beyond its budget is the
//! question this module answers, and the answer follows the pattern `ingest` already holds to for a
//! `prohibited` action and for a policy-denied one: **append and flag, never refuse.** The effect
//! has already happened. Refusing the envelope would delete the only record that it happened, which
//! is the opposite of an audit. `docs/product-completion-design.md` §4.2 proposed refusing it
//! outright; that would have made the store's account of the world quieter than the world, and
//! ADR-0015 records the deviation.
//!
//! # Accrual is exact, and it reaches every ancestor
//!
//! A budget caps "this mandate and everything delegated beneath it" (§03 §4.3), so a cost is charged
//! to the citing mandate *and to every ancestor*. Without that, a chain of delegations would be a
//! way to multiply an organisation's limit by its own depth: each hop would carry its own untouched
//! cap. Amounts are added with [`stozher_core::decimal`] rather than in binary64, because a running
//! total that drifts from the log it was folded from is not a fold.

use std::collections::BTreeMap;

use serde_json::Value;

/// Dimensions a `cost` member can name that are also budget dimensions of §03 §4.3.
///
/// The intersection is deliberately literal. `cost` reports `wall-clock-ms` and §03 §4.3 caps
/// `wall-clock-seconds`; `cost` reports `tokens-in` and `tokens-out` and §03 §4.3 also names a
/// combined `tokens`. Converting the first pair or summing the second would be inventing normative
/// meaning the specification does not state, and a budget enforced by an invented rule is worse than
/// one not enforced — so unmatched dimensions accrue nothing and the gap is recorded in ADR-0015
/// rather than papered over with an assumption.
const COST_DIMENSIONS: [&str; 3] = ["tokens-in", "tokens-out", "wall-clock-seconds"];

/// What one envelope adds to the running totals, by dimension.
///
/// An envelope that spends nothing returns an empty map and is not folded at all.
#[must_use]
pub fn accrual_of(envelope: &Value) -> BTreeMap<String, String> {
    let mut amounts: BTreeMap<String, String> = BTreeMap::new();
    let kind = envelope["kind"].as_str().unwrap_or_default();

    // An effect that was actually applied is one request. An effect that was blocked, denied or
    // merely attempted consumed nothing the organisation is paying for, and charging it would make
    // a refusal cost the same as an action — which would turn a working gate into a budget leak.
    if kind == "effect" && envelope["execution"]["outcome"].as_str() == Some("applied") {
        amounts.insert("requests".to_owned(), "1".to_owned());
    }

    // Cognition is where money is spent (§02 §6). Its `cost` is the only place the specification
    // puts a monetary figure, which is why §03 §4.3 names it as the accounting input.
    if let Some(cost) = envelope.get("cost").and_then(Value::as_object) {
        for (dimension, value) in cost {
            let named =
                COST_DIMENSIONS.contains(&dimension.as_str()) || dimension.starts_with("money-");
            if !named {
                continue;
            }
            let amount = match value {
                Value::String(s) => s.clone(),
                Value::Number(n) if n.is_i64() => n.to_string(),
                // Anything else is refused at envelope validation; skipping here rather than
                // guessing keeps this function total and leaves the refusal where it belongs.
                _ => continue,
            };
            amounts.insert(dimension.clone(), amount);
        }
    }
    amounts
}

/// The dimensions on which `accrued + adding` would exceed `cap`.
///
/// Empty means there is room. The comparison is exact ([`stozher_core::decimal`]); a dimension the
/// cap does not name is unbounded and is not reported, and a malformed figure is reported as
/// exceeded — the safe direction, because a cap that cannot be evaluated must not read as headroom.
#[must_use]
pub fn would_exceed(
    cap: &Value,
    accrued: &BTreeMap<String, String>,
    adding: &BTreeMap<String, String>,
) -> Vec<String> {
    let Some(cap) = cap.as_object() else {
        return Vec::new();
    };
    let mut exceeded = Vec::new();
    for (dimension, limit) in cap {
        let Some(adding) = adding.get(dimension) else {
            continue;
        };
        let zero = "0".to_owned();
        let held = accrued.get(dimension).unwrap_or(&zero);
        let limit = match limit {
            Value::String(s) => s.clone(),
            Value::Number(n) if n.is_i64() => n.to_string(),
            _ => {
                exceeded.push(dimension.clone());
                continue;
            }
        };
        match stozher_core::decimal::add(held, adding) {
            Ok(total) => match stozher_core::decimal::at_most(&total, &limit) {
                Ok(true) => {}
                // Either over the cap, or a cap this build cannot compare. Both are "no headroom":
                // a budget check that fails open is not a budget check.
                Ok(false) | Err(_) => exceeded.push(dimension.clone()),
            },
            Err(_) => exceeded.push(dimension.clone()),
        }
    }
    exceeded
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{accrual_of, would_exceed};

    fn amounts(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn an_applied_effect_is_one_request_and_a_refused_one_is_nothing() {
        let effect =
            |outcome: &str| json!({ "kind": "effect", "execution": { "outcome": outcome } });
        assert_eq!(
            accrual_of(&effect("applied")),
            amounts(&[("requests", "1")])
        );
        // Charging a refusal would make the gate a budget leak: an agent that is blocked a thousand
        // times would exhaust the organisation's cap without ever having done anything.
        for outcome in ["blocked", "denied", "failed", "attempted"] {
            assert!(
                accrual_of(&effect(outcome)).is_empty(),
                "{outcome} was charged as spend"
            );
        }
    }

    #[test]
    fn cognition_cost_accrues_money_and_the_dimensions_the_spec_shares() {
        let cognition = json!({
            "kind": "cognition",
            "cost": {
                "tokens-in": 18422,
                "tokens-out": 1200,
                "money-eur": "0.41",
                "wall-clock-ms": 9310
            }
        });
        let accrued = accrual_of(&cognition);
        assert_eq!(accrued.get("money-eur").map(String::as_str), Some("0.41"));
        assert_eq!(accrued.get("tokens-in").map(String::as_str), Some("18422"));
        assert_eq!(accrued.get("tokens-out").map(String::as_str), Some("1200"));
        // `wall-clock-ms` is not `wall-clock-seconds`. Converting would be inventing a normative
        // rule; the dimension simply does not accrue, and ADR-0015 records that as a stated gap.
        assert!(!accrued.contains_key("wall-clock-ms"));
        assert!(!accrued.contains_key("wall-clock-seconds"));
    }

    #[test]
    fn a_dimension_the_cap_does_not_name_is_unbounded() {
        let cap = json!({ "requests": 10 });
        assert!(would_exceed(&cap, &amounts(&[]), &amounts(&[("money-eur", "999")])).is_empty());
    }

    #[test]
    fn the_boundary_is_at_most_and_not_less_than() {
        let cap = json!({ "requests": 10 });
        // Nine spent plus one is ten, which is *within* a cap of ten.
        assert!(
            would_exceed(
                &cap,
                &amounts(&[("requests", "9")]),
                &amounts(&[("requests", "1")])
            )
            .is_empty()
        );
        // Ten spent plus one is eleven, which is not.
        assert_eq!(
            would_exceed(
                &cap,
                &amounts(&[("requests", "10")]),
                &amounts(&[("requests", "1")])
            ),
            vec!["requests".to_owned()]
        );
    }

    #[test]
    fn money_is_compared_where_binary64_would_get_it_wrong() {
        let cap = json!({ "money-eur": "9007199254740992" });
        assert_eq!(
            would_exceed(
                &cap,
                &amounts(&[("money-eur", "9007199254740992")]),
                &amounts(&[("money-eur", "1")])
            ),
            vec!["money-eur".to_owned()],
            "the sum is one over the cap and the same binary64 as the cap"
        );
    }

    #[test]
    fn a_cap_that_cannot_be_evaluated_is_not_headroom() {
        // Fail closed. A malformed cap that read as "no limit" would turn a typo in a mandate into
        // an unbounded budget, which is the direction this must never be wrong in.
        for cap in [
            json!({ "money-eur": "not-a-number" }),
            json!({ "money-eur": true }),
        ] {
            assert_eq!(
                would_exceed(&cap, &amounts(&[]), &amounts(&[("money-eur", "1")])),
                vec!["money-eur".to_owned()],
                "{cap} read as unbounded"
            );
        }
    }
}

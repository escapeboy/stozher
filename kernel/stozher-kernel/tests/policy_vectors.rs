//! `spec/vectors/policy-evaluation.json` — `spec/05 §3`, run against this implementation.
//!
//! # Why this file is here and not in `stozher-core`
//!
//! The corpus runner lives in `stozher-core`, because that is where the primitives are. Policy
//! evaluation is the kernel's, and the kernel depends on core rather than the other way round, so
//! the one vector file that exercises §05 §3 has to be run from this side. `stozher-core`'s runner
//! names the kind and does nothing with it; this asserts it did not thereby go unchecked.
//!
//! # What §05 §3 turned out to be
//!
//! Nothing in the corpus asked about the evaluation order until v0.9, and nothing in either test
//! suite exercised a non-empty `reclassify` array. In that silence the two implementations diverged:
//! this one scored the three dimensions unequally and supported `<prefix>.*` patterns, the gateway
//! scored nothing and supported no patterns at all. A policy reclassifying `github.*` was therefore
//! honoured here and ignored there — an effect applied in the world believing it was `read`, and a
//! kernel refusing the record of it. §05 §3.1 now states the rule; these vectors are how a third
//! implementation is asked the same questions.

use std::path::Path;

use serde_json::Value;
use stozher_core::signed::KeyId;
use stozher_kernel::policy::{ClassifyInput, Decision, Policy};

fn corpus() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/policy-evaluation.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading the corpus: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing the corpus: {e}"))
}

#[test]
fn every_policy_evaluation_vector_matches_this_implementation() {
    let corpus = corpus();
    let key = corpus["keys"][0]["key-id"]
        .as_str()
        .expect("the corpus names the policy key");
    let key = KeyId::parse(key).expect("a key identifier");

    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 14,
        "the corpus shrank to {} vectors; a question that stopped being asked is a question two \
         implementations can start disagreeing about again",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("?");
        let policy = match Policy::parse(&vector["policy"], &key) {
            Ok(policy) => policy,
            Err(e) => {
                failures.push(format!("{name}: the vector's policy does not parse: {e}"));
                continue;
            }
        };
        let request = &vector["request"];
        let class = policy.classify(&ClassifyInput {
            subject: request["subject"].as_str().unwrap_or_default(),
            action: request["action"].as_str().unwrap_or_default(),
            resource: request["resource"].as_str().unwrap_or_default(),
            manifest_class: request["manifest-class"].as_str(),
        });
        let expected_class = vector["expected"]["class"].as_str().unwrap_or_default();
        if class != expected_class {
            failures.push(format!("{name}: class {class}, the corpus says {expected_class}"));
            continue;
        }

        let decision = match policy.decision_for(&class) {
            Decision::Allow => "allow",
            Decision::Gate { .. } => "gate",
            Decision::Deny => "deny",
        };
        let expected_decision = vector["expected"]["decision"].as_str().unwrap_or_default();
        if decision != expected_decision {
            failures.push(format!(
                "{name}: decision {decision}, the corpus says {expected_decision}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} policy-evaluation vectors disagree with this implementation:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

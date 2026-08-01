//! The corpus files whose subject is the kernel's own logic, run against this implementation.
//!
//! # Why these are here and not in `stozher-core`
//!
//! The corpus runner lives in `stozher-core`, because that is where the primitives are. Policy
//! evaluation and manifest validation are the kernel's, and the kernel depends on core rather than
//! the other way round, so the files that exercise §05 §3 and §08 §1 have to be run from this side.
//! `stozher-core`'s runner names those kinds and does nothing with them; this asserts they did not
//! thereby go unchecked.
//!
//! `index.json` marks them `role: "kernel"`, which is the same statement made to a third
//! implementation: a harness that plays no kernel may decline them, and must say so.
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
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/policy-evaluation.json");
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
            failures.push(format!(
                "{name}: class {class}, the corpus says {expected_class}"
            ));
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

fn manifest_corpus() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/manifest.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading the corpus: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing the corpus: {e}"))
}

#[test]
fn every_manifest_vector_matches_this_implementation() {
    let corpus = manifest_corpus();
    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 17,
        "the corpus shrank to {} vectors; §08 §1 had none at all before v0.9 and every one of them \
         is a rule a third-party component has to satisfy before it can be registered",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("?");
        let expected_valid = vector["expected"]["valid"].as_bool().unwrap_or(false);
        let expected_error = vector["expected"]["error"].as_str();
        match stozher_kernel::manifest::Manifest::parse(&vector["manifest"]) {
            Ok(_) if expected_valid => {}
            Ok(_) => failures.push(format!(
                "{name}: accepted, the corpus says {expected_error:?}"
            )),
            Err(e) if !expected_valid && Some(e.code()) == expected_error => {}
            Err(e) if expected_valid => {
                failures.push(format!("{name}: refused {}: {e}", e.code()));
            }
            Err(e) => failures.push(format!(
                "{name}: refused {}, the corpus says {expected_error:?}",
                e.code()
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} manifest vectors disagree with this implementation:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

fn gate_arguments_corpus() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/gate-arguments.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading the corpus: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing the corpus: {e}"))
}

/// §06 §4.4 rules 3 and 4 — the predicate that decides whether an approver may be shown a call's
/// arguments at all.
///
/// The gateway holds the same predicate, because a component has to decide before it submits, and
/// this file is what keeps the two answering alike. The cap is the interesting half: it is stated in
/// bytes of the canonical form, and the two implementations count length in different units
/// natively, so `over-the-cap-by-multibyte` is the vector that fails on the side that counted wrong.
#[test]
fn every_gate_arguments_vector_matches_this_implementation() {
    let corpus = gate_arguments_corpus();
    assert_eq!(
        corpus["arguments-max-bytes"].as_u64(),
        Some(stozher_kernel::gatequeue::ARGUMENTS_MAX_BYTES as u64),
        "the corpus and this build disagree about the cap itself, so every size vector below is \
         asking a question neither of them settles"
    );
    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 11,
        "the corpus shrank to {} vectors",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("?");
        let args_hash = vector["args-hash"].as_str().unwrap_or_default();
        let expected = vector["expected"].as_str().unwrap_or_default();
        match stozher_kernel::gatequeue::check_arguments(&vector["arguments"], args_hash) {
            Ok(canonical) if expected == "accept" => {
                let bytes = u64::try_from(canonical.len()).unwrap_or(u64::MAX);
                if Some(bytes) != vector["canonical-bytes"].as_u64() {
                    failures.push(format!(
                        "{name}: {bytes} canonical bytes, the corpus says {}",
                        vector["canonical-bytes"]
                    ));
                }
            }
            Ok(_) => failures.push(format!("{name}: accepted, the corpus says {expected}")),
            Err(e) if e.code() == expected => {}
            Err(e) => failures.push(format!(
                "{name}: refused {}, the corpus says {expected}",
                e.code()
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} gate-arguments vectors disagree with this implementation:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

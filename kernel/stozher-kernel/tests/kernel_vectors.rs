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

fn root_change_corpus() -> Value {
    corpus_file("root-change.json")
}

fn corpus_file(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading the corpus: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing the corpus: {e}"))
}

/// §09 §4.2 — the predicate behind the row a console renders for one stream.
///
/// The row itself is this implementation's business; which of the three states it is in is not. The
/// state that did not exist until this file did is `refused`: the kernel knew *at the moment of the
/// refusals* that it was rejecting an emitter, and the surface that exists to answer "is anything
/// wrong with this stream" reported the same row it had reported the day before, and would keep
/// reporting until the quiet interval elapsed. Seven days, in the incident.
#[test]
fn every_stream_status_vector_matches_this_implementation() {
    use stozher_core::sync::stream_status;

    let corpus = corpus_file("stream-status.json");
    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 8,
        "the corpus shrank to {} vectors",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("?");
        let input = &vector["input"];
        let accepted = input["last-accepted-at"].as_str();
        let now = input["now"].as_str().expect("now");
        // The console computes the silence from the same two timestamps, through the same helper it
        // uses for every other age on the page; the corpus states the seconds so a harness whose
        // arithmetic differs fails here rather than in a row nobody reads.
        let silent = accepted.map(|at| seconds_between(at, now));
        let status = stream_status(
            accepted,
            input["last-refused-at"].as_str(),
            silent,
            input["quiet-after-seconds"].as_i64().unwrap_or(3600),
        );
        let expected = &vector["expected"];
        if expected["status"].as_str() != Some(status.as_str()) {
            failures.push(format!(
                "{name}: read as {}, the corpus says {}",
                status.as_str(),
                expected["status"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} stream-status vectors disagree with this implementation:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Whole seconds between two RFC 3339 UTC timestamps of §01 §2.3.
fn seconds_between(earlier: &str, later: &str) -> i64 {
    let parse = |stamp: &str| {
        let day: i64 = stamp[8..10].parse().unwrap_or(0);
        let hour: i64 = stamp[11..13].parse().unwrap_or(0);
        let minute: i64 = stamp[14..16].parse().unwrap_or(0);
        let second: i64 = stamp[17..19].parse().unwrap_or(0);
        ((day * 24 + hour) * 60 + minute) * 60 + second
    };
    parse(later) - parse(earlier)
}

/// §04 §7.2 — the operator act that un-wedges a refused stream, read out of its envelope.
///
/// Who may make it is not asked here: §05 §5.6 puts `kernel.resume_stream` among the actions no
/// policy may permit without an enrolled human root's signature, and `tests/def2_mandate_swap.rs`
/// drives that path end to end, including the negative. What this file binds is the half a third
/// implementation could get wrong silently — which position is being bridged, and by which hash.
#[test]
fn every_stream_recovery_vector_matches_this_implementation() {
    use stozher_core::chain::verify_chain;
    use stozher_kernel::ingest::stream_resume;

    let corpus = corpus_file("stream-recovery.json");
    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 7,
        "the corpus shrank to {} vectors",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    let mut chains_verified = 0usize;
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("?");
        let expected = &vector["expected"];
        let payloads: Vec<Value> = vector["payloads"].as_array().cloned().unwrap_or_default();
        match stream_resume(&vector["envelope"], &payloads) {
            Ok(_) if expected["valid"].as_bool() != Some(true) => failures.push(format!(
                "{name}: read as a resume, the corpus says {}",
                expected["error"]
            )),
            Ok(resume) => {
                if expected["stream"].as_str() != Some(resume.stream.as_str()) {
                    failures.push(format!("{name}: resumes {}", resume.stream));
                }
                if expected["resume-seq"].as_u64() != Some(resume.resume_seq) {
                    failures.push(format!("{name}: at seq {}", resume.resume_seq));
                }
                if expected["bridge-prev-hash"].as_str() != Some(resume.bridge_hash.as_str()) {
                    failures.push(format!("{name}: bridges {}", resume.bridge_hash));
                }
                // The emitter's own chain, continuing past a position that stays refused: seq is
                // not renumbered and the first `prev-hash` is the hash of the refused bytes.
                if let Some(records) = vector["chain"].as_array() {
                    let anchor = vector["expected-first-prev"].as_str();
                    match verify_chain(records, records[0]["stream"].as_str().unwrap_or(""), anchor)
                    {
                        Ok(result) => {
                            chains_verified += 1;
                            if expected["chain-head-hash"].as_str()
                                != Some(result.head_hash.as_str())
                            {
                                failures.push(format!("{name}: head {}", result.head_hash));
                            }
                            if expected["chain-anchored"].as_bool() != Some(result.anchored) {
                                failures.push(format!("{name}: anchored {}", result.anchored));
                            }
                        }
                        Err(e) => failures.push(format!(
                            "{name}: the post-recovery chain does not verify: {}",
                            e.code()
                        )),
                    }
                }
            }
            Err(e) if expected["error"].as_str() == Some(e.code()) => {}
            Err(e) => failures.push(format!(
                "{name}: refused {}, the corpus says {}",
                e.code(),
                expected["error"]
            )),
        }
    }
    assert!(
        chains_verified > 0,
        "no stream-recovery vector carried a post-recovery chain; the corpus lost the assertion \
         that a resumed stream still verifies"
    );
    assert!(
        failures.is_empty(),
        "{} stream-recovery vectors disagree with this implementation:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// §03 §6 — what a root change says, separated from who may make it.
///
/// The subject is the half worth stating cross-language. `roots` is `(key, subject)` pairs and the
/// subject is what §06 §5's self-approval prohibition compares — *a human holding a second key is
/// still the same human*. This implementation recorded `execution.target` there, which is a name no
/// human has, for as long as the path existed; nothing caught it because roots seeded from
/// configuration carry their real subjects and no vector asked. This is the asking.
#[test]
fn every_root_change_vector_matches_this_implementation() {
    use stozher_kernel::ingest::{RootChange, root_change};

    let corpus = root_change_corpus();
    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 7,
        "the corpus shrank to {} vectors",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("?");
        let expected = &vector["expected"];
        let payloads: Vec<Value> = vector["payloads"].as_array().cloned().unwrap_or_default();
        match root_change(&vector["envelope"], &payloads) {
            Ok(_) if expected["valid"].as_bool() != Some(true) => failures.push(format!(
                "{name}: read as a change, the corpus says {}",
                expected["error"]
            )),
            Ok(RootChange::Enrol { key, subject }) => {
                if expected["change"].as_str() != Some("enrol") {
                    failures.push(format!(
                        "{name}: read as an enrolment, the corpus says retire"
                    ));
                }
                if expected["key"].as_str() != Some(key.as_str()) {
                    failures.push(format!(
                        "{name}: enrolled {key}, the corpus says {}",
                        expected["key"]
                    ));
                }
                if expected["subject"].as_str() != Some(subject.as_str()) {
                    failures.push(format!(
                        "{name}: recorded {subject:?}, the corpus says {}",
                        expected["subject"]
                    ));
                }
            }
            Ok(RootChange::Retire { key }) => {
                if expected["change"].as_str() != Some("retire") {
                    failures.push(format!(
                        "{name}: read as a retirement, the corpus says enrol"
                    ));
                }
                if expected["key"].as_str() != Some(key.as_str()) {
                    failures.push(format!(
                        "{name}: retired {key}, the corpus says {}",
                        expected["key"]
                    ));
                }
            }
            Err(e) if expected["error"].as_str() == Some(e.code()) => {}
            Err(e) => failures.push(format!(
                "{name}: refused {}, the corpus says {}",
                e.code(),
                expected["error"]
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} root-change vectors disagree with this implementation:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

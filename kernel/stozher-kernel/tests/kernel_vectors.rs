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
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/root-change.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading the corpus: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing the corpus: {e}"))
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

fn gate_resubmission_corpus() -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/gate-resubmission.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading the corpus: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing the corpus: {e}"))
}

/// Whether this implementation reads `request` as describing `call`, having first agreed with the
/// corpus about the request's hash. `None` means it would not parse at all, which is a failure of a
/// different kind and is recorded as one.
fn identity(
    failures: &mut Vec<String>,
    checked: &mut usize,
    id: &str,
    request: &Value,
    expected_hash: &str,
    call: &Value,
    now: &str,
) -> Option<bool> {
    let at = request["requested-at"].as_str().unwrap_or(now);
    match stozher_kernel::gatequeue::validate(request, at) {
        Ok(parsed) => {
            *checked += 1;
            if parsed.request_hash != expected_hash {
                failures.push(format!(
                    "{id}: hashes to {}, the corpus says {expected_hash}",
                    parsed.request_hash
                ));
            }
            let field = |member: &str| call[member].as_str().unwrap_or_default();
            Some(
                parsed.subject == field("subject")
                    && parsed.subject_key == field("key")
                    && parsed.component == field("component")
                    && parsed.mandate_ref == field("mandate-ref")
                    && parsed.policy_version == field("policy-version")
                    && parsed.classification == field("classification")
                    && parsed.action == field("action")
                    && parsed.target == field("target")
                    && parsed.args_hash == field("args-hash"),
            )
        }
        Err(e) => {
            failures.push(format!("{id}: refused {}", e.code()));
            None
        }
    }
}

/// §06 §4.2 — what makes two submissions one call, asked of the kernel's own request identity.
///
/// The rule itself is a component's: it MUST resolve to a request it already holds rather than
/// build a second one, and this side cannot do it on the component's behalf. §4.3 rule 1 makes the
/// queue idempotent by `request-hash`, and §1.1 puts a fresh `nonce` inside the hashed object, so
/// two asks of one call arrive here as two genuinely different objects — collapsing them would be
/// this implementation deciding that an approval of one *is* an approval of the other.
///
/// What this side is asked is therefore the half it owns and the component depends on: that
/// `request-hash` is computed identically on both sides, that the columns the queue indexes are
/// exactly the nine fields the match is made on (`same-call` per row is the corpus saying which
/// rows describe the call, and this implementation has to reach the same verdict), and that a
/// request past its `not-after` is refused rather than served. A component that reused an expired
/// request would be handing its caller a `request-hash` this route no longer accepts.
#[test]
fn every_gate_resubmission_vector_matches_this_implementation() {
    let corpus = gate_resubmission_corpus();
    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        vectors.len() >= 12,
        "the corpus shrank to {} vectors",
        vectors.len()
    );

    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("?");
        let now = vector["now"].as_str().expect("now");
        let call = &vector["call"];

        let minted_hash = vector["minted"]["request-hash"]
            .as_str()
            .expect("minted hash");
        if identity(
            &mut failures,
            &mut checked,
            &format!("{name}/minted"),
            &vector["minted"]["request"],
            minted_hash,
            call,
            now,
        ) != Some(true)
        {
            failures.push(format!(
                "{name}/minted: the request the component built is not the call it describes"
            ));
        }

        for (index, row) in vector["held"].as_array().expect("held").iter().enumerate() {
            let id = format!("{name}/held[{index}]");
            let hash = row["request-hash"].as_str().expect("request-hash");
            let same = identity(
                &mut failures,
                &mut checked,
                &id,
                &row["request"],
                hash,
                call,
                now,
            );
            if same != Some(row["same-call"].as_bool().unwrap_or(false)) {
                failures.push(format!(
                    "{id}: this implementation reads same-call as {same:?}, the corpus says {}",
                    row["same-call"]
                ));
            }
            if hash == minted_hash {
                failures.push(format!(
                    "{id}: a re-ask shares its hash with a held request, which would leave `nonce` \
                     (§06 §1.1) doing nothing"
                ));
            }
            // The expiry half, taken from the route's own predicate rather than a string compare
            // written here: `gate-request-expired` is what a re-submission of a dead request meets.
            checked += 1;
            let answerable = stozher_kernel::gatequeue::validate(&row["request"], now).is_ok();
            if answerable != row["answerable-at-now"].as_bool().unwrap_or(false) {
                failures.push(format!(
                    "{id}: answerable at {now} is {answerable}, the corpus says {}",
                    row["answerable-at-now"]
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} gate-resubmission checks disagree with this implementation:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert!(
        checked >= 24,
        "only {checked} requests were parsed; the corpus stopped asking"
    );
}

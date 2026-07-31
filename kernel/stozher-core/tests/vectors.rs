//! The S0 gate: every vector in `spec/vectors/` must validate against this implementation.
//!
//! The harness is data-driven. It reads `spec/vectors/index.json` at test time and dispatches on
//! each file's `kind`, so adding a vector file of a known kind extends coverage with no code change
//! here. An **unknown** kind fails the run rather than being skipped — a silently skipped vector is
//! worse than an absent one.
//!
//! Expected values are read from the vector files and are never hardcoded here. The vectors are
//! produced by an independent implementation (`spec/vectors/generate_vectors.py`: hand-written JCS,
//! hand-written SLIP-0010, Ed25519 from libsodium), so agreement means two implementations agree —
//! not that this one is self-consistent.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use stozher_core::mandate::{MandateRequest, VerifyParams, verify_mandate_chain};
use stozher_core::signed::KeyId;
use stozher_core::{chain, crypto, envelope, gate, jcs, payload, signed};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn read_json(path: &Path) -> Value {
    let text =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

/// Accumulates every mismatch so one run reports all of them.
struct Report {
    checked: usize,
    failures: Vec<String>,
}

impl Report {
    fn new() -> Self {
        Self {
            checked: 0,
            failures: Vec::new(),
        }
    }

    fn check<T: PartialEq + std::fmt::Debug>(
        &mut self,
        id: &str,
        what: &str,
        actual: &T,
        expected: &T,
    ) {
        self.checked += 1;
        if actual != expected {
            self.failures.push(format!(
                "{id}: {what}\n     expected: {expected:?}\n     actual:   {actual:?}"
            ));
        }
    }

    fn fail(&mut self, id: &str, message: String) {
        self.checked += 1;
        self.failures.push(format!("{id}: {message}"));
    }
}

fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
    crypto::decode_hex::<N>(s).unwrap_or_else(|e| panic!("bad hex in vector: {e}"))
}

fn expected_error(vector: &Value) -> Option<&str> {
    vector
        .get("expected")
        .and_then(|e| e.get("error"))
        .and_then(Value::as_str)
}

fn key_ids(value: Option<&Value>) -> Vec<KeyId> {
    value
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(|s| KeyId::parse(s).expect("vector key id"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn every_vector_validates_against_the_reference_implementation() {
    let dir = vectors_dir();
    let index = read_json(&dir.join("index.json"));
    let files = index["files"]
        .as_array()
        .expect("index.files must be an array");
    assert!(!files.is_empty(), "index.json lists no vector files");

    let mut report = Report::new();
    let mut total_vectors = 0usize;

    for entry in files {
        let path = entry["path"].as_str().expect("files[].path");
        let declared_kind = entry["kind"].as_str().expect("files[].kind");
        let doc = read_json(&dir.join(path));
        let kind = doc["kind"].as_str().expect("kind");
        assert_eq!(
            kind, declared_kind,
            "{path}: index kind disagrees with the file's own kind"
        );

        let vectors = doc["vectors"].as_array().expect("vectors must be an array");
        assert_eq!(
            vectors.len() as u64,
            entry["count"].as_u64().expect("files[].count"),
            "{path}: index count disagrees with the file"
        );
        total_vectors += vectors.len();

        for vector in vectors {
            let id = format!("{path}/{}", vector["name"].as_str().unwrap_or("<unnamed>"));
            match kind {
                "jcs" => check_jcs(&mut report, &id, vector),
                "jcs-invalid" => check_jcs_invalid(&mut report, &id, vector),
                "sha256" => check_sha256(&mut report, &id, vector),
                "ed25519" => check_ed25519(&mut report, &id, vector),
                "slip10-ed25519" => check_slip10(&mut report, &id, vector),
                "object-hash" => check_object_hash(&mut report, &id, vector),
                "envelope" => check_envelope(&mut report, &id, vector),
                "envelope-shape" => check_envelope_shape(&mut report, &id, vector),
                "chain" => check_chain(&mut report, &id, vector),
                "mandate-chain" => check_mandate_chain(&mut report, &id, &doc, vector),
                "authorization" => check_authorization(&mut report, &id, vector),
                "payload-binding" => check_payload_binding(&mut report, &id, vector),
                "parity" => check_parity(&mut report, &id, vector),
                unknown => panic!(
                    "{path}: unsupported vector kind {unknown:?}. Vectors are never skipped: \
                     implement support or remove the file."
                ),
            }
        }
    }

    assert!(
        total_vectors > 0,
        "the vector suite is empty, which would make this gate meaningless"
    );

    if !report.failures.is_empty() {
        panic!(
            "{} of {} assertions failed across {} vectors:\n\n  {}\n",
            report.failures.len(),
            report.checked,
            total_vectors,
            report.failures.join("\n\n  ")
        );
    }

    println!(
        "vectors: {total_vectors} vectors, {} assertions, all matching",
        report.checked
    );
}

// ---------------------------------------------------------------------------

fn check_jcs(report: &mut Report, id: &str, vector: &Value) {
    let input = vector["input-json"].as_str().expect("input-json");
    match jcs::parse(input) {
        Ok(value) => match jcs::canonicalize(&value) {
            Ok(canonical) => {
                report.check(
                    id,
                    "canonical form",
                    &canonical.as_str(),
                    &vector["canonical"].as_str().expect("canonical"),
                );
                report.check(
                    id,
                    "canonical sha256",
                    &crypto::sha256_hex(canonical.as_bytes()).as_str(),
                    &vector["canonical-sha256"]
                        .as_str()
                        .expect("canonical-sha256"),
                );
            }
            Err(e) => report.fail(id, format!("canonicalization failed: {e}")),
        },
        Err(e) => report.fail(id, format!("parsing a valid vector failed: {e}")),
    }
}

fn check_jcs_invalid(report: &mut Report, id: &str, vector: &Value) {
    let input = vector["input-json"].as_str().expect("input-json");
    let expected = vector["error"].as_str().expect("error");
    match jcs::parse(input).and_then(|v| jcs::canonicalize(&v)) {
        Ok(out) => report.fail(id, format!("invalid input was accepted, producing {out:?}")),
        Err(e) => report.check(id, "error code", &e.code(), &expected),
    }
}

fn check_sha256(report: &mut Report, id: &str, vector: &Value) {
    let input = hex::decode(vector["input-hex"].as_str().expect("input-hex")).expect("hex");
    report.check(
        id,
        "sha256",
        &crypto::sha256_hex(&input).as_str(),
        &vector["sha256"].as_str().expect("sha256"),
    );
}

fn check_ed25519(report: &mut Report, id: &str, vector: &Value) {
    let public_key = hex_to_array::<32>(vector["public-key"].as_str().expect("public-key"));
    let message = hex::decode(vector["message-hex"].as_str().expect("message-hex")).expect("hex");
    let signature_hex = vector["signature"].as_str().expect("signature");

    if let Some(secret) = vector.get("secret-key").and_then(Value::as_str) {
        let secret_key = hex_to_array::<32>(secret);
        report.check(
            id,
            "derived public key",
            &hex::encode(crypto::public_key_of(&secret_key)).as_str(),
            &vector["public-key"].as_str().expect("public-key"),
        );
        report.check(
            id,
            "signature (Ed25519 is deterministic)",
            &hex::encode(crypto::sign(&secret_key, &message)).as_str(),
            &signature_hex,
        );
    }

    let signature = hex_to_array::<64>(signature_hex);
    report.check(
        id,
        "strict verification",
        &crypto::verify_strict(&public_key, &message, &signature),
        &vector["verifies"].as_bool().expect("verifies"),
    );
}

fn check_slip10(report: &mut Report, id: &str, vector: &Value) {
    let seed = hex::decode(vector["seed"].as_str().expect("seed")).expect("hex");
    let path = vector["path"].as_str().expect("path");
    match crypto::slip10::derive(&seed, path) {
        Ok(node) => {
            report.check(
                id,
                "chain code",
                &hex::encode(node.chain_code).as_str(),
                &vector["chain-code"].as_str().expect("chain-code"),
            );
            report.check(
                id,
                "private key",
                &hex::encode(node.private_key).as_str(),
                &vector["private-key"].as_str().expect("private-key"),
            );
            let public = crypto::public_key_of(&node.private_key);
            report.check(
                id,
                "public key",
                &hex::encode(public).as_str(),
                &vector["public-key"].as_str().expect("public-key"),
            );
            report.check(
                id,
                "key id",
                &KeyId::from_public_key(&public).as_str(),
                &vector["key-id"].as_str().expect("key-id"),
            );
        }
        Err(e) => report.fail(id, format!("derivation failed: {e}")),
    }
}

fn check_object_hash(report: &mut Report, id: &str, vector: &Value) {
    let object = &vector["object"];
    match jcs::canonicalize(object) {
        Ok(canonical) => report.check(
            id,
            "canonical form",
            &canonical.as_str(),
            &vector["expected-jcs"].as_str().expect("expected-jcs"),
        ),
        Err(e) => report.fail(id, format!("canonicalization failed: {e}")),
    }
    match signed::object_id(object) {
        Ok(hash) => report.check(
            id,
            "object hash",
            &hash.as_str(),
            &vector["expected-object-hash"]
                .as_str()
                .expect("expected-object-hash"),
        ),
        Err(e) => report.fail(id, format!("object hash failed: {e}")),
    }
    if let Some(expected) = vector.get("expected-signing-input").and_then(Value::as_str) {
        match signed::signing_input(object) {
            Ok(input) => {
                report.check(id, "signing input", &input.as_str(), &expected);
                report.check(
                    id,
                    "signing input sha256",
                    &crypto::sha256_hex(input.as_bytes()).as_str(),
                    &vector["expected-signing-input-sha256"]
                        .as_str()
                        .expect("sha256"),
                );
            }
            Err(e) => report.fail(id, format!("signing input failed: {e}")),
        }
    }
    if let Some(expected) = vector
        .get("expected-signature-valid")
        .and_then(Value::as_bool)
    {
        report.check(
            id,
            "signature validity",
            &signed::verify_signed_object(object).is_ok(),
            &expected,
        );
    }
}

fn check_envelope(report: &mut Report, id: &str, vector: &Value) {
    let env = &vector["envelope"];
    let expected = &vector["expected"];
    match signed::signing_input(env) {
        Ok(input) => report.check(
            id,
            "signing input sha256",
            &crypto::sha256_hex(input.as_bytes()).as_str(),
            &expected["signing-input-sha256"]
                .as_str()
                .expect("signing-input-sha256"),
        ),
        Err(e) => report.fail(id, format!("signing input failed: {e}")),
    }
    match signed::object_id(env) {
        Ok(hash) => report.check(
            id,
            "envelope hash",
            &hash.as_str(),
            &expected["envelope-hash"].as_str().expect("envelope-hash"),
        ),
        Err(e) => report.fail(id, format!("envelope hash failed: {e}")),
    }
    report.check(
        id,
        "signature validity",
        &signed::verify_signed_object(env).is_ok(),
        &expected["signature-valid"]
            .as_bool()
            .expect("signature-valid"),
    );
}

fn check_envelope_shape(report: &mut Report, id: &str, vector: &Value) {
    let result = envelope::validate(&vector["envelope"]);
    let expected_valid = vector["expected"]["valid"]
        .as_bool()
        .expect("expected.valid");
    report.check(id, "validity", &result.is_ok(), &expected_valid);
    match (&result, expected_error(vector)) {
        (Err(e), Some(expected)) => report.check(id, "error code", &e.code(), &expected),
        (Err(e), None) => report.fail(id, format!("rejected a valid envelope: {e}")),
        (Ok(()), Some(expected)) => report.fail(
            id,
            format!("accepted an envelope that must fail {expected}"),
        ),
        (Ok(()), None) => {}
    }
}

fn check_chain(report: &mut Report, id: &str, vector: &Value) {
    let envelopes: Vec<Value> = vector["envelopes"].as_array().expect("envelopes").clone();
    let stream = vector["stream"].as_str().expect("stream");
    let expected = &vector["expected"];
    let result = chain::verify_chain(&envelopes, stream, None);
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &expected["valid"].as_bool().expect("expected.valid"),
    );
    match result {
        Ok(ok) => {
            if let Some(head) = expected.get("head-hash").and_then(Value::as_str) {
                report.check(id, "head hash", &ok.head_hash.as_str(), &head);
            }
            if let Some(count) = expected.get("count").and_then(Value::as_u64) {
                report.check(id, "count", &(ok.count as u64), &count);
            }
            if let Some(anchored) = expected.get("anchored").and_then(Value::as_bool) {
                report.check(id, "anchored", &ok.anchored, &anchored);
            }
        }
        Err(e) => {
            if let Some(expected_code) = expected_error(vector) {
                report.check(id, "error code", &e.code(), &expected_code);
            }
            if let Some(seq) = expected.get("failed-at-seq").and_then(Value::as_u64) {
                report.check(id, "failed-at-seq", &e.seq(), &Some(seq));
            }
        }
    }
}

fn check_mandate_chain(report: &mut Report, id: &str, doc: &Value, vector: &Value) {
    let mandates = doc["mandates"].as_object().expect("mandates").clone();
    let roots = key_ids(doc.get("roots"));
    let revocations: Vec<Value> = vector["revocations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let subject_key =
        KeyId::parse(vector["subject-key"].as_str().expect("subject-key")).expect("key id");
    let request = MandateRequest::from_value(&vector["request"]).expect("request");
    let params = VerifyParams {
        roots: &roots,
        revocations: &revocations,
        at: vector["at"].as_str().expect("at"),
        subject_key: &subject_key,
        max_delegation_depth: u32::try_from(
            vector["max-delegation-depth"]
                .as_u64()
                .expect("max-delegation-depth"),
        )
        .expect("depth fits u32"),
    };

    let result = verify_mandate_chain(
        &mandates,
        vector["leaf-ref"].as_str().expect("leaf-ref"),
        &request,
        &params,
    );
    let expected = &vector["expected"];
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &expected["valid"].as_bool().expect("expected.valid"),
    );
    match result {
        Ok(ok) => {
            if let Some(root) = expected.get("human-root").and_then(Value::as_str) {
                report.check(id, "human root", &ok.human_root.as_str(), &root);
            }
            if let Some(key) = expected.get("root-key").and_then(Value::as_str) {
                report.check(id, "root key", &ok.root_key.as_str(), &key);
            }
            if let Some(depth) = expected.get("depth").and_then(Value::as_u64) {
                report.check(id, "depth", &u64::from(ok.depth), &depth);
            }
        }
        Err(e) => {
            if let Some(expected_code) = expected_error(vector) {
                report.check(id, "error code", &e.code(), &expected_code);
            }
        }
    }
}

fn check_authorization(report: &mut Report, id: &str, vector: &Value) {
    // A vector names approver *keys* and nothing about the humans behind them, so the subject is
    // unknown here rather than absent-by-oversight; `None` disables only the subject half of step
    // (4) and leaves every vector meaning what it meant before.
    let approvers: Vec<gate::Approver> = key_ids(vector.get("approvers"))
        .into_iter()
        .map(|key| gate::Approver { key, subject: None })
        .collect();
    let seen: HashSet<String> = vector["seen-request-hashes"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let requires_gate = vector["requires-gate"].as_bool().expect("requires-gate");
    let result = gate::verify_authorization(&vector["envelope"], requires_gate, &approvers, &seen);
    let expected = &vector["expected"];
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &expected["valid"].as_bool().expect("expected.valid"),
    );
    match result {
        Ok(ok) => {
            if let Some(hash) = expected.get("request-hash").and_then(Value::as_str) {
                report.check(
                    id,
                    "request hash",
                    &ok.as_ref().map(|a| a.request_hash.as_str()),
                    &Some(hash),
                );
            }
            if let Some(key) = expected.get("decided-by").and_then(Value::as_str) {
                report.check(
                    id,
                    "decided by",
                    &ok.as_ref().map(|a| a.decided_by.as_str()),
                    &Some(key),
                );
            }
        }
        Err(e) => {
            if let Some(expected_code) = expected_error(vector) {
                report.check(id, "error code", &e.code(), &expected_code);
            }
        }
    }
}

fn check_payload_binding(report: &mut Report, id: &str, vector: &Value) {
    let ingest = &vector["ingest"];
    let payloads: Vec<Value> = ingest["payloads"].as_array().cloned().unwrap_or_default();
    let result = payload::verify_ingest(&ingest["envelope"], &payloads);
    let expected = &vector["expected"];
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &expected["valid"].as_bool().expect("expected.valid"),
    );
    match &result {
        Ok(ok) => {
            if let Some(hash) = expected.get("envelope-hash").and_then(Value::as_str) {
                report.check(id, "envelope hash", &ok.envelope_hash.as_str(), &hash);
            }
            if let Some(decayed) = expected.get("decayed").and_then(Value::as_bool) {
                report.check(id, "decayed", &ok.decayed, &decayed);
            }
        }
        Err(e) => {
            if let Some(expected_code) = expected_error(vector) {
                report.check(id, "error code", &e.code(), &expected_code);
            }
        }
    }

    // Where a vector supplies a whole chain, verifying it with NO payloads must reproduce the same
    // head hash the chain vectors expect. This is the decay property, asserted rather than asserted
    // about.
    if let Some(envelopes) = vector.get("chain").and_then(Value::as_array) {
        let stream = envelopes[0]["stream"].as_str().expect("stream");
        match chain::verify_chain(envelopes, stream, None) {
            Ok(ok) => {
                if let Some(head) = expected.get("chain-head-hash").and_then(Value::as_str) {
                    report.check(
                        id,
                        "chain head hash with every payload erased",
                        &ok.head_hash.as_str(),
                        &head,
                    );
                }
                if let Some(valid) = expected.get("chain-valid").and_then(Value::as_bool) {
                    report.check(
                        id,
                        "chain validity with every payload erased",
                        &true,
                        &valid,
                    );
                }
            }
            Err(e) => report.fail(
                id,
                format!("chain verification without payloads failed: {e}"),
            ),
        }
    }
}

/// Cross-implementation parity: each vector reaches a branch on which two independent
/// implementations were observed to disagree.
///
/// Unlike every other kind, these vectors are not a second opinion on a branch both implementations
/// already agreed about — they exist *because* the implementations diverged, and the expectation
/// records what the specification mandates rather than what either one did. A parity vector that
/// passes on both sides is a divergence that has been closed.
///
/// Dispatch is on `algorithm` rather than the file's `kind`, because a divergence is a property of a
/// branch, not of an operation: closing them needs both `verify_authorization` and `verify_chain` in
/// the same file, against the same key material.
fn check_parity(report: &mut Report, id: &str, vector: &Value) {
    let input = &vector["input"];
    match vector["algorithm"].as_str().expect("algorithm") {
        "verify-authorization" => check_parity_authorization(report, id, input, &vector["expected"]),
        "verify-chain" => check_parity_chain(report, id, input, &vector["expected"]),
        other => report.fail(id, format!("unsupported parity algorithm {other:?}")),
    }
}

fn check_parity_authorization(report: &mut Report, id: &str, input: &Value, expected: &Value) {
    // `approvers` carries objects here, not the bare key strings the `authorization` kind uses:
    // §06 §5 states self-approval over the subject *as well as* the key, so a corpus that cannot
    // express "a second key belonging to the same person" cannot reach the branch that separates a
    // key-only check from a conforming one.
    let approvers: Vec<gate::Approver> = input["approvers"]
        .as_array()
        .expect("approvers")
        .iter()
        .map(|entry| gate::Approver {
            key: KeyId::parse(entry["key"].as_str().expect("approvers[].key")).expect("key id"),
            subject: entry
                .get("subject")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
        .collect();
    let seen: HashSet<String> = input["seen-request-hashes"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let requires_gate = input["requires-gate"].as_bool().expect("requires-gate");

    let result = gate::verify_authorization(&input["envelope"], requires_gate, &approvers, &seen);
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &expected["valid"].as_bool().expect("expected.valid"),
    );
    match result {
        Ok(ok) => {
            if let Some(hash) = expected.get("request-hash").and_then(Value::as_str) {
                report.check(
                    id,
                    "request hash",
                    &ok.as_ref().map(|a| a.request_hash.as_str()),
                    &Some(hash),
                );
            }
            if let Some(key) = expected.get("decided-by").and_then(Value::as_str) {
                report.check(
                    id,
                    "decided by",
                    &ok.as_ref().map(|a| a.decided_by.as_str()),
                    &Some(key),
                );
            }
            if let Some(single_use) = expected.get("single-use").and_then(Value::as_bool) {
                report.check(
                    id,
                    "single use",
                    &ok.as_ref().map(|a| a.single_use),
                    &Some(single_use),
                );
            }
        }
        Err(e) => {
            if let Some(expected_code) = parity_error(expected) {
                report.check(id, "error code", &e.code(), &expected_code);
            }
        }
    }
}

fn check_parity_chain(report: &mut Report, id: &str, input: &Value, expected: &Value) {
    let envelopes: Vec<Value> = input["envelopes"].as_array().expect("envelopes").clone();
    let stream = input["stream"].as_str().expect("stream");
    let anchor = input.get("expected-first-prev").and_then(Value::as_str);

    let result = chain::verify_chain(&envelopes, stream, anchor);
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &expected["valid"].as_bool().expect("expected.valid"),
    );
    match result {
        Ok(ok) => {
            if let Some(head) = expected.get("head-hash").and_then(Value::as_str) {
                report.check(id, "head hash", &ok.head_hash.as_str(), &head);
            }
        }
        Err(e) => {
            if let Some(expected_code) = parity_error(expected) {
                report.check(id, "error code", &e.code(), &expected_code);
            }
            if let Some(seq) = expected.get("failed-at-seq").and_then(Value::as_u64) {
                report.check(id, "failed-at-seq", &e.seq(), &Some(seq));
            }
        }
    }
}

/// A parity vector's `expected.error` is explicitly `null` on the accepting branches, so a present
/// member is not the same as an expected code.
fn parity_error(expected: &Value) -> Option<&str> {
    expected.get("error").and_then(Value::as_str)
}

/// The index must enumerate exactly the vector files present on disk.
#[test]
fn index_matches_the_directory() {
    let dir = vectors_dir();
    let index = read_json(&dir.join("index.json"));
    let listed: HashSet<String> = index["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|f| f["path"].as_str().expect("path").to_owned())
        .collect();

    let mut on_disk = HashSet::new();
    for entry in fs::read_dir(&dir).expect("read vectors dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".json") && name != "index.json" {
            on_disk.insert(name);
        }
    }

    let missing: Vec<&String> = on_disk.difference(&listed).collect();
    let phantom: Vec<&String> = listed.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "vector files on disk but absent from index.json: {missing:?}"
    );
    assert!(
        phantom.is_empty(),
        "index.json lists files that do not exist: {phantom:?}"
    );
}

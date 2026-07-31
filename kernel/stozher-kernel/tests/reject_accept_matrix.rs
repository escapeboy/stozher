//! **The S1 build-plan gate, half (a): the reject/accept matrix.**
//!
//! Two halves, one verdict:
//!
//! 1. **Vector replay.** Every vector in `spec/vectors/` whose kind bears on ingest is replayed
//!    through the kernel's own stage for that kind, asserting against the vector's *own* expected
//!    values. Nothing is hardcoded here — a disagreement means this implementation and the
//!    independent generator disagree, which is the only thing that makes agreement mean anything.
//!    An unrecognised kind **panics**; a silently skipped vector is worse than an absent one.
//!
//! 2. **Kernel rejection matrix.** Every rejection reason the kernel itself produces is provoked
//!    end-to-end through [`stozher_kernel::Ingest::submit`] — the real path, with a real policy, a
//!    real mandate chain and real signatures — and the reason code is asserted.
//!
//! Anti-vacuity guards, in the shape of S0's harness:
//!
//! * counts are asserted non-zero and against `index.json`;
//! * **every** code appearing as an `expected.error` anywhere in the vectors must be covered by the
//!   matrix, and the set of codes is read from the vectors rather than written down here — so a new
//!   vector for a new code fails this test until the matrix grows to meet it;
//! * every accept case asserts acceptance, so a kernel that refused everything would fail rather
//!   than pass trivially.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use stozher_core::mandate::{MandateRequest, VerifyParams, verify_mandate_chain};
use stozher_core::signed::KeyId;
use stozher_core::{chain, envelope, gate, jcs, payload};
use stozher_kernel::{Outcome, codes};
use stozher_testkit::{
    CORE_STREAM, EFFECT_STREAM, NOW, TestKey, World, mandate_object, manifest_object, merge,
    revise, tamper, without, world,
};

// ---------------------------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------------------------

/// Accumulates every row so one run reports all failures, not just the first.
struct Report {
    checked: usize,
    /// Codes proven end-to-end through `Ingest::submit`.
    rejections: BTreeSet<String>,
    /// Codes proven at stage level by replaying a vector.
    replayed: BTreeSet<String>,
    accepts: usize,
    failures: Vec<String>,
}

impl Report {
    fn new() -> Self {
        Self {
            checked: 0,
            rejections: BTreeSet::new(),
            replayed: BTreeSet::new(),
            accepts: 0,
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

    /// Record that a rejection reason was proven to reject **end-to-end through ingest**.
    fn rejected(&mut self, code: &str) {
        self.rejections.insert(code.to_owned());
    }

    /// Record that a vector proved a reason at stage level.
    fn replayed(&mut self, code: &str) {
        self.replayed.insert(code.to_owned());
    }
}

// ---------------------------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_reject_accept_matrix_is_green() {
    let mut report = Report::new();

    let vector_codes = replay_vectors(&mut report);
    kernel_rejections(&mut report).await;
    kernel_accepts(&mut report).await;

    // Every vector code must be replayed at stage level. This is mechanical: it holds unless a
    // vector file grows a kind the replay does not dispatch, which panics instead.
    let unreplayed: Vec<&String> = vector_codes.difference(&report.replayed).collect();
    assert!(
        unreplayed.is_empty(),
        "vector codes that were never replayed: {unreplayed:?}"
    );

    // The guard that matters: every vector code that a signed envelope can actually carry to ingest
    // must also be proven **end-to-end**, not merely at stage level. The exceptions are enumerated
    // and each one says why, so this cannot be satisfied by quietly widening the list.
    let mut missing_end_to_end: Vec<&String> = vector_codes
        .difference(&report.rejections)
        .filter(|code| !unreachable_end_to_end(code))
        .collect();
    missing_end_to_end.sort();
    assert!(
        missing_end_to_end.is_empty(),
        "these reasons are proven only at stage level, never through the real pipeline: \
         {missing_end_to_end:?}"
    );

    assert!(
        report.checked > 200,
        "only {} assertions ran; the matrix would be vacuous",
        report.checked
    );
    assert!(
        report.rejections.len() >= 80,
        "only {} distinct rejection reasons were proven; the spec defines far more",
        report.rejections.len()
    );
    assert!(
        report.accepts >= 10,
        "only {} accept cases ran; a kernel that refused everything would pass",
        report.accepts
    );

    if !report.failures.is_empty() {
        panic!(
            "{} of {} matrix assertions failed:\n\n  {}\n",
            report.failures.len(),
            report.checked,
            report.failures.join("\n\n  ")
        );
    }

    println!(
        "reject/accept matrix: {} assertions, {} distinct rejection reasons, {} accept cases",
        report.checked,
        report.rejections.len(),
        report.accepts
    );
}

/// Vector codes that cannot be provoked end-to-end through ingest, with the reason for each.
///
/// This list is the honest part of the coverage guard. Every entry is a code whose *only* reachable
/// proof is at stage level, and each is either proven against the store elsewhere or is structurally
/// unreachable through a single `POST /v1/ingest`.
fn unreachable_end_to_end(code: &str) -> bool {
    matches!(
        code,
        // `chain-stream-mismatch` is a property of verifying a *range*, not of appending one
        // envelope: `(stream, seq)` is the primary key, so a foreign envelope cannot be spliced into
        // a stream through ingest at all. Proven against the store in `tests/chain_10k.rs`.
        "chain-stream-mismatch" // §02 §9.1 lists these as structural codes reachable at ingest, and they are proven
                                // end-to-end below. Nothing else belongs here — if this list grows, the growth is a
                                // reviewed diff, not an accident.
    )
}

// ---------------------------------------------------------------------------------------------
// 1. vector replay
// ---------------------------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

/// Replay every ingest-relevant vector and return the set of codes they expect.
fn replay_vectors(report: &mut Report) -> BTreeSet<String> {
    let dir = vectors_dir();
    let index = read_json(&dir.join("index.json"));
    let files = index["files"].as_array().expect("index.files");
    assert!(!files.is_empty(), "index.json lists no vector files");

    let mut codes = BTreeSet::new();
    let mut replayed = 0usize;

    for entry in files {
        let path = entry["path"].as_str().expect("files[].path");
        let declared = entry["kind"].as_str().expect("files[].kind");
        // Kinds that test primitives rather than ingest behaviour are S0's gate, which still runs in
        // this same `cargo test`. Naming them explicitly is what keeps "not relevant here" from
        // becoming "silently skipped".
        if matches!(
            declared,
            "jcs"
                | "jcs-invalid"
                | "sha256"
                | "ed25519"
                | "slip10-ed25519"
                | "object-hash"
                | "envelope"
                // A pure comparison over two strings, with no envelope to submit. Its consequences
                // for ingest are reached through `mandate-chain`'s budget vectors, which this
                // dispatcher does replay.
                | "money-compare"
        ) {
            continue;
        }
        let doc = read_json(&dir.join(path));
        assert_eq!(
            doc["kind"].as_str(),
            Some(declared),
            "{path}: index kind disagrees with the file"
        );
        let vectors = doc["vectors"].as_array().expect("vectors");
        assert_eq!(
            vectors.len() as u64,
            entry["count"].as_u64().expect("files[].count"),
            "{path}: index count disagrees with the file"
        );

        for vector in vectors {
            let id = format!("{path}/{}", vector["name"].as_str().unwrap_or("<unnamed>"));
            if let Some(code) = vector["expected"]["error"].as_str() {
                codes.insert(code.to_owned());
            }
            match declared {
                "envelope-shape" => replay_shape(report, &id, vector),
                "mandate-chain" => replay_mandate(report, &id, &doc, vector),
                "authorization" => replay_authorization(report, &id, vector),
                "chain" => replay_chain(report, &id, vector),
                "payload-binding" => replay_payload(report, &id, vector),
                "parity" => replay_parity(report, &id, vector),
                unknown => panic!(
                    "{path}: unsupported vector kind {unknown:?}. Vectors are never skipped: \
                     implement support or remove the file."
                ),
            }
            replayed += 1;
        }
    }

    assert!(
        replayed >= 90,
        "only {replayed} vectors were replayed; the relevant kinds hold more"
    );
    println!(
        "vector replay: {replayed} vectors, {} distinct codes",
        codes.len()
    );
    codes
}

fn replay_shape(report: &mut Report, id: &str, vector: &Value) {
    // The kernel's schema stage is `envelope::validate` — the same call ingest makes at step (3).
    let result = envelope::validate(&vector["envelope"]);
    let expected_valid = vector["expected"]["valid"]
        .as_bool()
        .expect("expected.valid");
    report.check(id, "validity", &result.is_ok(), &expected_valid);
    match (&result, vector["expected"]["error"].as_str()) {
        (Err(e), Some(expected)) => {
            report.check(id, "reason code", &e.code(), &expected);
            report.replayed(expected);
        }
        (Err(e), None) => report.fail(id, format!("refused a valid envelope: {e}")),
        (Ok(()), Some(expected)) => {
            report.fail(
                id,
                format!("accepted an envelope that must fail {expected}"),
            );
        }
        (Ok(()), None) => {}
    }
}

fn replay_mandate(report: &mut Report, id: &str, doc: &Value, vector: &Value) {
    let mandates = doc["mandates"].as_object().expect("mandates").clone();
    let roots: Vec<KeyId> = doc["roots"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(|s| KeyId::parse(s).expect("root key id"))
                .collect()
        })
        .unwrap_or_default();
    let revocations: Vec<Value> = vector["revocations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let subject_key =
        KeyId::parse(vector["subject-key"].as_str().expect("subject-key")).expect("key");
    let request = MandateRequest::from_value(&vector["request"]).expect("request tuple");
    let result = verify_mandate_chain(
        &mandates,
        vector["leaf-ref"].as_str().expect("leaf-ref"),
        &request,
        &VerifyParams {
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
        },
    );
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &vector["expected"]["valid"]
            .as_bool()
            .expect("expected.valid"),
    );
    match (&result, vector["expected"]["error"].as_str()) {
        (Err(e), Some(expected)) => {
            report.check(id, "reason code", &e.code(), &expected);
            report.replayed(expected);
        }
        (Ok(ok), None) => {
            if let Some(root) = vector["expected"]["human-root"].as_str() {
                report.check(id, "human root", &ok.human_root.as_str(), &root);
            }
        }
        (Err(e), None) => report.fail(id, format!("refused a valid chain: {e}")),
        (Ok(_), Some(expected)) => {
            report.fail(id, format!("accepted a chain that must fail {expected}"));
        }
    }
}

fn replay_authorization(report: &mut Report, id: &str, vector: &Value) {
    // A vector names approver *keys* and says nothing about the humans behind them, so the subject
    // is genuinely unknown here rather than absent-by-oversight. `None` disables only the subject
    // half of step (4) and leaves every vector meaning exactly what it meant before.
    let approvers: Vec<gate::Approver> = vector["approvers"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(|s| gate::Approver {
                    key: KeyId::parse(s).expect("approver key id"),
                    subject: None,
                })
                .collect()
        })
        .unwrap_or_default();
    let seen: std::collections::HashSet<String> = vector["seen-request-hashes"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let result = gate::verify_authorization(
        &vector["envelope"],
        vector["requires-gate"].as_bool().expect("requires-gate"),
        &approvers,
        &seen,
    );
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &vector["expected"]["valid"]
            .as_bool()
            .expect("expected.valid"),
    );
    match (&result, vector["expected"]["error"].as_str()) {
        (Err(e), Some(expected)) => {
            report.check(id, "reason code", &e.code(), &expected);
            report.replayed(expected);
        }
        (Ok(ok), None) => {
            if let Some(hash) = vector["expected"]["request-hash"].as_str() {
                report.check(
                    id,
                    "request hash",
                    &ok.as_ref().map(|a| a.request_hash.as_str()),
                    &Some(hash),
                );
            }
        }
        (Err(e), None) => report.fail(id, format!("refused a valid authorization: {e}")),
        (Ok(_), Some(expected)) => {
            report.fail(
                id,
                format!("accepted an authorization that must fail {expected}"),
            );
        }
    }
}

/// Replay a cross-implementation parity vector.
///
/// It needs its own arm rather than reusing `replay_authorization`: a parity vector nests its input
/// under `input`, and its `approvers` are objects carrying a nullable `subject` where the
/// `authorization` kind has bare key strings. That difference is the point of the kind — §06 §5's
/// self-approval rule is stated over the subject as well as the key, and a corpus that cannot name a
/// subject cannot reach the branch where the two answers differ.
fn replay_parity(report: &mut Report, id: &str, vector: &Value) {
    let input = &vector["input"];
    let expected = &vector["expected"];
    let expected_error = expected["error"].as_str();

    let outcome = match vector["algorithm"].as_str().expect("algorithm") {
        "verify-authorization" => {
            let approvers: Vec<gate::Approver> = input["approvers"]
                .as_array()
                .expect("approvers")
                .iter()
                .map(|entry| gate::Approver {
                    key: KeyId::parse(entry["key"].as_str().expect("approvers[].key"))
                        .expect("approver key id"),
                    subject: entry
                        .get("subject")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
                .collect();
            let seen: std::collections::HashSet<String> = input["seen-request-hashes"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            gate::verify_authorization(
                &input["envelope"],
                input["requires-gate"].as_bool().expect("requires-gate"),
                &approvers,
                &seen,
            )
            .map(|_| ())
            .map_err(|e| (e.code().to_owned(), e.seq()))
        }
        "verify-chain" => {
            let envelopes: Vec<Value> = input["envelopes"].as_array().expect("envelopes").clone();
            chain::verify_chain(
                &envelopes,
                input["stream"].as_str().expect("stream"),
                input.get("expected-first-prev").and_then(Value::as_str),
            )
            .map(|_| ())
            .map_err(|e| (e.code().to_owned(), e.seq()))
        }
        other => {
            report.fail(id, format!("unsupported parity algorithm {other:?}"));
            return;
        }
    };

    report.check(
        id,
        "validity",
        &outcome.is_ok(),
        &expected["valid"].as_bool().expect("expected.valid"),
    );
    match (&outcome, expected_error) {
        (Err((code, seq)), Some(want)) => {
            report.check(id, "reason code", &code.as_str(), &want);
            if let Some(at) = expected["failed-at-seq"].as_u64() {
                report.check(id, "failed-at-seq", seq, &Some(at));
            }
            report.replayed(want);
        }
        (Err((code, _)), None) => report.fail(id, format!("refused a valid vector: {code}")),
        (Ok(()), Some(want)) => report.fail(id, format!("accepted a vector that must fail {want}")),
        (Ok(()), None) => {}
    }
}

fn replay_chain(report: &mut Report, id: &str, vector: &Value) {
    let envelopes: Vec<Value> = vector["envelopes"].as_array().expect("envelopes").clone();
    let stream = vector["stream"].as_str().expect("stream");
    let result = chain::verify_chain(&envelopes, stream, None);
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &vector["expected"]["valid"]
            .as_bool()
            .expect("expected.valid"),
    );
    match (&result, vector["expected"]["error"].as_str()) {
        (Err(e), Some(expected)) => {
            report.check(id, "reason code", &e.code(), &expected);
            if let Some(seq) = vector["expected"]["failed-at-seq"].as_u64() {
                report.check(id, "failed-at-seq", &e.seq(), &Some(seq));
            }
            report.replayed(expected);
        }
        (Ok(ok), None) => {
            if let Some(head) = vector["expected"]["head-hash"].as_str() {
                report.check(id, "head hash", &ok.head_hash.as_str(), &head);
            }
        }
        (Err(e), None) => report.fail(id, format!("refused a valid chain: {e}")),
        (Ok(_), Some(expected)) => {
            report.fail(id, format!("accepted a chain that must fail {expected}"));
        }
    }
}

fn replay_payload(report: &mut Report, id: &str, vector: &Value) {
    let ingest = &vector["ingest"];
    let payloads: Vec<Value> = ingest["payloads"].as_array().cloned().unwrap_or_default();
    let result = payload::verify_ingest(&ingest["envelope"], &payloads);
    report.check(
        id,
        "validity",
        &result.is_ok(),
        &vector["expected"]["valid"]
            .as_bool()
            .expect("expected.valid"),
    );
    match (&result, vector["expected"]["error"].as_str()) {
        (Err(e), Some(expected)) => {
            report.check(id, "reason code", &e.code(), &expected);
            report.replayed(expected);
        }
        (Ok(ok), None) => {
            if let Some(hash) = vector["expected"]["envelope-hash"].as_str() {
                report.check(id, "envelope hash", &ok.envelope_hash.as_str(), &hash);
            }
            if let Some(decayed) = vector["expected"]["decayed"].as_bool() {
                report.check(id, "decayed", &ok.decayed, &decayed);
            }
        }
        (Err(e), None) => report.fail(id, format!("refused a valid ingest record: {e}")),
        (Ok(_), Some(expected)) => {
            report.fail(
                id,
                format!("accepted an ingest record that must fail {expected}"),
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 2. kernel rejection matrix — every row goes through the real pipeline
// ---------------------------------------------------------------------------------------------

/// Submit and require a specific reason code, recording that the reason is covered.
async fn row(
    report: &mut Report,
    world: &World,
    id: &str,
    expected: &str,
    envelope: &Value,
    payloads: &[Value],
) {
    report.rejected(expected);
    match world.submit(envelope, payloads).await {
        Outcome::Rejected {
            reason,
            detail,
            record,
        } => {
            report.check(id, "reason code", &reason.as_str(), &expected);
            if record.is_none() {
                report.fail(id, "the rejection was not recorded".to_owned());
            }
            let _ = detail;
        }
        Outcome::Accepted(appended) => report.fail(
            id,
            format!(
                "expected {expected}, but the envelope was accepted as {}",
                appended.id
            ),
        ),
        Outcome::Unavailable(detail) => report.fail(id, format!("store unavailable: {detail}")),
    }
}

/// Submit raw bytes and require a specific reason code — for malformed requests that are not
/// envelopes at all.
async fn raw_row(report: &mut Report, world: &World, id: &str, expected: &str, body: &str) {
    report.rejected(expected);
    match world
        .ingest()
        .submit(body.as_bytes(), Some("agent:test-harness"))
        .await
    {
        Outcome::Rejected { reason, .. } => {
            report.check(id, "reason code", &reason.as_str(), &expected);
        }
        Outcome::Accepted(appended) => {
            report.fail(id, format!("expected {expected}, accepted {}", appended.id));
        }
        Outcome::Unavailable(detail) => report.fail(id, format!("store unavailable: {detail}")),
    }
}

async fn kernel_rejections(report: &mut Report) {
    let world = world().await;
    let valid = world.gated_effect("github.create_issue", json!({})).await;

    request_shape_rows(report, &world).await;
    signature_row(report, &world, &valid).await;
    schema_rows(report, &world, &valid).await;
    freshness_row(report, &world, &valid).await;
    payload_rows(report, &world, &valid).await;
    policy_rows(report, &world).await;
    mandate_grant_rows(report, &world).await;
    mandate_use_rows(report, &world).await;
    revocation_rows(report, &world).await;
    gate_rows(report, &world, &valid).await;
    chain_position_rows(report, &world, &valid).await;
    trigger_rows(report, &world).await;
    aggregate_rows(report, &world).await;
    checkpoint_rows(report, &world).await;
    manifest_rows(report, &world).await;
    retention_row(report, &world).await;
    replay_and_rewrite_rows(report).await;
}

/// The two refusals that need an already-accepted envelope to exist, so they get their own world.
async fn replay_and_rewrite_rows(report: &mut Report) {
    let world = stozher_testkit::world().await;

    // An ungated read at seq 0, then a *different* envelope for that same occupied position. It is
    // either a bug or an attempted rewrite, and both are audit-relevant (§04 §3).
    let read = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&read, &[]).await;
    let clash = revise(
        &read,
        json!({ "emitted-at": "2026-07-26T09:00:00.002Z" }),
        &world.agent,
    );
    row(
        report,
        &world,
        "chain/seq-duplicate",
        "chain-seq-duplicate",
        &clash,
        &[],
    )
    .await;

    // One approval, applied twice. §06 §3: the second envelope carrying the same `request-hash` is
    // refused. The approval is data that travels with the work — it is not a licence to repeat it.
    let gated = world.gated_effect("github.create_issue", json!({})).await;
    world.accept(&gated, &[]).await;
    let (next, prev) = world.head(EFFECT_STREAM).await;
    let again = revise(
        &gated,
        json!({ "seq": next, "prev-hash": prev.clone() }),
        &world.agent,
    );
    row(
        report,
        &world,
        "gate/authorization-replayed",
        "gate-authorization-replayed",
        &again,
        &[],
    )
    .await;

    // `prev-hash` must match the head. This needs a non-empty stream, so it lives here rather than
    // with the other chain rows — on an empty stream the schema stage refuses it as a bad genesis.
    let broken = world
        .effect(
            "github.get_file",
            "read",
            json!({ "seq": next, "prev-hash": "a".repeat(64) }),
        )
        .await;
    row(
        report,
        &world,
        "chain/prev-hash-mismatch",
        "chain-prev-hash-mismatch",
        &broken,
        &[],
    )
    .await;
    let _ = prev;
}

async fn request_shape_rows(report: &mut Report, world: &World) {
    raw_row(
        report,
        world,
        "request/not-json",
        "jcs-malformed-json",
        "{not json",
    )
    .await;
    raw_row(
        report,
        world,
        "request/duplicate-member",
        "jcs-duplicate-key",
        r#"{"envelope":{},"envelope":{}}"#,
    )
    .await;
    raw_row(
        report,
        world,
        "request/unknown-member",
        "schema-unknown-member",
        r#"{"envelope":{},"payloads":[],"trusted":true}"#,
    )
    .await;
    raw_row(
        report,
        world,
        "request/no-envelope",
        "schema-missing-member",
        r#"{"payloads":[]}"#,
    )
    .await;
    raw_row(
        report,
        world,
        "request/payloads-not-array",
        "schema-type-mismatch",
        r#"{"envelope":{},"payloads":{}}"#,
    )
    .await;
}

async fn signature_row(report: &mut Report, world: &World, valid: &Value) {
    // Mutated *after* signing, so the signature covers different bytes. §02 §9.2 puts this check
    // before the schema check, and this row is what proves the order holds.
    let tampered = tamper(valid, json!({ "policy-version": "2026.07.99" }));
    row(
        report,
        world,
        "signature/tampered-after-signing",
        "sig-invalid",
        &tampered,
        &[],
    )
    .await;
}

async fn schema_rows(report: &mut Report, world: &World, valid: &Value) {
    let signer = &world.agent;
    let cases: Vec<(&str, &str, Value)> = vec![
        (
            "v-unsupported",
            "envelope-version-unsupported",
            json!({ "v": "stozher/0.2" }),
        ),
        (
            "kind-unknown",
            "envelope-unknown-kind",
            json!({ "kind": "instruction" }),
        ),
        (
            "classification-unknown",
            "envelope-classification-unknown",
            json!({ "classification": "important" }),
        ),
        (
            "outcome-unknown",
            "envelope-outcome-unknown",
            json!({ "execution": { "outcome": "probably" } }),
        ),
        (
            "unknown-member",
            "schema-unknown-member",
            json!({ "approved": true }),
        ),
        (
            "time-inverted",
            "execution-time-inverted",
            json!({ "execution": { "started-at": "2026-07-26T09:00:05.000Z", "finished-at": "2026-07-26T09:00:01.000Z" } }),
        ),
        (
            "correlation-too-long",
            "correlation-ref-too-long",
            json!({ "correlation-ref": "x".repeat(513) }),
        ),
        (
            "args-hash-uppercase",
            "encoding-not-lowercase-hex",
            json!({ "execution": { "args-hash": "A".repeat(64) } }),
        ),
        (
            "bad-timestamp",
            "encoding-bad-timestamp",
            json!({ "emitted-at": "2026-07-26T09:00:00Z" }),
        ),
        (
            "stream-malformed",
            "stream-id-malformed",
            json!({ "stream": "gw dev/0001" }),
        ),
        (
            "genesis-prev-not-null",
            "chain-genesis-prev-not-null",
            json!({ "seq": 0, "prev-hash": "b".repeat(64) }),
        ),
        (
            "prev-hash-missing",
            "chain-prev-hash-missing",
            json!({ "seq": 3, "prev-hash": Value::Null }),
        ),
    ];
    for (name, code, overrides) in cases {
        let fixture = revise(valid, overrides, signer);
        row(
            report,
            world,
            &format!("schema/{name}"),
            code,
            &fixture,
            &[],
        )
        .await;
    }

    // Members missing rather than wrong.
    let stripped = without(valid, "policy-version", signer);
    row(
        report,
        world,
        "schema/missing-member",
        "schema-missing-member",
        &stripped,
        &[],
    )
    .await;

    // Numeric range and integrality live in the same stage.
    let out_of_range = revise(
        valid,
        json!({ "execution": { "args-hash": "c".repeat(64) }, "seq": 9_007_199_254_740_992u64 }),
        signer,
    );
    row(
        report,
        world,
        "schema/integer-out-of-range",
        "encoding-integer-out-of-range",
        &out_of_range,
        &[],
    )
    .await;
    let non_integer = revise(valid, json!({ "seq": 1.5 }), signer);
    row(
        report,
        world,
        "schema/non-integer-number",
        "encoding-non-integer-number",
        &non_integer,
        &[],
    )
    .await;

    // `identity.key` must equal `sig.key`: the envelope is signed by the subject it names.
    let mismatched = {
        let mut body = valid.as_object().expect("object").clone();
        body.remove("sig");
        let mut body = Value::Object(body);
        merge(
            &mut body,
            json!({ "identity": { "key": world.stranger.id.as_str() } }),
        );
        world.agent.sign(&body)
    };
    row(
        report,
        world,
        "schema/identity-key-sig-mismatch",
        "identity-key-sig-mismatch",
        &mismatched,
        &[],
    )
    .await;

    // Kind-specific member exclusions. Cognition has no field a prompt could live in, and a signal
    // has no field in which it could carry a mandate.
    let cognition = world
        .cognition(json!({ "evidence": {
        "schema": "x.v1", "media-type": "application/json",
        "payload-hash": "d".repeat(64), "retain-until": "2026-08-01T00:00:00.000Z"
    } }))
        .await;
    row(
        report,
        world,
        "schema/cognition-has-effect-fields",
        "cognition-envelope-has-effect-fields",
        &cognition,
        &[],
    )
    .await;
    let payload_body = json!({ "issue": 7 });
    let signal = world
        .signal(
            &payload_body,
            json!({ "mandate-ref": world.standing_mandate }),
        )
        .await;
    row(
        report,
        world,
        "schema/signal-has-effect-fields",
        "signal-envelope-has-effect-fields",
        &signal,
        &[],
    )
    .await;
}

async fn freshness_row(report: &mut Report, world: &World, valid: &Value) {
    // §09 §5: an emitter controls its own `emitted-at`, so the kernel bounds how far ahead it may be.
    // The vectors deliberately exclude anything relative to *now* and hand this case to S1.
    let future = revise(
        valid,
        json!({ "emitted-at": "2026-07-26T09:30:00.000Z" }),
        &world.agent,
    );
    row(
        report,
        world,
        "freshness/emitted-in-future",
        "envelope-emitted-in-future",
        &future,
        &[],
    )
    .await;
}

async fn payload_rows(report: &mut Report, world: &World, valid: &Value) {
    let body = json!({ "title": "a bug" });
    let hash = jcs::object_hash(&body).expect("payload hash");
    let with_evidence = revise(
        valid,
        json!({ "evidence": {
            "schema": "github.create_issue.v1",
            "media-type": "application/json",
            "payload-hash": hash,
            "retain-until": "2027-01-01T00:00:00.000Z"
        } }),
        &world.agent,
    );
    // A payload that does not hash to what it claims.
    let lying = json!({ "payload-hash": hash, "media-type": "application/json", "payload": { "title": "something else" } });
    row(
        report,
        world,
        "payload/hash-mismatch",
        "payload-hash-mismatch",
        &with_evidence,
        &[lying],
    )
    .await;
    // A payload the envelope does not commit to: the payload store is reachable only through an
    // envelope, so it cannot be used as unaudited storage (§04 §5.2).
    let unreferenced = json!({
        "payload-hash": jcs::object_hash(&json!({ "smuggled": true })).expect("hash"),
        "media-type": "application/json",
        "payload": { "smuggled": true }
    });
    row(
        report,
        world,
        "payload/not-referenced",
        "payload-not-referenced",
        &with_evidence,
        &[unreferenced],
    )
    .await;
}

async fn policy_rows(report: &mut Report, world: &World) {
    // A component may not apply a class weaker than the effective policy's (§08 §1.2).
    let weakened = world.effect("github.create_issue", "read", json!({})).await;
    row(
        report,
        world,
        "policy/component-override",
        "policy-component-override-attempt",
        &weakened,
        &[],
    )
    .await;

    // A policy document signed by a key that is not the enrolled policy key.
    let forged = world
        .stranger
        .sign(&stozher_kernel::policy::baseline_conservative(
            "2026.08.1",
            NOW,
            &world.root.subject,
        ));
    let (envelope, payloads) = world.policy_change(&forged).await;
    row(
        report,
        world,
        "policy/sig-invalid",
        "policy-sig-invalid",
        &envelope,
        &payloads,
    )
    .await;

    // The approval must bind the exact bytes of the policy that took effect (§05 §5.3).
    let good = world
        .policy_key
        .sign(&stozher_kernel::policy::baseline_conservative(
            "2026.08.2",
            NOW,
            &world.root.subject,
        ));
    let (envelope, _) = world.policy_change(&good).await;
    row(
        report,
        world,
        "policy/document-unbound",
        codes::POLICY_CHANGE_DOCUMENT_UNBOUND,
        &envelope,
        &[],
    )
    .await;

    // `execution.target` names the version the document declares, or the change is not that change.
    let (envelope, payloads) = world.policy_change(&good).await;
    let retargeted = revise(
        &envelope,
        json!({ "execution": { "target": "policy:something-else" } }),
        &world.agent,
    );
    row(
        report,
        world,
        "policy/target-mismatch",
        codes::POLICY_CHANGE_TARGET_MISMATCH,
        &retargeted,
        &payloads,
    )
    .await;

    // A fresh kernel with no policy refuses an ordinary effect outright.
    let empty = world_without_policy().await;
    let orphan = empty
        .effect(
            "github.get_file",
            "read",
            json!({ "mandate-ref": "a".repeat(64) }),
        )
        .await;
    row(
        report,
        &empty,
        "policy/not-published",
        "policy-not-published",
        &orphan,
        &[],
    )
    .await;

    // Documents the kernel refuses to enforce at all, checked at parse time.
    let mut gated_offline =
        stozher_kernel::policy::baseline_conservative("2026.08.3", NOW, &world.root.subject);
    gated_offline["offline"]["consequential"] = Value::from("allow");
    let signed_doc = world.policy_key.sign(&gated_offline);
    report.rejected(codes::POLICY_OFFLINE_ALLOWS_GATED);
    report.check(
        "policy/offline-allows-gated",
        "reason code",
        &stozher_kernel::policy::Policy::parse(&signed_doc, &world.policy_key.id)
            .expect_err("an offline-allowed gated class must be refused")
            .code(),
        &codes::POLICY_OFFLINE_ALLOWS_GATED,
    );

    let mut group_approver =
        stozher_kernel::policy::baseline_conservative("2026.08.4", NOW, "the-team");
    group_approver["gate-rules"][1]["approvers"] = json!(["the-team"]);
    let signed_doc = world.policy_key.sign(&group_approver);
    report.rejected("gate-approver-not-human");
    report.check(
        "policy/approver-not-human",
        "reason code",
        &stozher_kernel::policy::Policy::parse(&signed_doc, &world.policy_key.id)
            .expect_err("a group cannot be the signer of record")
            .code(),
        &"gate-approver-not-human",
    );
}

async fn mandate_grant_rows(report: &mut Report, world: &World) {
    let root = &world.root;
    let agent = &world.agent;
    let stranger = &world.stranger;

    // Each row is a mandate object that is wrong in exactly one way.
    let cases: Vec<(&str, &str, Value, Option<&TestKey>)> = vec![
        (
            "self-grant",
            "mandate-self-grant",
            json!({ "grantee": { "subject": root.subject, "key": root.id.as_str() } }),
            None,
        ),
        (
            "missing-expiry",
            "mandate-missing-expiry",
            json!({ "not-after": Value::Null }),
            None,
        ),
        (
            "window-inverted",
            "mandate-window-inverted",
            json!({ "not-after": "2026-07-01T00:00:00.000Z" }),
            None,
        ),
        (
            "standing-lifetime-exceeded",
            "mandate-standing-lifetime-exceeded",
            json!({ "not-after": "2027-07-26T00:00:00.000Z" }),
            None,
        ),
        (
            "root-has-parent",
            "mandate-root-has-parent",
            json!({ "parent": "a".repeat(64) }),
            None,
        ),
        (
            "root-grantor-not-human",
            "mandate-root-grantor-not-human",
            json!({ "grantor": { "role": "agent" } }),
            None,
        ),
        (
            "kind-unknown",
            "mandate-kind-unknown",
            json!({ "mandate-kind": "eternal" }),
            None,
        ),
        (
            "bad-scope-pattern",
            "scope-bad-pattern",
            json!({ "scope": { "actions": ["git*hub.*"] } }),
            None,
        ),
        (
            "class-not-a-class",
            "scope-bad-pattern",
            json!({ "scope": { "classes": ["important"] } }),
            None,
        ),
        (
            "delegated-without-parent",
            "mandate-delegated-without-parent",
            json!({ "mandate-kind": "delegated", "parent": Value::Null }),
            None,
        ),
        // Signed by someone other than the grantor it names.
        (
            "signer-not-grantor",
            "mandate-signer-not-grantor",
            json!({}),
            Some(stranger),
        ),
    ];
    for (index, (name, code, overrides, signer)) in cases.into_iter().enumerate() {
        let nonce = format!("{:032x}", 0x1000 + index);
        let object = mandate_object(root, agent, &nonce, overrides);
        let signed_object = signer.unwrap_or(root).sign(&object);
        let envelope = world
            .core_envelope("mandate", json!({ "mandate": signed_object }))
            .await;
        row(
            report,
            world,
            &format!("grant/{name}"),
            code,
            &envelope,
            &[],
        )
        .await;
    }

    // A root key must not also be an agent grantee (§03 §6).
    let object = mandate_object(
        root,
        &world.second_root,
        "00000000000000000000000000009001",
        json!({ "grantee": { "subject": "agent:impersonator", "key": world.second_root.id.as_str() } }),
    );
    let envelope = world
        .core_envelope("mandate", json!({ "mandate": root.sign(&object) }))
        .await;
    row(
        report,
        world,
        "grant/root-key-as-agent",
        "root-key-used-as-agent",
        &envelope,
        &[],
    )
    .await;

    // A root that is not enrolled cannot grant a root mandate.
    let unenrolled = TestKey::new(0x77, "human:nobody");
    let object = mandate_object(
        &unenrolled,
        agent,
        "00000000000000000000000000009002",
        json!({}),
    );
    let envelope = world
        .core_envelope("mandate", json!({ "mandate": unenrolled.sign(&object) }))
        .await;
    row(
        report,
        world,
        "grant/root-not-enrolled",
        "mandate-root-not-enrolled",
        &envelope,
        &[],
    )
    .await;

    // Delegated grants: every bound is locally checkable at grant time, before any effect exists.
    let parent = world.standing_mandate.clone();
    let delegated = |overrides: Value, nonce: &str| {
        let mut base = json!({
            "mandate-kind": "delegated",
            "parent": parent,
            "grantor": { "subject": agent.subject, "key": agent.id.as_str(), "role": "agent" },
            "grantee": { "subject": "agent:worker", "key": stranger.id.as_str() },
            "max-depth": 1,
            "not-before": NOW,
            "not-after": "2026-09-01T00:00:00.000Z",
            "scope": {
                "components": ["gateway"],
                "actions": ["github.create_issue"],
                "classes": ["consequential"],
                "resources": ["repo:acme/backend"]
            }
        });
        merge(&mut base, overrides);
        mandate_object(agent, stranger, nonce, base)
    };
    let delegated_cases: Vec<(&str, &str, Value)> = vec![
        (
            "grantor-not-agent",
            "mandate-delegated-grantor-not-agent",
            json!({ "grantor": { "role": "human" } }),
        ),
        (
            "delegation-not-held",
            "mandate-delegation-not-held",
            json!({ "grantor": { "subject": "agent:other", "key": stranger.id.as_str(), "role": "agent" },
                    "grantee": { "subject": "agent:worker", "key": world.second_root.id.as_str() } }),
        ),
        (
            "depth-exceeded",
            "mandate-delegation-depth-exceeded",
            json!({ "max-depth": 5 }),
        ),
        (
            "scope-widened",
            "mandate-scope-widened",
            json!({ "scope": { "actions": ["*"] } }),
        ),
        (
            "window-outside-parent",
            "mandate-window-outside-parent",
            json!({ "not-after": "2027-01-01T00:00:00.000Z" }),
        ),
        (
            "unresolved-parent",
            "mandate-unresolved",
            json!({ "parent": "f".repeat(64) }),
        ),
    ];
    for (index, (name, code, overrides)) in delegated_cases.into_iter().enumerate() {
        let nonce = format!("{:032x}", 0x2000 + index);
        let object = delegated(overrides, &nonce);
        let grantor = if name == "delegation-not-held" {
            stranger
        } else {
            agent
        };
        let envelope = world
            .core_envelope("mandate", json!({ "mandate": grantor.sign(&object) }))
            .await;
        row(
            report,
            world,
            &format!("grant/delegated-{name}"),
            code,
            &envelope,
            &[],
        )
        .await;
    }

    // A delegated budget may only narrow, in every dimension the parent constrains.
    let object = mandate_object(
        agent,
        stranger,
        "00000000000000000000000000009003",
        json!({
            "mandate-kind": "delegated",
            "parent": world.budgeted_mandate,
            "grantor": { "subject": agent.subject, "key": agent.id.as_str(), "role": "agent" },
            "grantee": { "subject": "agent:worker", "key": stranger.id.as_str() },
            "max-depth": 1,
            "not-before": NOW,
            "not-after": "2026-09-01T00:00:00.000Z",
            "budget": { "requests": 100 }
        }),
    );
    let envelope = world
        .core_envelope("mandate", json!({ "mandate": agent.sign(&object) }))
        .await;
    row(
        report,
        world,
        "grant/delegated-budget-exceeds-parent",
        "mandate-budget-exceeds-parent",
        &envelope,
        &[],
    )
    .await;
}

async fn mandate_use_rows(report: &mut Report, world: &World) {
    // The mandate is not transferable: only the grantee may sign under it.
    let borrowed = world
        .effect_as(&world.stranger, "github.get_file", "read", json!({}))
        .await;
    row(
        report,
        world,
        "use/grantee-key-mismatch",
        "mandate-grantee-key-mismatch",
        &borrowed,
        &[],
    )
    .await;

    // An unresolvable mandate reference.
    let orphan = world
        .effect(
            "github.get_file",
            "read",
            json!({ "mandate-ref": "e".repeat(64) }),
        )
        .await;
    row(
        report,
        world,
        "use/unresolved",
        "mandate-unresolved",
        &orphan,
        &[],
    )
    .await;

    // Outside the mandate's window, in both directions. `emitted-at` drives the evaluation instant.
    let expired = world
        .effect(
            "github.get_file",
            "read",
            json!({ "mandate-ref": world.narrow_mandate }),
        )
        .await;
    let expired = revise(
        &expired,
        json!({ "emitted-at": "2026-07-26T08:59:00.000Z" }),
        &world.agent,
    );
    row(
        report,
        world,
        "use/not-yet-valid",
        "mandate-not-yet-valid",
        &expired,
        &[],
    )
    .await;

    // Scope: the narrow mandate covers `github.get_file` only.
    let outside = world
        .effect(
            "slack.post_message",
            "consequential",
            json!({ "mandate-ref": world.narrow_mandate }),
        )
        .await;
    row(
        report,
        world,
        "use/scope-not-permitted",
        "mandate-scope-not-permitted",
        &outside,
        &[],
    )
    .await;

    // A revoked mandate is invalid for every effect emitted at or after the revocation instant.
    let revoked_world = world_with_revocation().await;
    let after = revoked_world
        .effect(
            "github.get_file",
            "read",
            json!({ "mandate-ref": revoked_world.narrow_mandate }),
        )
        .await;
    row(
        report,
        &revoked_world,
        "use/revoked",
        "mandate-revoked",
        &after,
        &[],
    )
    .await;

    // An expired mandate: the same narrow grant, used after its `not-after`.
    let late_world = stozher_testkit::world().await;
    late_world.clock.advance_seconds(60 * 60 * 24 * 400);
    let late = late_world
        .effect(
            "github.get_file",
            "read",
            json!({ "mandate-ref": late_world.narrow_mandate }),
        )
        .await;
    row(
        report,
        &late_world,
        "use/expired",
        "mandate-expired",
        &late,
        &[],
    )
    .await;
}

async fn revocation_rows(report: &mut Report, world: &World) {
    // Only the grantor, an ancestor's grantor, or an enrolled root may revoke.
    let unauthorized = world
        .revocation(
            &world.stranger,
            &world.narrow_mandate,
            "2026-07-26T10:00:00.000Z",
        )
        .await;
    row(
        report,
        world,
        "revocation/not-authorized",
        "revocation-not-authorized",
        &unauthorized,
        &[],
    )
    .await;

    // Backdating a revocation to erase a window of authority is a rejection, not a workflow.
    let backdated = world
        .revocation(
            &world.root,
            &world.narrow_mandate,
            "2026-07-01T00:00:00.000Z",
        )
        .await;
    row(
        report,
        world,
        "revocation/before-issue",
        "revocation-before-issue",
        &backdated,
        &[],
    )
    .await;
}

async fn gate_rows(report: &mut Report, world: &World, valid: &Value) {
    let signer = &world.agent;

    // (1) the ambient-flag bypass: a gated action with no approval at all.
    let bare = without(valid, "authorization", signer);
    row(
        report,
        world,
        "gate/authorization-missing",
        "gate-authorization-missing",
        &bare,
        &[],
    )
    .await;

    // (2) a real signature paired with a rewritten request body.
    let rewritten = revise(
        valid,
        json!({ "authorization": { "request": { "target": "repo:acme/other" } } }),
        signer,
    );
    row(
        report,
        world,
        "gate/request-hash-mismatch",
        "gate-authorization-request-hash-mismatch",
        &rewritten,
        &[],
    )
    .await;

    // (3) a forged or corrupted approval.
    let forged = revise(
        valid,
        json!({ "authorization": { "decision": { "sig": { "value": "0".repeat(128) } } } }),
        signer,
    );
    row(
        report,
        world,
        "gate/decision-sig-invalid",
        "gate-decision-sig-invalid",
        &forged,
        &[],
    )
    .await;

    // (4) nobody approves their own action.
    let self_approved = world
        .gated_effect_approved_by(&world.agent, "github.create_issue")
        .await;
    row(
        report,
        world,
        "gate/self-approval",
        "gate-self-approval",
        &self_approved,
        &[],
    )
    .await;

    // (5) an approver the policy does not name for this scope.
    let wrong_approver = world
        .gated_effect_approved_by(&world.second_root, "github.create_issue")
        .await;
    row(
        report,
        world,
        "gate/approver-not-permitted",
        "gate-approver-not-permitted",
        &wrong_approver,
        &[],
    )
    .await;

    // (6) a decision value outside the closed vocabulary read as permission.
    let unknown_verdict = world.gated_effect_with_verdict("maybe", None).await;
    row(
        report,
        world,
        "gate/decision-unknown",
        "gate-decision-unknown",
        &unknown_verdict,
        &[],
    )
    .await;

    // (7) a denial recorded without the reason the agent and the audit are owed.
    let silent_denial = world.gated_effect_with_verdict("deny", None).await;
    row(
        report,
        world,
        "gate/denial-without-reason",
        "gate-denial-without-reason",
        &silent_denial,
        &[],
    )
    .await;

    // …and a denial carried by an envelope that claims the effect was applied anyway.
    let denied_but_applied = world
        .gated_effect_with_verdict("deny", Some("we do not file public issues"))
        .await;
    row(
        report,
        world,
        "gate/denied",
        "gate-denied",
        &denied_but_applied,
        &[],
    )
    .await;

    // (8) approving a request that had already expired in the queue.
    let stale_request = revise(
        valid,
        json!({ "authorization": { "decision": { "decided-at": "2026-07-26T09:00:00.000Z" },
                                   "request": { "not-after": "2026-07-26T08:00:00.000Z" } } }),
        signer,
    );
    // Rewriting the request changes its hash, so the fixture re-derives the decision over it.
    let stale_request = world.reseal_authorization(&stale_request);
    row(
        report,
        world,
        "gate/request-expired",
        "gate-request-expired",
        &stale_request,
        &[],
    )
    .await;

    // (9) using an approval long after it was granted.
    let expired_approval = revise(
        valid,
        json!({ "authorization": { "decision": { "not-after": "2026-07-26T09:00:00.000Z" } } }),
        signer,
    );
    let expired_approval = world.reseal_authorization(&expired_approval);
    let expired_approval = revise(
        &expired_approval,
        json!({ "emitted-at": "2026-07-26T09:00:00.001Z" }),
        signer,
    );
    row(
        report,
        world,
        "gate/approval-expired",
        "gate-approval-expired",
        &expired_approval,
        &[],
    )
    .await;

    // (10) carrying a valid approval for action A while performing action B.
    let switched = revise(
        valid,
        json!({ "execution": { "target": "repo:acme/production" } }),
        signer,
    );
    row(
        report,
        world,
        "gate/action-mismatch",
        "gate-authorization-action-mismatch",
        &switched,
        &[],
    )
    .await;
}

async fn chain_position_rows(report: &mut Report, world: &World, valid: &Value) {
    let signer = &world.agent;
    let (next, prev) = world.head(EFFECT_STREAM).await;

    // An emitter must not be able to reserve future positions.
    let gap = revise(
        valid,
        json!({ "seq": next + 5, "prev-hash": "a".repeat(64) }),
        signer,
    );
    row(report, world, "chain/seq-gap", "chain-seq-gap", &gap, &[]).await;
    let _ = prev;

    // A stream never mixes effects with inbound signals (§07 §2.5). A stream's kind is set by its
    // first accepted writer, so this needs a stream that already carries effects — in its own world,
    // because establishing one would move the head under every other fixture here.
    let established = stozher_testkit::world().await;
    let effect = established
        .effect("github.get_file", "read", json!({}))
        .await;
    established.accept(&effect, &[]).await;
    let mixed = established
        .signal(&json!({ "issue": 1 }), json!({ "stream": EFFECT_STREAM }))
        .await;
    row(
        report,
        &established,
        "chain/stream-kind-mixed",
        "stream-kind-mixed",
        &mixed,
        &[],
    )
    .await;
}

async fn trigger_rows(report: &mut Report, world: &World) {
    // The authority for a triggered action is the same mandate the effect is judged against.
    let mismatched = world
        .effect(
            "github.create_issue",
            "consequential",
            json!({ "trigger": { "signal-ref": "b".repeat(64), "standing-mandate-ref": "c".repeat(64) } }),
        )
        .await;
    row(
        report,
        world,
        "trigger/mandate-mismatch",
        "trigger-mandate-mismatch",
        &mismatched,
        &[],
    )
    .await;

    // `signal-ref` must resolve to an appended signal envelope.
    let unresolved = world
        .effect(
            "github.create_issue",
            "consequential",
            json!({ "trigger": { "signal-ref": "b".repeat(64), "standing-mandate-ref": world.standing_mandate } }),
        )
        .await;
    row(
        report,
        world,
        "trigger/signal-unresolved",
        "trigger-signal-unresolved",
        &unresolved,
        &[],
    )
    .await;

    // An interactive mandate cannot authorize a triggered action: by definition nobody was watching.
    let triggered_world = world_with_signal().await;
    let interactive = triggered_world
        .effect(
            "kernel.publish_policy",
            "consequential",
            json!({
                "identity": { "component": "kernel" },
                "mandate-ref": triggered_world.interactive_mandate,
                "trigger": {
                    "signal-ref": triggered_world.signal_id,
                    "standing-mandate-ref": triggered_world.interactive_mandate
                }
            }),
        )
        .await;
    row(
        report,
        &triggered_world,
        "trigger/mandate-not-standing",
        "trigger-mandate-not-standing",
        &interactive,
        &[],
    )
    .await;
}

async fn aggregate_rows(report: &mut Report, world: &World) {
    let inverted = world
        .aggregate(json!({ "window": { "from": "2026-07-26T09:00:00.000Z", "to": "2026-07-26T08:55:00.000Z" } }))
        .await;
    row(
        report,
        world,
        "aggregate/window-inverted",
        codes::AGGREGATE_WINDOW_INVERTED,
        &inverted,
        &[],
    )
    .await;

    // "An aggregate that is still open is an effect that is not yet in the audit" (§02 §7.5).
    let too_long = world
        .aggregate(json!({ "window": { "from": "2026-07-26T08:00:00.000Z", "to": "2026-07-26T09:00:00.000Z" } }))
        .await;
    row(
        report,
        world,
        "aggregate/window-too-long",
        codes::AGGREGATE_WINDOW_TOO_LONG,
        &too_long,
        &[],
    )
    .await;

    // Only class `read` may be aggregated; attempts must stay itemized.
    let wrong_class = world
        .aggregate(json!({ "classification": "consequential" }))
        .await;
    row(
        report,
        world,
        "aggregate/class-not-read",
        "aggregate-class-not-read",
        &wrong_class,
        &[],
    )
    .await;
    let bad_arithmetic = world.aggregate(json!({ "counts": { "total": 99 } })).await;
    row(
        report,
        world,
        "aggregate/count-mismatch",
        "aggregate-count-mismatch",
        &bad_arithmetic,
        &[],
    )
    .await;
    let no_samples = world.aggregate(json!({ "sample-hashes": [] })).await;
    row(
        report,
        world,
        "aggregate/sample-bounds",
        "aggregate-sample-bounds",
        &no_samples,
        &[],
    )
    .await;
}

async fn checkpoint_rows(report: &mut Report, world: &World) {
    // A checkpoint signed by any other key is not a checkpoint (§04 §4.1).
    let foreign = world
        .checkpoint(&world.agent, CORE_STREAM, 0, 0, json!({}))
        .await;
    row(
        report,
        world,
        "checkpoint/signer-not-kernel",
        "checkpoint-signer-not-kernel",
        &foreign,
        &[],
    )
    .await;

    let kernel_signed =
        |overrides: Value, to: u64| world.kernel_checkpoint(CORE_STREAM, 0, to, overrides);
    let miscounted = kernel_signed(json!({ "checkpoint": { "count": 99 } }), 0).await;
    row(
        report,
        world,
        "checkpoint/count-mismatch",
        "checkpoint-count-mismatch",
        &miscounted,
        &[],
    )
    .await;
    let wrong_head =
        kernel_signed(json!({ "checkpoint": { "head-hash": "a".repeat(64) } }), 0).await;
    row(
        report,
        world,
        "checkpoint/head-mismatch",
        "checkpoint-head-mismatch",
        &wrong_head,
        &[],
    )
    .await;
    let unknown_stream = world
        .kernel_checkpoint(
            "gw:nowhere:0001",
            0,
            0,
            json!({ "checkpoint": { "head-hash": "a".repeat(64) } }),
        )
        .await;
    row(
        report,
        world,
        "checkpoint/stream-unknown",
        codes::CHECKPOINT_STREAM_UNKNOWN,
        &unknown_stream,
        &[],
    )
    .await;
    // Checkpoints of a stream are non-overlapping and contiguous (§04 §4.4): with none recorded yet,
    // a range that does not start at 0 leaves a hole no later checkpoint can fill.
    let discontinuous = world.kernel_checkpoint(CORE_STREAM, 3, 3, json!({})).await;
    row(
        report,
        world,
        "checkpoint/range-discontinuous",
        "checkpoint-range-discontinuous",
        &discontinuous,
        &[],
    )
    .await;
}

async fn manifest_rows(report: &mut Report, world: &World) {
    let component = &world.component;

    // Registration-time manifest validation, checked through the real registration envelope.
    let cases: Vec<(&str, &str, Value)> = vec![
        (
            "action-namespace",
            "manifest-action-namespace",
            json!({ "actions": [ { "action": "elsewhere.do_it", "class": "read",
                                   "evidence-schema": "github.get_file.v1",
                                   "aggregate": { "sampling": "first", "max-samples": 4 },
                                   "idempotent": true, "target-kind": "repo" } ] }),
        ),
        (
            "evidence-schema-missing",
            "manifest-evidence-schema-missing",
            json!({ "actions": [ { "action": "github.get_file", "class": "read",
                                   "evidence-schema": "github.undeclared.v1",
                                   "aggregate": { "sampling": "first", "max-samples": 4 },
                                   "idempotent": true, "target-kind": "repo" } ] }),
        ),
        (
            "prohibited-degrade",
            "manifest-prohibited-degrade",
            json!({ "actions": [ { "action": "github.delete_repo", "class": "prohibited",
                                   "evidence-schema": "github.create_issue.v1",
                                   "idempotent": false, "target-kind": "repo",
                                   "degrade": { "form": "archive" } } ] }),
        ),
        (
            "malformed",
            codes::MANIFEST_MALFORMED,
            json!({ "subject-class": "wizard" }),
        ),
    ];
    for (name, code, overrides) in cases {
        let manifest = component.sign(&manifest_object("github", "1.0.0", overrides));
        let (envelope, payloads) = world.register_component(&manifest, true).await;
        row(
            report,
            world,
            &format!("manifest/{name}"),
            code,
            &envelope,
            &payloads,
        )
        .await;
    }

    // No green conformance run, no registration (§08 §3.3).
    let manifest = component.sign(&manifest_object("github", "1.0.0", json!({})));
    let (envelope, payloads) = world.register_component(&manifest, false).await;
    row(
        report,
        world,
        "manifest/conformance-not-green",
        "manifest-conformance-not-green",
        &envelope,
        &payloads,
    )
    .await;

    // A registered world, to exercise the conflict and durable-object rules.
    let registered = world_with_manifest().await;
    let impostor = registered
        .stranger
        .sign(&manifest_object("github", "2.0.0", json!({})));
    let (envelope, payloads) = registered.register_component(&impostor, true).await;
    row(
        report,
        &registered,
        "manifest/name-key-conflict",
        "manifest-name-key-conflict",
        &envelope,
        &payloads,
    )
    .await;

    let same_version = registered
        .component
        .sign(&manifest_object("github", "1.0.0", json!({})));
    let (envelope, payloads) = registered.register_component(&same_version, true).await;
    row(
        report,
        &registered,
        "manifest/version-retained",
        "manifest-version-retained",
        &envelope,
        &payloads,
    )
    .await;

    // A `["human"]`-only transition refused from an agent key, regardless of the agent's mandate.
    let human_only = registered
        .gated_effect(
            "github.create_issue",
            json!({
                "identity": { "component": "github" },
                "commitment-ref": { "object-type": "github.ticket", "object-id": "t-1", "transition": "approved" }
            }),
        )
        .await;
    row(
        report,
        &registered,
        "durable/transition-not-permitted",
        "durable-transition-not-permitted",
        &human_only,
        &[],
    )
    .await;

    // A transition whose `from` does not contain the object's current folded state.
    let illegal = registered
        .gated_effect(
            "github.create_issue",
            json!({
                "identity": { "component": "github" },
                "commitment-ref": { "object-type": "github.ticket", "object-id": "t-2", "transition": "closed" }
            }),
        )
        .await;
    row(
        report,
        &registered,
        "durable/transition-illegal",
        "durable-transition-illegal",
        &illegal,
        &[],
    )
    .await;
}

async fn retention_row(report: &mut Report, world: &World) {
    // An emitter cannot buy itself a longer retention than the org allows (§02 §5).
    let body = json!({ "title": "a bug" });
    let hash = jcs::object_hash(&body).expect("payload hash");
    let greedy = world
        .gated_effect(
            "github.create_issue",
            json!({ "evidence": {
                "schema": "github.create_issue.v1",
                "media-type": "application/json",
                "payload-hash": hash,
                "retain-until": "2099-01-01T00:00:00.000Z"
            } }),
        )
        .await;
    row(
        report,
        world,
        "retention/too-long",
        "evidence-retention-too-long",
        &greedy,
        &[json!({ "payload-hash": hash, "media-type": "application/json", "payload": body })],
    )
    .await;
}

// ---------------------------------------------------------------------------------------------
// 3. accept cases — a kernel that refused everything must fail this gate too
// ---------------------------------------------------------------------------------------------

async fn kernel_accepts(report: &mut Report) {
    let world = world().await;
    let mut accepted = 0usize;

    // A `read` effect under an allow rule: no approval required, none carried.
    let read = world.effect("github.get_file", "read", json!({})).await;
    let outcome = world.submit(&read, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/read-effect", outcome));

    // Idempotency by `id()`: the same bytes again, with no second row and no replay complaint.
    let outcome = world.submit(&read, &[]).await;
    match outcome {
        Outcome::Accepted(appended) => {
            report.check(
                "accept/idempotent",
                "idempotent",
                &appended.idempotent,
                &true,
            );
            accepted += 1;
        }
        other => report.fail(
            "accept/idempotent",
            format!("re-submission was not idempotent: {other:?}"),
        ),
    }

    // A `consequential` effect with a named human's signature over the exact action.
    let gated = world.gated_effect("github.create_issue", json!({})).await;
    let outcome = world.submit(&gated, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/gated-effect", outcome));

    // A signed denial: §06 §4.5 REQUIRES this envelope to exist, so ingest must accept it.
    let denied = world.denied_effect("github.create_issue").await;
    let outcome = world.submit(&denied, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/signed-denial", outcome));

    // A gated action that timed out: blocked, with no approval to carry.
    let blocked = world
        .effect(
            "github.create_issue",
            "consequential",
            json!({ "execution": { "outcome": "blocked" } }),
        )
        .await;
    let outcome = world.submit(&blocked, &[]).await;
    accepted += usize::from(expect_accept(
        report,
        "accept/blocked-without-approval",
        outcome,
    ));

    // A `prohibited` attempt: emitted with full evidence, and never silently skipped.
    let attempted = world
        .effect(
            "github.delete_repo",
            "prohibited",
            json!({ "execution": { "outcome": "attempted" } }),
        )
        .await;
    let outcome = world.submit(&attempted, &[]).await;
    accepted += usize::from(expect_accept(
        report,
        "accept/prohibited-attempted",
        outcome,
    ));

    // Cognition: identity, resource, cost, and nowhere for a prompt to live.
    let cognition = world.cognition(json!({})).await;
    let outcome = world.submit(&cognition, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/cognition", outcome));

    // An inbound signal, carrying no authority whatsoever.
    let body = json!({ "action": "opened", "issue": 41 });
    let signal = world.signal(&body, json!({})).await;
    let payload = json!({
        "payload-hash": jcs::object_hash(&body).expect("hash"),
        "media-type": "application/json",
        "payload": body
    });
    let outcome = world.submit(&signal, &[payload]).await;
    accepted += usize::from(expect_accept(report, "accept/signal", outcome));

    // An aggregation record over a folded window of reads.
    let aggregate = world.aggregate(json!({})).await;
    let outcome = world.submit(&aggregate, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/aggregate", outcome));

    // A delegated grant at depth 1, narrowing its parent in every dimension.
    let delegated = world.delegated_grant().await;
    let outcome = world.submit(&delegated, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/delegated-grant", outcome));

    // A revocation by the grantor.
    let revocation = world
        .revocation(
            &world.root,
            &world.narrow_mandate,
            "2026-07-26T10:00:00.000Z",
        )
        .await;
    let outcome = world.submit(&revocation, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/revocation", outcome));

    // A checkpoint the kernel signed over a head it can reproduce.
    let (head_seq, _) = world.head(EFFECT_STREAM).await;
    let checkpoint = world
        .kernel_checkpoint(EFFECT_STREAM, 0, head_seq - 1, json!({}))
        .await;
    let outcome = world.submit(&checkpoint, &[]).await;
    accepted += usize::from(expect_accept(report, "accept/checkpoint", outcome));

    report.accepts = accepted;
}

/// Require acceptance, reporting the refusal if there is one. Returns whether it was accepted.
fn expect_accept(report: &mut Report, id: &str, outcome: Outcome) -> bool {
    report.checked += 1;
    match outcome {
        Outcome::Accepted(_) => true,
        Outcome::Rejected { reason, detail, .. } => {
            report.fail(id, format!("a valid case was refused {reason}: {detail}"));
            false
        }
        Outcome::Unavailable(detail) => {
            report.fail(id, format!("store unavailable: {detail}"));
            false
        }
    }
}

// ---------------------------------------------------------------------------------------------
// worlds in particular states
// ---------------------------------------------------------------------------------------------

/// A kernel with keys and roots configured but no policy published: the state before the ceremony.
async fn world_without_policy() -> World {
    stozher_testkit::world_bare().await
}

/// A world where the narrow mandate has been revoked, and the clock has moved past the revocation.
async fn world_with_revocation() -> World {
    let world = world().await;
    let revocation = world
        .revocation(
            &world.root,
            &world.narrow_mandate,
            "2026-07-26T09:05:00.000Z",
        )
        .await;
    world.accept(&revocation, &[]).await;
    world.clock.advance_seconds(600);
    world
}

/// A world with one appended signal, so a trigger can resolve.
async fn world_with_signal() -> World {
    let mut world = world().await;
    let body = json!({ "action": "opened" });
    let signal = world.signal(&body, json!({})).await;
    let payload = json!({
        "payload-hash": jcs::object_hash(&body).expect("hash"),
        "media-type": "application/json",
        "payload": body
    });
    world.signal_id = world.accept(&signal, &[payload]).await;
    world
}

/// A world with a registered `github` manifest and a green conformance run behind it.
async fn world_with_manifest() -> World {
    let world = world().await;
    let manifest = world
        .component
        .sign(&manifest_object("github", "1.0.0", json!({})));
    let (envelope, payloads) = world.register_component(&manifest, true).await;
    world.accept(&envelope, &payloads).await;
    world
}

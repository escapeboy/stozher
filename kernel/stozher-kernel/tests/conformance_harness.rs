//! A whole conformance run — `spec/08 §4`, end to end, against a component that speaks §4.8.
//!
//! # Why this test exists separately from the group tests
//!
//! `tests/conformance_driven_groups.rs` proves each group's judgement by feeding it scripted
//! answers. That leaves the join untested: whether a component implementing the protocol as written
//! can actually pass, and whether the harness's own bootstrap — its throwaway ceremony, its mandate,
//! its approvals, its clock move — produces a kernel those answers survive. Every mistake in that
//! wiring shows up here as a red run, and nowhere else.
//!
//! The component below is therefore not a stub. It signs with its own key, chains its own stream,
//! computes the vector corpus from the primitives rather than reading the answers, and emits the
//! seven attempts §4.4 requires. It is the reference the gateway's `conformance` mode mirrors.

use std::sync::Mutex;

use serde_json::{Value, json};
use stozher_core::error::Result;
use stozher_core::{chain, crypto, jcs, signed};
use stozher_kernel::conformance::REQUIRED_GROUPS;
use stozher_kernel::driver::ComponentDriver;
use stozher_kernel::harness::{self, Plan};
use stozher_kernel::manifest::Manifest;
use stozher_testkit::{TestKey, manifest_object};

const STREAM: &str = "cf:selftest:0001";
/// Mandate envelopes go on their own stream: one stream holds one kind (`stream-kind-mixed`), and
/// §4.4's rootless-chain attempt is a mandate envelope.
const MANDATE_STREAM: &str = "cf:selftest:mandates";

/// A component that conforms, implemented against `spec/08 §4.8`.
struct SelfTest {
    key: TestKey,
    /// The next free position on the component's stream, and what precedes it.
    chain: Mutex<(u64, Value)>,
    manifest: Value,
}

impl SelfTest {
    fn new() -> Self {
        Self {
            key: TestKey::new(0x21, "agent:selftest"),
            chain: Mutex::new((0, Value::Null)),
            manifest: manifest_object("github", "1.0.0", json!({})),
        }
    }

    /// The next position, without taking it. A refused envelope never occupies one (§08 §4.8).
    fn position(&self) -> (u64, Value) {
        self.chain.lock().expect("the chain lock").clone()
    }

    /// Take the position an accepted envelope occupies.
    fn commit(&self, envelope: &Value) {
        let id = signed::object_id(envelope).expect("an envelope id");
        let mut chain = self.chain.lock().expect("the chain lock");
        *chain = (
            envelope["seq"].as_u64().expect("a seq") + 1,
            Value::from(id),
        );
    }

    /// An effect envelope at the next free position.
    fn effect(&self, context: &Value, action: &str, class: &str, extra: Value) -> Value {
        let (seq, prev) = self.position();
        let at = context["at"].as_str().expect("the context carries an instant");
        let mut body = json!({
            "v": stozher_core::VERSION,
            "kind": "effect",
            "emitted-at": at,
            "stream": STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": {
                "subject": self.key.subject, "key": self.key.id.as_str(), "component": "gateway"
            },
            "mandate-ref": context["mandate-ref"],
            "policy-version": context["policy-version"],
            "classification": class,
            "execution": {
                "action": action,
                "target": "conformance:sample",
                "args-hash": crypto::sha256_hex(b"conformance-sample"),
                "outcome": "applied",
                "started-at": at,
                "finished-at": at
            }
        });
        stozher_testkit::merge(&mut body, extra);
        self.key.sign(&body)
    }

    /// An effect plus the payload its evidence commits to.
    fn with_evidence(&self, context: &Value, action: &str, class: &str, extra: Value) -> Value {
        let at = context["at"].as_str().expect("an instant");
        let body = if class == "read" {
            json!({ "path": "README.md" })
        } else {
            json!({ "title": "conformance" })
        };
        let hash = jcs::object_hash(&body).expect("a payload hash");
        // `read` retains for nothing at all under the baseline profile, so the retention asked for
        // is the instant itself; anything later would be clamped and the request would be a
        // component asking for something it cannot have.
        let retain_until = if class == "read" {
            at.to_owned()
        } else {
            stozher_kernel::clock::shift(at, 60 * 60 * 24).expect("a retention")
        };
        let mut evidence = json!({ "evidence": {
            "schema": format!("{action}.v1"),
            "media-type": "application/json",
            "payload-hash": hash,
            "retain-until": retain_until
        }});
        stozher_testkit::merge(&mut evidence, extra);
        let envelope = self.effect(context, action, class, evidence);
        json!({
            "envelope": envelope,
            "payloads": [{
                "payload-hash": hash,
                "media-type": "application/json",
                "payload": body
            }]
        })
    }

    fn class_of(&self, action: &str) -> String {
        self.manifest["actions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|a| a["action"].as_str() == Some(action))
            .and_then(|a| a["class"].as_str())
            .unwrap_or("consequential")
            .to_owned()
    }

    // -- the cases ------------------------------------------------------------------------------

    fn vectors(&self, request: &Value) -> Value {
        let mut answers = serde_json::Map::new();
        for vector in request["vectors"].as_array().into_iter().flatten() {
            let id = vector["id"].as_str().unwrap_or_default().to_owned();
            let answer = match vector["kind"].as_str().unwrap_or_default() {
                "jcs" => {
                    let value = jcs::parse(vector["input-json"].as_str().expect("input-json"))
                        .expect("a valid vector parses");
                    let canonical = jcs::canonicalize(&value).expect("canonicalization");
                    json!({
                        "canonical": canonical,
                        "canonical-sha256": crypto::sha256_hex(canonical.as_bytes())
                    })
                }
                "sha256" => {
                    let input =
                        hex::decode(vector["input-hex"].as_str().expect("input-hex")).expect("hex");
                    json!({ "sha256": crypto::sha256_hex(&input) })
                }
                "ed25519" => {
                    let public = hex_array::<32>(vector["public-key"].as_str().expect("public-key"));
                    let message = hex::decode(vector["message-hex"].as_str().expect("message-hex"))
                        .expect("hex");
                    // With a secret key the signature is ours to produce; without one it is given
                    // and only verification is asked for (§08 §4.8).
                    let mut answer = json!({});
                    let signature = match vector["secret-key"].as_str() {
                        Some(secret) => {
                            let produced = crypto::sign(&hex_array::<32>(secret), &message);
                            answer["signature"] = json!(hex::encode(produced));
                            produced
                        }
                        None => hex_array::<64>(
                            vector["signature"].as_str().expect("a signature to verify"),
                        ),
                    };
                    answer["verifies"] = json!(crypto::verify_strict(&public, &message, &signature));
                    answer
                }
                "object-hash" => {
                    let object = &vector["object"];
                    let mut answer = json!({
                        "expected-jcs": jcs::canonicalize(object).expect("canonicalization"),
                        "expected-object-hash": signed::object_id(object).expect("object hash"),
                        "expected-signature-valid": signed::verify_signed_object(object).is_ok()
                    });
                    if let Ok(input) = signed::signing_input(object) {
                        answer["expected-signing-input-sha256"] =
                            json!(crypto::sha256_hex(input.as_bytes()));
                        answer["expected-signing-input"] = json!(input);
                    }
                    answer
                }
                "chain" => {
                    let envelopes: Vec<Value> = vector["envelopes"]
                        .as_array()
                        .expect("envelopes")
                        .clone();
                    let stream = vector["stream"].as_str().expect("stream");
                    match chain::verify_chain(&envelopes, stream, None) {
                        Ok(ok) => json!({
                            "expected": {
                                "valid": true, "error": Value::Null,
                                "head-hash": ok.head_hash, "anchored": ok.anchored,
                                "count": ok.count
                            }
                        }),
                        Err(e) => json!({
                            "expected": {
                                "valid": false, "error": e.code(), "failed-at-seq": e.seq()
                            }
                        }),
                    }
                }
                other => panic!("the harness asked for a vector kind nobody declared: {other}"),
            };
            answers.insert(id, answer);
        }
        json!({ "answers": answers })
    }

    fn emit(&self, request: &Value) -> Value {
        let context = &request["context"];
        let action = request["action"].as_str().expect("an action");
        let class = self.class_of(action);
        let count = request["count"].as_u64().unwrap_or(1);

        if count > 1 {
            // More calls than the declared sampling allows: fold them, which is what §02 §7 asks
            // an emitter to do and what §08 §4.3 checks it actually does.
            let at = context["at"].as_str().expect("an instant");
            let (seq, prev) = self.position();
            let envelope = self.key.sign(&json!({
                "v": stozher_core::VERSION,
                "kind": "aggregate",
                "emitted-at": at,
                "stream": STREAM,
                "seq": seq,
                "prev-hash": prev,
                "identity": {
                    "subject": self.key.subject, "key": self.key.id.as_str(), "component": "gateway"
                },
                "mandate-ref": context["mandate-ref"],
                "policy-version": context["policy-version"],
                "classification": "read",
                "window": { "from": at, "to": at },
                "counts": { "total": count, "by-action": { action: count } },
                "sample-hashes": [
                    crypto::sha256_hex(b"first"), crypto::sha256_hex(b"last")
                ]
            }));
            self.commit(&envelope);
            return json!({ "submissions": [{ "envelope": envelope, "payloads": [] }] });
        }

        let mut extra = json!({ "execution": {
            "target": request["target"], "args-hash": request["args-hash"]
        }});
        if let Some(authorization) = request.get("authorization") {
            extra["authorization"] = authorization.clone();
        }
        let submission = self.with_evidence(context, action, &class, extra);
        self.commit(&submission["envelope"]);
        json!({ "submissions": [submission] })
    }

    fn negative(&self, request: &Value) -> Value {
        let context = &request["context"];
        let case = request["negative"].as_str().expect("a case");
        let lands = request["expect"].as_str() == Some("accepted");
        let action = request["action"].as_str().unwrap_or("github.create_issue");

        let submissions = match case {
            "gate-authorization-missing" => {
                vec![json!({
                    "envelope": self.effect(context, action, "consequential", json!({})),
                    "payloads": []
                })]
            }
            "gate-authorization-action-mismatch" => {
                // A real approval, over a target this envelope does not name.
                let extra = json!({
                    "authorization": request["authorization"],
                    "execution": {
                        "target": request["target"], "args-hash": request["args-hash"]
                    }
                });
                vec![json!({
                    "envelope": self.effect(context, action, "consequential", extra),
                    "payloads": []
                })]
            }
            "gate-authorization-replayed" => {
                let extra = json!({
                    "authorization": request["authorization"],
                    "execution": {
                        "target": request["target"], "args-hash": request["args-hash"]
                    }
                });
                let first = self.effect(context, action, "consequential", extra.clone());
                self.commit(&first);
                let second = self.effect(context, action, "consequential", extra);
                vec![
                    json!({ "envelope": first, "payloads": [] }),
                    json!({ "envelope": second, "payloads": [] }),
                ]
            }
            "mandate-expired" => {
                vec![json!({
                    "envelope": self.effect(context, "github.get_file", "read", json!({})),
                    "payloads": []
                })]
            }
            "mandate-root-not-human" => {
                // A standing mandate this component grants itself authority with. `spec/03 §1`'s
                // root must be a human, and this kernel refuses to store such a chain at all — so
                // the refusal arrives when the chain is introduced rather than when it is used,
                // which is stronger and carries the code §4.4 names.
                let at = context["at"].as_str().expect("an instant");
                let mandate = self.key.sign(&json!({
                    "v": stozher_core::VERSION,
                    "kind": "mandate",
                    "mandate-kind": "standing",
                    "grantor": {
                        "subject": self.key.subject, "key": self.key.id.as_str(), "role": "agent"
                    },
                    // A key other than the grantor's: §03 §1 forbids self-grant, and a fixture that
                    // tripped that would be refused before the rootless chain was ever examined.
                    "grantee": {
                        "subject": "agent:selftest-child",
                        "key": TestKey::new(0x22, "agent:selftest-child").id.as_str()
                    },
                    "issued-at": at,
                    "not-before": at,
                    "not-after": stozher_kernel::clock::shift(at, 60 * 60 * 24).expect("a window"),
                    "parent": Value::Null,
                    "max-depth": 1,
                    "scope": {
                        "components": ["gateway"], "actions": ["github.*"],
                        "classes": ["read"], "resources": ["*"]
                    },
                    "nonce": "0000000000000000000000000000cccc"
                }));
                let envelope = self.key.sign(&json!({
                    "v": stozher_core::VERSION,
                    "kind": "mandate",
                    "emitted-at": at,
                    "stream": MANDATE_STREAM,
                    "seq": 0,
                    "prev-hash": Value::Null,
                    "identity": {
                        "subject": self.key.subject, "key": self.key.id.as_str(),
                        "component": "gateway"
                    },
                    "mandate": mandate
                }));
                vec![json!({ "envelope": envelope, "payloads": [] })]
            }
            "prohibited-attempted" => {
                let envelope = self.effect(
                    context,
                    "github.delete_repo",
                    "prohibited",
                    json!({ "execution": { "outcome": "attempted" } }),
                );
                vec![json!({ "envelope": envelope, "payloads": [] })]
            }
            "cognition-with-evidence" => {
                let at = context["at"].as_str().expect("an instant");
                let (seq, prev) = self.position();
                let envelope = self.key.sign(&json!({
                    "v": stozher_core::VERSION,
                    "kind": "cognition",
                    "emitted-at": at,
                    "stream": STREAM,
                    "seq": seq,
                    "prev-hash": prev,
                    "identity": {
                        "subject": self.key.subject, "key": self.key.id.as_str(),
                        "component": "gateway"
                    },
                    "mandate-ref": context["mandate-ref"],
                    "policy-version": context["policy-version"],
                    "classification": "benign",
                    "model": { "provider": "anthropic", "name": "claude", "version": "1" },
                    "evidence": {
                        "schema": "github.get_file.v1",
                        "media-type": "application/json",
                        "payload-hash": crypto::sha256_hex(b"nothing"),
                        "retain-until": at
                    }
                }));
                vec![json!({ "envelope": envelope, "payloads": [] })]
            }
            other => panic!("the harness asked for a case §08 §4.4 does not define: {other}"),
        };
        if lands {
            let last = submissions.last().expect("a submission");
            self.commit(&last["envelope"]);
        }
        json!({ "submissions": submissions })
    }

    fn offline(&self, request: &Value) -> Value {
        let context = &request["context"];
        let gated = request["gated"].as_str().expect("a gated action");
        let mut submissions = Vec::new();
        let mut blocked = Vec::new();
        for action in request["actions"].as_array().into_iter().flatten() {
            let action = action.as_str().expect("an action name");
            if action == gated {
                // Consequential under a gate rule, and nobody could have approved it. The record of
                // having declined is what makes the refusal auditable rather than invisible.
                let envelope = self.effect(
                    context,
                    action,
                    "consequential",
                    json!({ "execution": { "outcome": "blocked" } }),
                );
                self.commit(&envelope);
                submissions.push(json!({ "envelope": envelope, "payloads": [] }));
                blocked.push(action);
            } else {
                let envelope = self.effect(context, action, &self.class_of(action), json!({}));
                self.commit(&envelope);
                submissions.push(json!({ "envelope": envelope, "payloads": [] }));
            }
        }
        json!({ "submissions": submissions, "blocked": blocked })
    }
}

impl ComponentDriver for SelfTest {
    async fn ask(&self, request: Value) -> Result<Value> {
        Ok(match request["case"].as_str().unwrap_or_default() {
            "hello" => json!({
                "subject": self.key.subject,
                "key": self.key.id.as_str(),
                "stream": STREAM
            }),
            "vectors" => self.vectors(&request),
            "emit" => self.emit(&request),
            "negative" => self.negative(&request),
            "offline" => self.offline(&request),
            other => json!({ "error": format!("unknown case {other}") }),
        })
    }
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    let bytes = hex::decode(text).expect("hex");
    bytes.try_into().expect("the declared length")
}

fn corpus() -> Vec<Value> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    [
        "jcs-canonicalization.json",
        "sha256.json",
        "ed25519.json",
        "object-hash.json",
        "chain.json",
    ]
    .iter()
    .map(|file| {
        serde_json::from_str(
            &std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}")),
        )
        .unwrap_or_else(|e| panic!("{file}: {e}"))
    })
    .collect()
}

#[tokio::test]
async fn a_conforming_component_produces_a_green_run() {
    let component = SelfTest::new();
    let manifest =
        Manifest::parse(&component.key.sign(&component.manifest)).expect("the manifest parses");
    let plan = Plan {
        manifest: &manifest,
        corpus: corpus(),
        at: "2026-07-26T09:00:00.000Z".to_owned(),
    };

    let run = harness::run(&component, &plan).await.expect("the run");
    assert!(
        run.is_green(),
        "the run is red on {:?}: {}",
        run.outstanding(),
        serde_json::to_string_pretty(&run.evidence()).expect("evidence")
    );

    // The evidence is what unlocks registration, so it has to name every group and commit to the
    // manifest a human will sign over.
    let evidence = run.evidence();
    assert_eq!(evidence["manifest-hash"].as_str(), Some(manifest.hash()));
    for group in REQUIRED_GROUPS {
        assert_eq!(
            evidence["groups"][group]["result"].as_str().is_some(),
            true,
            "the evidence says nothing about {group}"
        );
    }
}

#[tokio::test]
async fn a_component_that_will_not_identify_itself_stops_the_run_before_any_group() {
    // A run that carried on would have to invent a subject to mandate, and would then be certifying
    // something other than the component in front of it.
    struct Mute;
    impl ComponentDriver for Mute {
        async fn ask(&self, _request: Value) -> Result<Value> {
            Ok(json!({ "error": "no" }))
        }
    }
    let component = SelfTest::new();
    let manifest =
        Manifest::parse(&component.key.sign(&component.manifest)).expect("the manifest parses");
    let plan = Plan {
        manifest: &manifest,
        corpus: corpus(),
        at: "2026-07-26T09:00:00.000Z".to_owned(),
    };
    let error = harness::run(&Mute, &plan).await.expect_err("a refusal");
    assert_eq!(error.code(), "x-conformance-harness-failed");
}

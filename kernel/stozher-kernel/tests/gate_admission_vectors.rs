//! `spec/06 §4.4` rule 9 and `spec/09 §7` — which gate submission earns a durable record, driven
//! entirely by `spec/vectors/gate-admission.json`.
//!
//! # Why this file reads the vectors instead of asserting its own constants
//!
//! The admission order is a pure function of stated inputs, and the two implementations count and
//! order these checks in their own code. A suite that asserted against its own constants could not
//! discover that the two disagree, which is the whole reason the corpus exists
//! (`spec/vectors/README.md`). Every expected status, outcome and record flag below is read from the
//! file; nothing here is hardcoded.
//!
//! # The two facts under test that an implementation gets wrong by being reasonable
//!
//! **A size refusal is not a lie.** `gate-arguments-too-large` says a component was honest and
//! verbose; only rule 4's mismatch says it submitted values its own signed commitment does not
//! cover. Recording both fills the chain with the events that do not matter.
//!
//! **The bound counts records, not parked rows.** A refused submission parks nothing, so the
//! obvious counter is zero forever for a component that only ever lies.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use stozher_core::jcs;
use stozher_kernel::http;
use stozher_testkit::{Ask, TOKEN, World, world};
use tower::ServiceExt;

const MISMATCH: &str = "gate-arguments-hash-mismatch";

struct Answer {
    status: StatusCode,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn post(world: &World, uri: &str, body: &Value) -> Answer {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(jcs::canonicalize(body).expect("canonicalizing")))
        .expect("a request");
    let response = http::router(Arc::clone(&world.kernel))
        .oneshot(request)
        .await
        .expect("the router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("a body")
        .to_bytes();
    Answer {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn request_for(world: &World, arguments: &Value) -> Value {
    world.action_request(&Ask {
        requester: &world.agent,
        component: "gateway",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "github.create_issue",
        target: "repo:acme/backend",
        args_hash: &jcs::object_hash(arguments).expect("hashing the arguments"),
    })
}

fn submission(request: &Value, arguments: &Value) -> Value {
    json!({ "request": request, "arguments": arguments })
}

/// How many argument-mismatch records the store holds. The record flag under test.
async fn mismatches(world: &World) -> usize {
    world
        .ingest()
        .store()
        .rejections(Some(MISMATCH), 1000)
        .await
        .expect("reading the rejection stream")
        .len()
}

/// The body a vector's `arguments-check` describes, and the request it belongs to.
fn body_for(world: &World, check: Option<&str>) -> Value {
    match check {
        // The member omitted entirely: a component that never held the preimage.
        None => request_for(world, &json!({})),
        Some("accept") => {
            let arguments = json!({"title": "ship it", "draft": false});
            submission(&request_for(world, &arguments), &arguments)
        }
        Some(MISMATCH) => {
            // The request commits to one value; the submission carries another. Nothing else about
            // it is wrong, which is what makes it a lie rather than a malformation.
            let committed = json!({"title": "ship it"});
            submission(
                &request_for(world, &committed),
                &json!({"title": "ship it to production"}),
            )
        }
        Some("gate-arguments-too-large") => {
            // Honest and verbose: the values are exactly what `args-hash` commits to, and over the
            // 16384-byte cap of rule 3.
            let arguments = json!({"a": "x".repeat(20_000)});
            submission(&request_for(world, &arguments), &arguments)
        }
        Some(other) => {
            panic!("the vector names an arguments-check this harness cannot build: {other}")
        }
    }
}

/// Drive the world into `parked-in-window` parked requests and `mismatches-in-window` recorded
/// mismatches from this caller, then return the already-queued submission if the vector wants one.
async fn arrange(world: &World, input: &Value) -> Option<Value> {
    let parked = input["parked-in-window"]
        .as_u64()
        .expect("parked-in-window");
    let recorded = input["mismatches-in-window"]
        .as_u64()
        .expect("mismatches-in-window");

    // The retried request is parked *first* and counts toward `parked-in-window`. Parking it last
    // would meet the queue cap on the way in whenever the vector puts the queue at its cap, which
    // is exactly the state `a-retry-of-a-queued-request-is-idempotent` exists to describe.
    let queued_request = if input["already-queued"].as_bool().expect("already-queued") {
        let arguments = json!({"title": "ship it", "draft": false, "retried": true});
        let request = request_for(world, &arguments);
        let answer = post(
            world,
            "/v1/gate/requests",
            &submission(&request, &arguments),
        )
        .await;
        assert_eq!(
            answer.status,
            StatusCode::CREATED,
            "arranging the already-queued request: {}",
            answer.body
        );
        Some(request)
    } else {
        None
    };
    let fill = parked.saturating_sub(u64::from(queued_request.is_some()));

    // Each arranged request must be a *different* request: the harness clock is frozen, so §06
    // §1.1's nonce is the same for two requests built from the same fields, and the second would
    // resolve to the first by `request-hash` and park nothing. Varying the arguments varies
    // `args-hash`, which is inside the hashed object.
    for n in 0..fill {
        let arguments = json!({"title": "ship it", "draft": false, "n": n});
        let body = submission(&request_for(world, &arguments), &arguments);
        let answer = post(world, "/v1/gate/requests", &body).await;
        assert_eq!(
            answer.status,
            StatusCode::CREATED,
            "arranging the parked count: {}",
            answer.body
        );
    }
    for n in 0..recorded {
        let committed = json!({"title": "ship it", "n": n});
        let body = submission(
            &request_for(world, &committed),
            &json!({"title": "ship it to production", "n": n}),
        );
        let answer = post(world, "/v1/gate/requests", &body).await;
        assert_eq!(
            answer.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "arranging the mismatch count: {}",
            answer.body
        );
    }
    assert_eq!(
        mismatches(world).await,
        usize::try_from(recorded).expect("a small count"),
        "the arrangement did not produce the mismatch count the vector describes"
    );

    queued_request
}

#[tokio::test]
async fn every_gate_admission_vector_decides_as_the_corpus_says() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../../spec/vectors/gate-admission.json"))
            .expect("the gate-admission corpus parses");
    let vectors = corpus["vectors"].as_array().expect("vectors");
    assert!(
        !vectors.is_empty(),
        "the corpus is empty, so this test asserts nothing"
    );

    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        let input = &vector["input"];
        let expected = &vector["expected"];

        // The vectors state the limit they were computed under. A kernel configured differently
        // would decide differently and the file would be lying about what it binds.
        let world = world().await;
        assert_eq!(
            u64::from(world.kernel.config.gate_rate_limit.per_subject),
            input["rate-limit"]["per-subject"].as_u64().expect("cap"),
            "{name}: the harness kernel's per-subject cap is not the one the vector assumes"
        );

        let queued_request = arrange(&world, input).await;
        let before = mismatches(&world).await;

        let check = input["arguments-check"].as_str();
        let body = match (&queued_request, check) {
            // A retry of a request already on the queue: the same request object, resubmitted.
            (Some(request), Some("accept")) => {
                let arguments = json!({"title": "ship it", "draft": false, "retried": true});
                submission(request, &arguments)
            }
            // The case the idempotency skip must not launder: the same queued request, this time
            // carrying values it does not commit to.
            (Some(request), Some(MISMATCH)) => {
                submission(request, &json!({"title": "something else entirely"}))
            }
            _ => body_for(&world, check),
        };

        let answer = post(&world, "/v1/gate/requests", &body).await;
        let expected_status = StatusCode::from_u16(
            u16::try_from(expected["status"].as_u64().expect("a status")).expect("a status"),
        )
        .expect("a valid status");
        assert_eq!(answer.status, expected_status, "{name}: {}", answer.body);

        match expected["outcome"].as_str().expect("an outcome") {
            "queued" => {
                assert_eq!(answer.json()["idempotent"].as_bool(), Some(false), "{name}");
            }
            "already-queued" => {
                assert_eq!(answer.json()["idempotent"].as_bool(), Some(true), "{name}");
            }
            code => {
                assert_eq!(
                    answer.json()["reason-code"].as_str(),
                    Some(code),
                    "{name}: {}",
                    answer.body
                );
            }
        }

        let after = mismatches(&world).await;
        let wrote = after > before;
        assert_eq!(
            wrote,
            expected["record"].as_bool().expect("a record flag"),
            "{name}: the rejection stream went from {before} to {after} records, and the vector \
             says record={}",
            expected["record"]
        );
    }
}

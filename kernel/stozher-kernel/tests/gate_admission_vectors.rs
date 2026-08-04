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

async fn get(world: &World, uri: &str) -> Answer {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
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

/// Submit `n` distinct mismatching submissions, each of which records.
async fn lie(world: &World, n: u32) {
    for i in 0..n {
        let committed = json!({"title": "ship it", "n": i});
        let body = submission(
            &request_for(world, &committed),
            &json!({"title": "ship it to production", "n": i}),
        );
        let answer = post(world, "/v1/gate/requests", &body).await;
        assert_eq!(
            answer.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            answer.body
        );
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

#[tokio::test]
async fn a_mismatch_is_surfaced_as_a_finding_and_not_as_a_longer_list() {
    // ADR-0032 §5 named this gap and this test closes it. The records were already on the page —
    // `/console/rejections` lists every refusal — but listed is not surfaced: a reader scanning a
    // flat table of refused submissions has no reason to notice that a dozen of them share one
    // submitter, which is the only fact that distinguishes a broken component from noise.
    let world = world().await;
    let limit = world.kernel.config.gate_rate_limit;
    let threshold = (limit.per_subject / 2).max(1);

    let quiet = get(&world, "/console/rejections").await;
    assert_eq!(quiet.status, StatusCode::OK, "{}", quiet.body);
    assert!(
        !quiet.body.contains("had not committed to"),
        "an empty rejection stream must not report a finding"
    );

    // One short of the threshold: still a row in the table, still not a finding. A page that named
    // a single mismatch would be the approval-fatigue mistake §09 §7 describes, one surface over.
    lie(&world, threshold - 1).await;
    let below = get(&world, "/console/rejections").await;
    assert!(
        !below.body.contains("had not committed to"),
        "{} mismatches were reported as a finding below the threshold of {threshold}: {}",
        threshold - 1,
        below.body
    );

    lie(&world, 1).await;
    let page = get(&world, "/console/rejections").await;
    assert!(
        page.body.contains("had not committed to"),
        "the finding did not appear at the threshold of {threshold}: {}",
        page.body
    );
    assert!(
        page.body.contains("agent:test-harness"),
        "the finding must name the caller, not merely count: {}",
        page.body
    );
}

#[tokio::test]
async fn at_the_cap_the_finding_says_the_count_stopped_and_the_component_may_not_have() {
    // The honest half of §06 §4.4 rule 9's bound. Past the cap the kernel stops recording, so the
    // number on the page stops moving — and a reader who took that as "it stopped happening" would
    // have drawn exactly the wrong conclusion from a safety measure.
    let world = world().await;
    let limit = world.kernel.config.gate_rate_limit;

    lie(&world, limit.per_subject).await;
    let page = get(&world, "/console/rejections").await;
    assert!(
        page.body.contains("this count has stopped growing and the"),
        "at the cap the finding must say why it stopped counting: {}",
        page.body
    );

    // And the refusal itself changes shape at the cap, which is the wire-visible half.
    let committed = serde_json::json!({"title": "one more"});
    let over = post(
        &world,
        "/v1/gate/requests",
        &submission(
            &request_for(&world, &committed),
            &serde_json::json!({"title": "something else"}),
        ),
    )
    .await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS, "{}", over.body);
}

/// A connection to the database that bypasses every line of kernel code — the same seam
/// `append_only_and_decay.rs` uses to prove the storage engine, rather than this crate's manners,
/// is what holds a guarantee.
async fn raw(database: &std::path::PathBuf) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(database))
        .await
        .expect("opening the database directly")
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stozher-store-{}-{name}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("stozher.db")
}

#[tokio::test]
async fn a_store_that_cannot_take_the_record_is_not_a_kernel_that_said_no() {
    // ADR-0032 §3.4, which was recorded as having **no test** on the grounds that injecting a store
    // failure at that one line needed a fault-injection seam this harness does not have. It does
    // have one: `world_at` plus a direct connection, the same pair `append_only_and_decay.rs`
    // already uses. The seam was not missing; I had not looked for it — the second time in two days
    // that "this needs a seam" turned out to mean "I stopped early" (see ADR-0028 §6).
    //
    // The claim: §06 §4.4 rule 9's record is a MUST, so a store that cannot take it means the
    // kernel could not *complete the admission* — not that it decided against the submission.
    // Answering `422 gate-arguments-hash-mismatch` there would be DEF-6's mistake exactly: a moment
    // the kernel could not answer, reported as a verdict about the bytes. A component reading that
    // would record a refusal it can never retry, for a request the kernel never actually judged.
    let database = scratch("rejection-write-fails");
    let world = stozher_testkit::world_at(&database).await;

    let committed = json!({"title": "ship it"});
    let lying = || {
        submission(
            &request_for(&world, &committed),
            &json!({"title": "ship it to production"}),
        )
    };

    // Baseline in this same world, so the difference below is the store and nothing else.
    let judged = post(&world, "/v1/gate/requests", &lying()).await;
    assert_eq!(
        judged.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        judged.body
    );
    assert_eq!(judged.json()["reason-code"].as_str(), Some(MISMATCH));

    // Now make the *insert* fail and nothing else. A trigger rather than dropping the table,
    // because §4.4 rule 9's bound reads the same table one statement earlier
    // (`argument_mismatches_since`) — take the table away and the route answers 503 from the
    // count, never reaching the line this test is about. That is not a hypothetical: the first
    // version of this test renamed the table, passed, and went on passing when the record path was
    // mutated to answer `422`. The mutation is what found it.
    let direct = raw(&database).await;
    sqlx::query(
        "CREATE TRIGGER injected_rejection_write_failure BEFORE INSERT ON rejections \
         BEGIN SELECT RAISE(ABORT, 'injected: the store cannot take this record'); END",
    )
    .execute(&direct)
    .await
    .expect("installing the injected failure");
    direct.close().await;

    let unanswerable = post(&world, "/v1/gate/requests", &lying()).await;
    assert_eq!(
        unanswerable.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a store that could not take the record answered as though it had judged the submission: {}",
        unanswerable.body
    );
    assert_eq!(
        unanswerable.json()["reason-code"].as_str(),
        Some("x-store-unavailable"),
        "{}",
        unanswerable.body
    );
    // And the half that makes it worth asserting: the caller is told to retry rather than told no.
    assert_ne!(
        unanswerable.json()["reason-code"].as_str(),
        Some(MISMATCH),
        "the kernel reported a moment it could not answer as a verdict about the bytes"
    );
}

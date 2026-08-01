//! S4: the kernel-native pending queue, the console's one mutating route, and the approver ping.
//!
//! # What these tests are for
//!
//! ADR-0008 §A left one S3 bullet unmet for a structural reason: `spec/06 §4.3` obliges the kernel
//! to record a parked request, but no envelope kind could carry one to it. These tests assert the
//! resolution — a request-submission route, per `spec/06 §1.1`'s own "submitted over an
//! authenticated channel" — and then attack it.
//!
//! # The adversarial half is the point
//!
//! ADR-0002 records a shipped product that bypassed its own gate through an ambient container
//! binding. The positive tests below show the mechanism working; the negative ones show that the
//! *new surface S4 adds* — a write route and a console form — did not become a second way to
//! satisfy `requires-gate`. A rewritten request, a stranger's signature, a self-approval, a replay
//! and an approval borrowed from another action must each permit nothing, and each is attempted
//! here rather than argued about.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use stozher_core::jcs;
use stozher_kernel::clock::Clock;
use stozher_kernel::notify::{Channel, Ping};
use stozher_kernel::store::EnvelopeQuery;
use stozher_kernel::{http, notify};
use stozher_testkit::{
    Ask, CORE_STREAM, EFFECT_STREAM, TOKEN, TestKey, World, revise, world, world_with_channels,
};
use tower::ServiceExt;

// -- a channel that records instead of sending ---------------------------------------------------

/// A real [`Channel`] whose wire is a vector. The adapter under test is the shipped one; only the
/// transport is a double, because a gate that needed a Slack workspace to run is a gate nobody runs.
#[derive(Debug, Default)]
struct Capturing {
    pings: Mutex<Vec<Ping>>,
    fail: bool,
}

impl Capturing {
    fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn failing() -> Arc<Self> {
        Arc::new(Self {
            pings: Mutex::default(),
            fail: true,
        })
    }

    fn seen(&self) -> Vec<Ping> {
        self.pings.lock().expect("the capture lock").clone()
    }
}

/// So the test can hold one handle and the notifier another.
#[derive(Debug)]
struct Shared(Arc<Capturing>);

impl Channel for Shared {
    fn name(&self) -> &str {
        "capturing"
    }

    fn deliver(&self, ping: &Ping) -> stozher_core::error::Result<()> {
        self.0
            .pings
            .lock()
            .expect("the capture lock")
            .push(ping.clone());
        if self.0.fail {
            return Err(stozher_core::error::Error::new(
                notify::NOTIFY_FAILED,
                "the test channel is down",
            ));
        }
        Ok(())
    }
}

// -- plumbing ------------------------------------------------------------------------------------

struct Answer {
    status: StatusCode,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn call(
    world: &World,
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, String)],
) -> Answer {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    let request = builder
        .body(body.map_or_else(Body::empty, Body::from))
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
        .expect("collecting the body")
        .to_bytes();
    Answer {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn bearer() -> Vec<(&'static str, String)> {
    vec![("authorization", format!("Bearer {TOKEN}"))]
}

async fn get(world: &World, uri: &str) -> Answer {
    call(world, "GET", uri, None, &bearer()).await
}

async fn post_json(world: &World, uri: &str, body: &Value) -> Answer {
    let mut headers = bearer();
    headers.push(("content-type", "application/json".to_owned()));
    call(
        world,
        "POST",
        uri,
        Some(jcs::canonicalize(body).expect("canonicalizing")),
        &headers,
    )
    .await
}

/// A `consequential` `github.create_issue` draft, and the action request that describes it exactly.
///
/// Both come from the same draft so the two objects agree field for field — which is what step (10)
/// of §06 §2 checks, and what every "approval for A cannot authorize B" test below breaks on
/// purpose.
async fn draft_and_request(world: &World, action: &str) -> (Value, Value) {
    let draft = world.effect(action, "consequential", json!({})).await;
    let args_hash = draft["execution"]["args-hash"]
        .as_str()
        .expect("args-hash")
        .to_owned();
    let target = draft["execution"]["target"]
        .as_str()
        .expect("target")
        .to_owned();
    let request = world.action_request(&Ask {
        requester: &world.agent,
        component: "gateway",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action,
        target: &target,
        args_hash: &args_hash,
    });
    (draft, request)
}

/// Park a request through the kernel-native route and return its hash.
async fn park(world: &World, request: &Value) -> String {
    let answer = post_json(world, "/v1/gate/requests", request).await;
    assert_eq!(answer.status, StatusCode::CREATED, "{}", answer.body);
    answer.json()["request-hash"]
        .as_str()
        .expect("a request hash")
        .to_owned()
}

/// Answer a parked request through the console, exactly as a human would: a signed decision object
/// plus the CSRF token the page issued to this caller.
async fn decide_in_console(world: &World, request_hash: &str, decision: &Value) -> Answer {
    let body = json!({
        "csrf": world.kernel.csrf_token("agent:test-harness", request_hash),
        "decision": decision
    });
    post_json(
        world,
        &format!("/console/pending/{request_hash}/decide"),
        &body,
    )
    .await
}

/// Wait for the notification worker, which runs off the response path on purpose.
async fn settle() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

// -- 1. the park is visible, which is the ADR-0008 §A bullet -------------------------------------

#[tokio::test]
async fn a_parked_request_is_visible_in_the_console_pending_queue() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;

    // Asserted against the bytes the kernel rendered, not the return value of a function.
    let page = get(&world, "/console/pending").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains(&request_hash),
        "the park is not on the page: {}",
        page.body
    );
    assert!(page.body.contains("github.create_issue"), "{}", page.body);
    assert!(page.body.contains("agent:gateway/dev"), "{}", page.body);
    // The approver must be able to read the exact object their signature would cover.
    assert!(
        page.body.contains("action-request"),
        "the request object itself is not shown: {}",
        page.body
    );
    // And where to answer it. There was a form here, and it could not be submitted: the only
    // documented way to reach this page in a browser is `bin/stozher-console`, which forwards `GET`
    // only and says why (ADR-0009 §2 — a browser proxy that could POST is the shortest path back to
    // the thing that file exists to avoid). The button returned `501 Unsupported method`, and going
    // back discarded the pasted signature. Three people found it independently in a day, two of them
    // mid-demo. The `/decide` route is unchanged and still serves anything that can authenticate;
    // what is gone is a control the shipped path could never work, which taught an approver the
    // product was broken at the moment it asked them to trust it.
    assert!(
        page.body.contains("stozher-approve"),
        "the page must name where the decision is actually made: {}",
        page.body
    );
    assert!(
        !page.body.contains("<form"),
        "a control the shipped browser path cannot submit is worse than none: {}",
        page.body
    );
}

#[tokio::test]
async fn parking_a_request_appends_nothing_to_any_chain() {
    let world = world().await;
    let before = world
        .ingest()
        .store()
        .envelope_count()
        .await
        .expect("counting");
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    park(&world, &request).await;
    let after = world
        .ingest()
        .store()
        .envelope_count()
        .await
        .expect("counting");
    // A question is not an effect. `Store::append` is crate-private and this route never reaches it.
    assert_eq!(before, after, "submitting a request appended an envelope");
}

#[tokio::test]
async fn a_request_that_has_already_expired_never_enters_the_queue() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let expired = {
        let mut request = request;
        request["not-after"] = Value::from("2026-07-26T08:00:00.000Z");
        request
    };
    let answer = post_json(&world, "/v1/gate/requests", &expired).await;
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-request-expired")
    );
}

#[tokio::test]
async fn a_request_carrying_a_member_the_approver_was_never_shown_is_refused() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let mut smuggled = request;
    smuggled["approved"] = Value::Bool(true);
    let answer = post_json(&world, "/v1/gate/requests", &smuggled).await;
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("schema-unknown-member")
    );
}

#[tokio::test]
async fn the_queue_is_not_readable_without_a_credential() {
    let world = world().await;
    for (method, uri) in [
        ("GET", "/v1/gate/requests"),
        ("POST", "/v1/gate/requests"),
        ("GET", "/console/pending"),
    ] {
        let answer = call(&world, method, uri, Some("{}".to_owned()), &[]).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

// -- 2. the ping fires, and a failure to notify is a record --------------------------------------

#[tokio::test]
async fn the_approver_ping_fires_and_its_delivery_is_recorded() {
    let capture = Capturing::shared();
    let world = world_with_channels(vec![Box::new(Shared(Arc::clone(&capture)))]).await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    settle().await;

    let pings = capture.seen();
    assert_eq!(pings.len(), 1, "the approver was not pinged");
    assert_eq!(pings[0].request_hash, request_hash);
    assert_eq!(pings[0].action, "github.create_issue");
    // §10 §6: a ping carries no arguments, no other pending requests, no policy, no key material.
    let rendered = format!("{}{}", pings[0].body(), pings[0].to_json());
    assert!(!rendered.contains("ed25519:"), "{rendered}");

    let page = get(&world, "/console/pending").await;
    assert!(
        page.body.contains("delivered on 1 channel(s)"),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn a_failed_ping_is_recorded_and_the_park_still_stands() {
    let capture = Capturing::failing();
    let world = world_with_channels(vec![Box::new(Shared(Arc::clone(&capture)))]).await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    settle().await;

    assert_eq!(capture.seen().len(), 1, "the channel was not tried");
    // The park is what must survive a channel outage. An approver ping that failed silently, with
    // the request dropped, is the failure mode this assertion exists for.
    let queued = get(&world, "/v1/gate/requests").await;
    assert_eq!(queued.json()["count"].as_u64(), Some(1));
    assert_eq!(
        queued.json()["requests"][0]["request-hash"].as_str(),
        Some(request_hash.as_str())
    );

    let page = get(&world, "/console/pending").await;
    assert!(page.body.contains("not delivered"), "{}", page.body);
    assert!(
        page.body.contains("the test channel is down"),
        "the failure reason is not shown: {}",
        page.body
    );
}

#[tokio::test]
async fn a_deployment_with_no_channel_says_so_rather_than_rendering_silence() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    park(&world, &request).await;

    let page = get(&world, "/console/pending").await;
    // The `[unknown]` vs `[clean]` distinction: "nobody was told" must never look like "told".
    assert!(
        page.body.contains("No notification channel is configured"),
        "{}",
        page.body
    );
}

// -- 3. approving produces a real signed decision that survives all nine steps --------------------

#[tokio::test]
async fn approving_in_the_console_records_a_chained_gate_decision_envelope() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;

    let decision = world.decide(&request, "approve", None, &world.root);
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::CREATED, "{}", answer.body);
    let envelope_id = answer.json()["envelope-id"]
        .as_str()
        .expect("an envelope id")
        .to_owned();

    // §06 §5: the decision is itself an envelope on the kernel's core stream, so the approval
    // history is chained and checkpointed independently of the effects that consume it.
    let recorded = get(&world, &format!("/v1/envelopes/{envelope_id}")).await;
    assert_eq!(recorded.status, StatusCode::OK);
    let envelope = &recorded.json()["envelope"];
    assert_eq!(envelope["kind"].as_str(), Some("gate-decision"));
    assert_eq!(envelope["stream"].as_str(), Some(CORE_STREAM));
    assert_eq!(
        envelope["decision-of"].as_str(),
        Some(request_hash.as_str())
    );
    // The inner signature is the human's; the envelope's own is the kernel attesting receipt.
    assert_eq!(
        envelope["decision"]["sig"]["key"].as_str(),
        Some(world.root.id.as_str())
    );

    // The chain still verifies with the decision in it: the report names a failure when there is
    // one, so the absence of a reason code — with the head recomputed over every envelope — is the
    // verification passing.
    let verified = get(&world, &format!("/v1/streams/{CORE_STREAM}/verify")).await;
    assert_eq!(verified.status, StatusCode::OK);
    assert!(
        verified.json()["reason-code"].is_null(),
        "the core stream stopped verifying once a decision was on it: {}",
        verified.body
    );
    let console_verify = get(&world, &format!("/console/streams/{CORE_STREAM}/verify")).await;
    assert!(
        console_verify.body.contains("VALID") && !console_verify.body.contains("INVALID"),
        "{}",
        console_verify.body
    );

    // And a component can fetch the decision to carry with its work (§06 §3).
    let fetched = get(&world, &format!("/v1/gate/requests/{request_hash}")).await;
    assert_eq!(fetched.json()["decision"], decision);

    // The console moves it out of the parked section and into the answered one.
    let page = get(&world, "/console/pending").await;
    assert!(
        page.body.contains("Answered by a named human"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Nothing is parked."), "{}", page.body);
}

#[tokio::test]
async fn the_recorded_approval_lets_the_exact_approved_effect_through_and_nothing_else() {
    let world = world().await;
    let (draft, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    let decision = world.decide(&request, "approve", None, &world.root);
    assert_eq!(
        decide_in_console(&world, &request_hash, &decision)
            .await
            .status,
        StatusCode::CREATED
    );

    // The permission is data that travels with the work (§06 §3): the component embeds the request
    // and the decision verbatim, and ingest runs all eleven steps over the pair.
    let authorization = json!({ "request": request, "decision": decision });
    let effect = revise(
        &draft,
        json!({ "authorization": authorization }),
        &world.agent,
    );
    world.accept(&effect, &[]).await;

    let applied = world
        .ingest()
        .store()
        .query(&EnvelopeQuery {
            action: Some("github.create_issue"),
            outcome: Some("applied"),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("querying");
    assert_eq!(applied.len(), 1, "the approved effect did not land");
}

#[tokio::test]
async fn denying_captures_the_reason_and_the_effect_is_refused() {
    let world = world().await;
    let (draft, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;

    let decision = world.decide(
        &request,
        "deny",
        Some("we do not file public issues on behalf of customers"),
        &world.root,
    );
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::CREATED, "{}", answer.body);
    assert_eq!(answer.json()["decision"].as_str(), Some("deny"));

    // The reason is captured — it is what the calling agent is owed (§06 §4.1) and the training
    // data policy tier 3 would learn from (`docs/design/policy-model.md`).
    let page = get(&world, "/console/pending").await;
    assert!(
        page.body
            .contains("we do not file public issues on behalf of customers"),
        "{}",
        page.body
    );

    // An effect that reports itself applied while carrying the denial is refused (§06 §2 step 7).
    let authorization = json!({ "request": request, "decision": decision });
    let effect = revise(
        &draft,
        json!({ "authorization": authorization }),
        &world.agent,
    );
    world.reject(&effect, &[], "gate-denied").await;
}

#[tokio::test]
async fn a_denial_without_a_reason_is_refused_at_the_console() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    let decision = world.decide(&request, "deny", None, &world.root);
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-denial-without-reason")
    );
}

// -- 4. adversarial: the new surface is not a second way in --------------------------------------

#[tokio::test]
async fn self_approval_is_refused_at_the_console() {
    let world = world().await;
    // The subject asks, and then signs its own request with its own key.
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    let decision = world.decide(&request, "approve", None, &world.agent);
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-self-approval")
    );
}

#[tokio::test]
async fn a_strangers_signature_permits_nothing() {
    let world = world().await;
    let (draft, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;

    // A key enrolled nowhere. It signs a perfectly well-formed approval.
    let decision = world.decide(&request, "approve", None, &world.stranger);
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-approver-not-permitted")
    );

    // And even if it reached an emitter some other way, ingest refuses the effect for the same
    // reason — the console is not the only place this is checked.
    let effect = revise(
        &draft,
        json!({ "authorization": { "request": request, "decision": decision } }),
        &world.agent,
    );
    world
        .reject(&effect, &[], "gate-approver-not-permitted")
        .await;
}

#[tokio::test]
async fn a_decision_whose_request_was_rewritten_permits_nothing() {
    let world = world().await;
    let (draft, request) = draft_and_request(&world, "github.create_issue").await;
    park(&world, &request).await;
    let decision = world.decide(&request, "approve", None, &world.root);

    // A real signature paired with a request body that is not the one it covers. This is the
    // failure mode step (2) exists for, and the reason the request travels verbatim.
    let mut rewritten = request;
    rewritten["target"] = Value::from("repo:acme/production-secrets");
    let effect = revise(
        &draft,
        json!({ "authorization": { "request": rewritten, "decision": decision } }),
        &world.agent,
    );
    world
        .reject(&effect, &[], "gate-authorization-request-hash-mismatch")
        .await;
}

#[tokio::test]
async fn an_approval_for_one_action_cannot_authorize_another_field_by_field() {
    let world = world().await;

    // Approve `github.create_issue` for real, through the whole path.
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    let decision = world.decide(&request, "approve", None, &world.root);
    assert_eq!(
        decide_in_console(&world, &request_hash, &decision)
            .await
            .status,
        StatusCode::CREATED
    );
    let authorization = json!({ "request": request, "decision": decision });

    // Now try to spend that approval on something else, one bound member at a time. Every one of
    // these is a valid signature over a real request — what fails is that the *effect* is not the
    // approved effect (§06 §2 step 10).
    for (member, overrides) in [
        (
            "action",
            json!({ "execution": { "action": "github.close_issue" } }),
        ),
        (
            "target",
            json!({ "execution": { "target": "repo:acme/production-secrets" } }),
        ),
        (
            "args-hash",
            json!({ "execution": { "args-hash": "ff".repeat(32) } }),
        ),
        (
            "component",
            json!({ "identity": { "component": "boruna" } }),
        ),
        (
            "mandate-ref",
            // A mandate that is itself wide enough for this action, so the walk succeeds and the
            // refusal can only come from step (10) — swapping in a *narrower* one would be caught
            // one check earlier and would prove something else.
            json!({ "mandate-ref": world.budgeted_mandate.clone() }),
        ),
    ] {
        let draft = world
            .effect("github.create_issue", "consequential", json!({}))
            .await;
        let mut changed = overrides;
        stozher_testkit::merge(
            &mut changed,
            json!({ "authorization": authorization.clone() }),
        );
        let effect = revise(&draft, changed, &world.agent);
        match world.submit(&effect, &[]).await {
            stozher_kernel::Outcome::Rejected { reason, .. } => assert_eq!(
                reason, "gate-authorization-action-mismatch",
                "changing {member} was refused by something other than the approval binding"
            ),
            other => panic!("changing {member} was not refused: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_single_use_approval_cannot_be_spent_twice() {
    let world = world().await;
    let (draft, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    let decision = world.decide(&request, "approve", None, &world.root);
    assert_eq!(
        decide_in_console(&world, &request_hash, &decision)
            .await
            .status,
        StatusCode::CREATED
    );
    let authorization = json!({ "request": request, "decision": decision });

    let first = revise(
        &draft,
        json!({ "authorization": authorization.clone() }),
        &world.agent,
    );
    world.accept(&first, &[]).await;

    // A *different* envelope carrying the same approval — the FleetQ re-execution shape, done the
    // right way and then done once too often. Everything the approval binds is identical, so the
    // only thing that can refuse this is the replay set itself.
    let (seq, prev) = world.head(EFFECT_STREAM).await;
    let second = revise(
        &draft,
        json!({ "seq": seq, "prev-hash": prev, "authorization": authorization }),
        &world.agent,
    );
    world
        .reject(&second, &[], "gate-authorization-replayed")
        .await;
}

#[tokio::test]
async fn one_request_gets_one_answer() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;

    let approve = world.decide(&request, "approve", None, &world.root);
    assert_eq!(
        decide_in_console(&world, &request_hash, &approve)
            .await
            .status,
        StatusCode::CREATED
    );

    // The approver cannot overwrite their own answer. (A *different* human would be refused one
    // step earlier, at `gate-approver-not-permitted`, which is a different property — see
    // `a_strangers_signature_permits_nothing`.)
    let deny = world.decide(&request, "deny", Some("on reflection, no"), &world.root);
    let answer = decide_in_console(&world, &request_hash, &deny).await;
    assert_eq!(
        answer.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        answer.body
    );
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-decision-already-recorded")
    );
    let fetched = get(&world, &format!("/v1/gate/requests/{request_hash}")).await;
    assert_eq!(
        fetched.json()["decision"]["decision"].as_str(),
        Some("approve")
    );
}

#[tokio::test]
async fn the_decision_route_refuses_a_token_it_did_not_issue() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;
    let decision = world.decide(&request, "approve", None, &world.root);

    for forged in ["", "00", &"ab".repeat(32)] {
        let body = json!({ "csrf": forged, "decision": decision });
        let answer = post_json(
            &world,
            &format!("/console/pending/{request_hash}/decide"),
            &body,
        )
        .await;
        assert!(
            answer.status == StatusCode::FORBIDDEN || answer.status == StatusCode::BAD_REQUEST,
            "a forged token {forged:?} was accepted: {} {}",
            answer.status,
            answer.body
        );
    }
    // Nothing was recorded by any of those attempts.
    let fetched = get(&world, &format!("/v1/gate/requests/{request_hash}")).await;
    assert_eq!(fetched.json()["decision"], Value::Null);
}

#[tokio::test]
async fn a_token_issued_to_one_request_does_not_answer_another() {
    let world = world().await;
    let (_, first) = draft_and_request(&world, "github.create_issue").await;
    let first_hash = park(&world, &first).await;
    let (_, second) = draft_and_request(&world, "github.close_issue").await;
    let second_hash = park(&world, &second).await;

    let decision = world.decide(&second, "approve", None, &world.root);
    let body = json!({
        "csrf": world.kernel.csrf_token("agent:test-harness", &first_hash),
        "decision": decision
    });
    let answer = post_json(
        &world,
        &format!("/console/pending/{second_hash}/decide"),
        &body,
    )
    .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
}

#[tokio::test]
async fn the_console_still_has_exactly_one_write_verb() {
    let world = world().await;
    // Every read page stays `GET`-only; S3's ten-path assertion lives in `console_and_revocations`
    // and still holds. What this adds is the other half: the decision path itself answers nothing
    // but `POST`, so no read route was accidentally widened to reach it.
    for method in ["GET", "PUT", "PATCH", "DELETE"] {
        let answer = call(
            &world,
            method,
            &format!("/console/pending/{}/decide", "ab".repeat(32)),
            None,
            &bearer(),
        )
        .await;
        assert_eq!(
            answer.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} on the decision route was routed somewhere"
        );
    }
}

#[tokio::test]
async fn a_decision_over_a_request_the_kernel_never_queued_is_refused_by_the_console() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = jcs::object_hash(&request).expect("hashing");
    let decision = world.decide(&request, "approve", None, &world.root);

    // Never parked, so there is nothing to answer. The console cannot be used to mint a decision
    // for a request the kernel has not seen.
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.body);
}

#[tokio::test]
async fn an_approver_who_is_not_the_requesters_key_but_is_the_requesters_subject_is_refused() {
    // §06 §5 prohibits self-approval over the *subject*, not only the keypair: a human holding a
    // second key is still one human, and "escalation terminates at a named human" is about the
    // person. Here the root `human:ivan` asks, and then answers with the same root key's subject.
    let world = world().await;
    let requester = TestKey::new(0x21, &world.root.subject);
    let draft = world
        .effect(
            "github.create_issue",
            "consequential",
            json!({
                "identity": { "subject": world.root.subject.clone(), "key": requester.id.as_str() }
            }),
        )
        .await;
    let request = world.action_request(&Ask {
        requester: &requester,
        component: "gateway",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "github.create_issue",
        target: draft["execution"]["target"].as_str().expect("target"),
        args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
    });
    let request_hash = park(&world, &request).await;

    let decision = world.decide(&request, "approve", None, &world.root);
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-self-approval")
    );
}

#[tokio::test]
async fn a_mandate_holding_human_who_is_the_requesters_subject_is_refused_by_the_console() {
    // The same prohibition as the test above, against the *other* approver kind §06 §5 names: "a
    // human holding a mandate whose scope includes the action being approved". Resolving an
    // approver's subject through the root set alone cannot see that kind at all, so a person with
    // two mandated keys — neither of them a root key — could answer their own request.
    let world = world().await;
    let requester = TestKey::new(0x27, &world.root.subject);
    let approver = TestKey::new(0x28, &world.root.subject);
    let mandate = grant_to(&world, &requester, "0000000000000000000000000000ac01").await;
    grant_to(&world, &approver, "0000000000000000000000000000ac02").await;

    let draft = world
        .effect(
            "github.create_issue",
            "consequential",
            json!({
                "identity": { "subject": requester.subject, "key": requester.id.as_str() }
            }),
        )
        .await;
    let request = world.action_request(&Ask {
        requester: &requester,
        component: "gateway",
        mandate_ref: &mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "github.create_issue",
        target: draft["execution"]["target"].as_str().expect("target"),
        args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
    });
    let request_hash = park(&world, &request).await;

    let decision = world.decide(&request, "approve", None, &approver);
    let answer = decide_in_console(&world, &request_hash, &decision).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-self-approval")
    );
}

/// A standing mandate granted to a second key of a human subject, wide enough for `github.*`.
async fn grant_to(world: &World, holder: &TestKey, nonce: &str) -> String {
    world
        .grant_standing(
            nonce,
            json!({
                "grantee": { "subject": holder.subject, "key": holder.id.as_str() },
                "not-after": "2026-09-01T00:00:00.000Z"
            }),
        )
        .await
}

#[tokio::test]
async fn an_approval_decided_after_the_request_expired_is_refused() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    let request_hash = park(&world, &request).await;

    // The request's window closes at 17:00; the human answers at 18:00. §06 §2 step (8).
    let late = world.root.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "gate-decision",
        "request-hash": request_hash,
        "decision": "approve",
        "decided-at": "2026-07-26T18:00:00.000Z",
        "not-after": "2026-07-26T18:15:00.000Z",
        "single-use": true,
        "reason": Value::Null
    }));
    let answer = decide_in_console(&world, &request_hash, &late).await;
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-request-expired")
    );
}

#[tokio::test]
async fn the_queue_says_when_a_request_has_timed_out_rather_than_leaving_it_answerable() {
    let world = world().await;
    let (_, request) = draft_and_request(&world, "github.create_issue").await;
    park(&world, &request).await;

    // §06 §4.6: a timed-out gate is a block, never an allow, and an implementation MUST NOT provide
    // an "approve on timeout" option. The page must not present a dead request as live.
    world.clock.advance_seconds(9 * 3600);
    let page = get(&world, "/console/pending").await;
    assert!(
        page.body.contains("expired; a timed-out gate is a block"),
        "{}",
        page.body
    );
}

// -- the approver-flood bound (spec 09 section 7) -------------------------------------------------

/// Build a distinct action request per call, so each one is a genuinely new question.
async fn request_number(world: &World, index: usize) -> Value {
    let draft = world
        .effect("github.create_issue", "consequential", json!({}))
        .await;
    world.action_request(&Ask {
        requester: &world.agent,
        component: "gateway",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "github.create_issue",
        target: &format!("repo:acme/flood-{index}"),
        args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
    })
}

#[tokio::test]
async fn one_subject_cannot_grow_the_queue_without_bound() {
    // §09 §7: "approval fatigue is an availability attack: an adversary that generates many
    // gate-worthy actions can train an approver to click through … the kernel MUST rate-limit gate
    // requests per subject per interval".
    let world = world().await;
    let cap = world.kernel.config.gate_rate_limit.per_subject as usize;

    for index in 0..cap {
        let request = request_number(&world, index).await;
        let answer = post_json(&world, "/v1/gate/requests", &request).await;
        assert_eq!(
            answer.status,
            StatusCode::CREATED,
            "request {index} below the cap was refused: {}",
            answer.body
        );
    }

    let over = request_number(&world, cap).await;
    let answer = post_json(&world, "/v1/gate/requests", &over).await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        answer.body
    );
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-rate-limited")
    );

    // Refusing the request refused nobody's action: nothing was applied, and the call the request
    // was for is still gated and still blocked. What was refused is the queue growth.
    let queued = get(&world, "/v1/gate/requests?answered=false").await;
    assert_eq!(queued.status, StatusCode::OK, "{}", queued.body);

    // And the window is a window: once it has passed, the same subject is answerable again. A cap
    // that never released would be a subject-level denial of service wearing a rate limit's name.
    world
        .clock
        .advance_seconds(world.kernel.config.gate_rate_limit.window_seconds + 1);
    let later = request_number(&world, cap + 1).await;
    let answer = post_json(&world, "/v1/gate/requests", &later).await;
    assert_eq!(answer.status, StatusCode::CREATED, "{}", answer.body);
}

#[tokio::test]
async fn a_retry_of_an_already_queued_request_is_never_counted_against_the_cap() {
    // A component that retries after a lost response is doing the right thing. Counting the retry
    // would turn correct behaviour into the thing that trips the flood defence.
    let world = world().await;
    let cap = world.kernel.config.gate_rate_limit.per_subject;
    let request = request_number(&world, 0).await;
    for _ in 0..=cap {
        let answer = post_json(&world, "/v1/gate/requests", &request).await;
        assert!(
            answer.status == StatusCode::CREATED || answer.status == StatusCode::OK,
            "an identical retry was refused: {} {}",
            answer.status,
            answer.body
        );
    }
}

#[tokio::test]
async fn a_spike_is_surfaced_as_a_finding_and_not_as_a_longer_queue() {
    // §09 §7's second clause. A queue that is merely longer is what an approver clicks through;
    // a named finding is what makes them stop.
    let world = world().await;
    let threshold = (world.kernel.config.gate_rate_limit.per_subject / 2).max(1) as usize;

    let quiet = get(&world, "/console/pending").await;
    assert!(
        !quiet.body.contains("Gate-request spike"),
        "an ordinary queue must not be reported as a spike"
    );

    for index in 0..threshold {
        park(&world, &request_number(&world, index).await).await;
    }
    let page = get(&world, "/console/pending").await;
    assert!(page.body.contains("Gate-request spike"), "{}", page.body);
    assert!(
        page.body.contains(world.agent.subject.as_str()),
        "the finding must name the subject: {}",
        page.body
    );
}

// -- 6. the arguments an approver reads (§06 §4.4) -----------------------------------------------
//
// A parked request carried `args-hash` and nothing else, so two requests — one writing "revenue
// down 12%", one promoting a build to production — rendered identically in the console but for a
// digest, and the page told the approver to get the values from the component that built the
// request. That component is a stdio process which has already exited. Every approval was therefore
// on trust, by construction, which is the one thing this product exists not to ask for.

/// An action request whose `args-hash` commits to `arguments`, so a submission carrying them is
/// well formed. §06 §4.4 rule 4 refuses any other pairing.
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

/// What the template does to a string on its way into the page.
///
/// Spelled out rather than taken from the renderer, so that an escaping change is something this
/// test notices: the approver is told to hash the block they see, and the bytes they see are these
/// unescaped by their browser. If the two ever stop matching, the recipe on the page stops working.
fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

#[tokio::test]
async fn an_approver_can_read_the_arguments_and_recompute_the_digest_their_signature_binds() {
    let world = world().await;
    // Written with `title` first, so that the page showing `body` first is the page showing the
    // canonical form (§01 §2 sorts members) rather than whatever the submitter happened to send.
    let arguments = json!({"title": "Q3 numbers", "body": "revenue down 12%"});
    let request = request_for(&world, &arguments);
    let request_hash = park(&world, &submission(&request, &arguments)).await;

    let page = get(&world, "/console/pending").await;
    let canonical = jcs::canonicalize(&arguments).expect("canonicalizing");
    assert!(
        page.body.contains("revenue down 12%"),
        "the approver still cannot read what they are approving: {}",
        page.body
    );
    // Canonical, byte for byte, because the recipe the page gives them is to hash exactly these
    // bytes — a pretty-printed copy would hash to something else and fail for the wrong reason.
    assert!(
        page.body.contains(&escaped(&canonical)),
        "the arguments are not shown in the form that hashes: {}",
        page.body
    );
    // And the digest they compare against, in full. Shown short, it was a hash nobody could check.
    let args_hash = request["args-hash"].as_str().expect("args-hash");
    assert!(
        page.body.contains(args_hash),
        "the full args-hash is not on the page, so the check cannot be repeated: {}",
        page.body
    );
    assert!(
        !page.body.contains("The arguments were not supplied"),
        "a request that carried its arguments is being described as one that did not: {}",
        page.body
    );

    // The same for a component polling the route rather than a human reading the page.
    let fetched = get(&world, &format!("/v1/gate/requests/{request_hash}")).await;
    let body = fetched.json();
    assert_eq!(body["arguments-supplied"].as_bool(), Some(true));
    assert_eq!(body["arguments"], arguments);
}

#[tokio::test]
async fn arguments_that_are_not_what_the_request_commits_to_never_reach_an_approver() {
    // The check is the whole reason showing them is safe: without it a component could display one
    // call to a human and execute another, and the display would be worth less than the blank.
    let world = world().await;
    let approved = json!({"title": "ship it"});
    let request = request_for(&world, &approved);
    let answer = post_json(
        &world,
        "/v1/gate/requests",
        &submission(&request, &json!({"title": "ship it to production"})),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        answer.body
    );
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-arguments-hash-mismatch")
    );
    // Refused before anything was recorded: a queue holding a request whose arguments were a lie
    // would be worse than one holding none.
    let queued = get(&world, "/v1/gate/requests").await;
    assert_eq!(queued.json()["count"].as_u64(), Some(0), "{}", queued.body);
}

#[tokio::test]
async fn arguments_over_the_cap_are_refused_rather_than_stored() {
    let world = world().await;
    let arguments = json!({"a": "x".repeat(20_000)});
    let request = request_for(&world, &arguments);
    let answer = post_json(
        &world,
        "/v1/gate/requests",
        &submission(&request, &arguments),
    )
    .await;
    assert_eq!(
        answer.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        answer.body
    );
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("gate-arguments-too-large")
    );
    // A component meeting this refusal parks without the values instead — the request itself is
    // never the thing that is lost, because a park nobody can see is a gate nobody can answer.
    let bare = post_json(&world, "/v1/gate/requests", &request).await;
    assert_eq!(bare.status, StatusCode::CREATED, "{}", bare.body);
}

#[tokio::test]
async fn a_call_that_took_no_arguments_is_not_rendered_as_one_nobody_described() {
    // §06 §4.4 rule 8. "The component did not tell us" and "the call took no arguments" are
    // different facts about what is being approved, and a page that renders them alike is telling
    // the approver something it does not know.
    let world = world().await;
    let empty = json!({});
    let request = request_for(&world, &empty);
    park(&world, &submission(&request, &empty)).await;
    let page = get(&world, "/console/pending").await;
    assert!(
        !page.body.contains("The arguments were not supplied"),
        "a call that took no arguments is being shown as one whose arguments are unknown: {}",
        page.body
    );

    // And the contrast, in the same world: a submission that carried none says so.
    let (_, undescribed) = draft_and_request(&world, "github.close_issue").await;
    park(&world, &undescribed).await;
    let page = get(&world, "/console/pending").await;
    assert!(
        page.body.contains("The arguments were not supplied"),
        "a request with no arguments does not say so: {}",
        page.body
    );
}

#[tokio::test]
async fn a_later_submission_cannot_add_arguments_an_approver_never_saw() {
    // §06 §4.4 rule 7 over §4.3 rule 5: the queue is append-only, and a request whose displayed
    // arguments could appear after a human read it is not the request they read.
    let world = world().await;
    let arguments = json!({"title": "ship it"});
    let request = request_for(&world, &arguments);
    let request_hash = park(&world, &request).await;

    let again = post_json(
        &world,
        "/v1/gate/requests",
        &submission(&request, &arguments),
    )
    .await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
    assert_eq!(again.json()["idempotent"].as_bool(), Some(true));

    let fetched = get(&world, &format!("/v1/gate/requests/{request_hash}")).await;
    assert_eq!(
        fetched.json()["arguments-supplied"].as_bool(),
        Some(false),
        "the second submission wrote values into a request already in the queue: {}",
        fetched.body
    );
}

#[tokio::test]
async fn the_arguments_go_when_the_request_can_no_longer_be_answered() {
    // §06 §4.4 rule 7. An expired request is refused a decision by §06 §2 step (8), so values kept
    // past that instant are readable only by someone who cannot act on them — and the queue is not
    // a place for a component's unsigned bytes to accumulate indefinitely.
    let world = world().await;
    let arguments = json!({"body": "revenue down 12%"});
    let request = request_for(&world, &arguments);
    let request_hash = park(&world, &submission(&request, &arguments)).await;

    let store = world.ingest().store();
    let before = store
        .erase_expired_gate_arguments(&world.clock.now())
        .await
        .expect("the sweep runs");
    assert_eq!(before, 0, "a live request lost its arguments");

    world.clock.advance_seconds(43_200);
    let page = get(&world, "/console/pending").await;
    assert!(
        !page.body.contains("revenue down 12%"),
        "an expired request is still serving its arguments: {}",
        page.body
    );
    let fetched = get(&world, &format!("/v1/gate/requests/{request_hash}")).await;
    assert_eq!(fetched.json()["arguments-supplied"].as_bool(), Some(false));

    let erased = store
        .erase_expired_gate_arguments(&world.clock.now())
        .await
        .expect("the sweep runs");
    assert_eq!(erased, 1, "the values were still in the store");

    // The request itself remains, with the digest that binds it: erasing the preimage changes no
    // signed byte, which is why this is not §04 §5 decay and owes no checkpoint.
    let after = get(&world, &format!("/v1/gate/requests/{request_hash}")).await;
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(after.json()["request"]["args-hash"], request["args-hash"]);
}

#[tokio::test]
async fn a_submission_carrying_a_member_nothing_reads_is_refused() {
    // The same strictness the action request gets, for the same reason: a member this kernel does
    // not understand is a member the approver was never shown.
    let world = world().await;
    let arguments = json!({"title": "ship it"});
    let request = request_for(&world, &arguments);
    let mut body = submission(&request, &arguments);
    body["approved"] = Value::Bool(true);
    let answer = post_json(&world, "/v1/gate/requests", &body).await;
    assert_eq!(
        answer.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        answer.body
    );
    assert_eq!(
        answer.json()["reason-code"].as_str(),
        Some("schema-unknown-member")
    );
}

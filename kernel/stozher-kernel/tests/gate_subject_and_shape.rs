//! The effect path's half of `spec/06 §5` and `spec/06 §1.1`.
//!
//! # Why a second gate test file
//!
//! `gate_queue_and_console_decisions.rs` attacks the *queue* and the *console form*: the surfaces a
//! human touches. Everything here attacks the surface a **component** touches — `POST /v1/ingest` —
//! where an `authorization` object arrives already assembled, having never been submitted to the
//! queue and therefore never having met [`stozher_kernel::gatequeue::validate`].
//!
//! That asymmetry was the bug. §06 §5 states self-approval as two conjoined MUSTs — the key *and*
//! the subject — but only the key half ran on the effect path, and §06 §1.1's "unknown members MUST
//! be rejected" ran only on the route nobody has to use. An approval that never enters the queue is
//! the cheapest thing in the protocol to construct: it is nine JSON members and one signature.

use serde_json::{Value, json};
use stozher_core::jcs;
use stozher_testkit::{Ask, TestKey, World, revise, world};

/// A standing mandate granted to `holder`, wide enough for the fixtures' `github.*` effects.
///
/// The grantee is a **human** subject on purpose: §03 §6 refuses a root key used as an *agent*
/// grantee (`mandate.rs`'s `root-key-used-as-agent`), and permits exactly this — a person acting
/// under authority someone else granted them, which §05 §5's own worked example does.
async fn standing_mandate_for(world: &World, holder: &TestKey, nonce: &str) -> String {
    world
        .grant_standing(
            nonce,
            json!({
                "grantee": { "subject": holder.subject, "key": holder.id.as_str() },
                "not-after": "2026-09-01T00:00:00.000Z",
                "scope": {
                    "components": ["gateway"],
                    "actions": ["github.*"],
                    "classes": ["read", "benign", "consequential"],
                    "resources": ["repo:acme/backend"]
                }
            }),
        )
        .await
}

/// A `consequential` effect signed by `requester`, carrying an approval signed by `approver`.
///
/// Nothing here is parked. The request object is built, hashed, signed over and embedded — the
/// whole authorization exists only inside the envelope, which is the shape §06 §1.3 explicitly
/// blesses ("the request is embedded verbatim so that any verifier … can recompute").
async fn effect_approved_by(
    world: &World,
    requester: &TestKey,
    mandate: &str,
    approver: &TestKey,
) -> Value {
    let action = "github.create_issue";
    let draft = world
        .effect(
            action,
            "consequential",
            json!({
                "identity": { "subject": requester.subject, "key": requester.id.as_str() },
                "mandate-ref": mandate
            }),
        )
        .await;
    let request = world.action_request(&Ask {
        requester,
        component: "gateway",
        mandate_ref: mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action,
        target: draft["execution"]["target"].as_str().expect("target"),
        args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
    });
    let decision = world.decide(&request, "approve", None, approver);
    revise(
        &draft,
        json!({ "authorization": { "request": request, "decision": decision } }),
        requester,
    )
}

// -- SEC-1: the subject half of §06 §5, on the path every effect takes ---------------------------

#[tokio::test]
async fn a_root_may_not_approve_an_effect_its_own_subject_requested() {
    // The attack §06 §5's second MUST exists to stop, run against `POST /v1/ingest` rather than the
    // console. `human:ivan` is an enrolled root holding `K_root`. The same human takes a second
    // keypair `K_sub` and a mandate as a human — both permitted — and asks under `K_sub`. The key
    // comparison of step (4) passes, because `K_root != K_sub`. One person has approved their own
    // action, and no human other than them ever saw it.
    let world = world().await;
    let second_key = TestKey::new(0x21, &world.root.subject);
    let mandate =
        standing_mandate_for(&world, &second_key, "0000000000000000000000000000ab01").await;

    let envelope = effect_approved_by(&world, &second_key, &mandate, &world.root).await;
    world.reject(&envelope, &[], "gate-self-approval").await;
}

// -- SEC-2: the second approver kind §06 §5 names ------------------------------------------------

#[tokio::test]
async fn a_mandate_holding_human_may_not_approve_their_own_subjects_effect() {
    // §06 §5 admits two approver kinds: "an enrolled human root, or a human holding a mandate whose
    // scope includes the action being approved". Resolving the approver's *subject* through the root
    // set alone therefore sees only half of them — and the half it cannot see is exactly the half a
    // deployment adds when it stops wanting every approval to come from a root.
    //
    // Here neither key is a root: both are mandated keys of `human:ivan`, whom the baseline policy
    // names as the approver for `consequential`.
    let world = world().await;
    let requester = TestKey::new(0x22, &world.root.subject);
    let approver = TestKey::new(0x23, &world.root.subject);
    let mandate =
        standing_mandate_for(&world, &requester, "0000000000000000000000000000ab02").await;
    standing_mandate_for(&world, &approver, "0000000000000000000000000000ab03").await;

    let envelope = effect_approved_by(&world, &requester, &mandate, &approver).await;
    world.reject(&envelope, &[], "gate-self-approval").await;
}

#[tokio::test]
async fn a_mandate_holding_human_may_still_approve_another_subjects_effect() {
    // The companion to the two refusals above: the subject check must refuse *self*-approval, not
    // approval. This key is a root's second keypair holding a mandate — §06 §5's second approver
    // kind, and the very key the SEC-2 fix teaches the kernel to resolve a subject for. The
    // requester is `agent:gateway/dev`, a different subject, so the signature is the one the spec
    // wants. If this test ever fails, the fix has stopped being a self-approval check and become an
    // approver check.
    let world = world().await;
    let approver = TestKey::new(0x26, &world.root.subject);
    standing_mandate_for(&world, &approver, "0000000000000000000000000000ab06").await;

    let envelope = world
        .gated_effect_approved_by(&approver, "github.create_issue")
        .await;
    world.accept(&envelope, &[]).await;
}

// -- SEC-4: §06 §1.1's closed member set, on the embedded request --------------------------------

#[tokio::test]
async fn an_embedded_action_request_carrying_an_unknown_member_is_refused() {
    // §06 §1.1: "All members are REQUIRED. Unknown members MUST be rejected." The queue route
    // enforced that; an authorization arriving inside an effect envelope met no shape check at all,
    // so the member the approver was never shown travelled with the object their signature covers.
    //
    // The request is re-hashed and the decision re-signed, so this fixture fails for the reason
    // under test rather than for a broken hash.
    let world = world().await;
    let effect = world.gated_effect("github.create_issue", json!({})).await;
    let smuggled = revise(
        &effect,
        json!({ "authorization": { "request": { "approved": true } } }),
        &world.agent,
    );
    let sealed = world.reseal_authorization(&smuggled);

    // The hash really does still cover the rewritten body — the refusal is the shape check, not a
    // mismatch that would have been caught anyway.
    let request = &sealed["authorization"]["request"];
    assert_eq!(
        sealed["authorization"]["decision"]["request-hash"].as_str(),
        Some(jcs::object_hash(request).expect("hashing").as_str())
    );
    world.reject(&sealed, &[], "schema-unknown-member").await;
}

#[tokio::test]
async fn an_embedded_action_request_missing_its_nonce_is_refused() {
    // The other half of the same sentence. Without `nonce` an approval of one request is an approval
    // of every otherwise identical one (§06 §1.1), which is precisely the property the embedded
    // object was never checked for.
    let world = world().await;
    let effect = world.gated_effect("github.create_issue", json!({})).await;
    let mut request = effect["authorization"]["request"]
        .as_object()
        .expect("a request object")
        .clone();
    request.remove("nonce");
    let sealed = world.reseal_authorization(&with_request(&effect, Value::Object(request)));
    world.reject(&sealed, &[], "schema-missing-member").await;
}

/// Replace `authorization.request` outright.
///
/// `revise` deep-merges, which can add a member and can never remove one — so a fixture testing a
/// *missing* member has to swap the whole object.
fn with_request(envelope: &Value, request: Value) -> Value {
    let mut map = envelope.as_object().expect("an envelope object").clone();
    let mut authorization = map["authorization"]
        .as_object()
        .expect("an authorization object")
        .clone();
    authorization.insert("request".to_owned(), request);
    map.insert("authorization".to_owned(), Value::Object(authorization));
    Value::Object(map)
}

#[tokio::test]
async fn an_approval_whose_not_after_is_not_a_timestamp_is_refused() {
    // Steps (8) and (9) of §06 §2 compare timestamps as strings. That is sound only while every
    // string compared is a timestamp: `"z"` sorts above every real one, so an approval bounded by it
    // is bounded by nothing and step (9) becomes vacuous. Nothing validated this member — neither
    // `envelope::validate`, which does not descend into `authorization`, nor the queue, which this
    // envelope never entered.
    let world = world().await;
    let effect = world.gated_effect("github.create_issue", json!({})).await;
    let forever = revise(
        &effect,
        json!({ "authorization": { "decision": { "not-after": "z" } } }),
        &world.agent,
    );
    let sealed = world.reseal_authorization(&forever);
    world.reject(&sealed, &[], "encoding-bad-timestamp").await;
}

#[tokio::test]
async fn an_embedded_decision_carrying_an_unknown_member_is_refused() {
    // §06 §1.2's shape is as closed as §1.1's, and for the same reason: a member this kernel does
    // not understand is a member nobody was shown.
    let world = world().await;
    let effect = world.gated_effect("github.create_issue", json!({})).await;
    let smuggled = revise(
        &effect,
        json!({ "authorization": { "decision": { "single-use-override": false } } }),
        &world.agent,
    );
    let sealed = world.reseal_authorization(&smuggled);
    world.reject(&sealed, &[], "schema-unknown-member").await;
}

// -- SEC-6: the conformance run a registration leans on -------------------------------------------

#[tokio::test]
async fn a_conformance_run_is_itself_a_root_approved_claim() {
    // §08 §3.3 makes registration conditional on a green conformance run, and the kernel verifies
    // that claim by looking for an applied `kernel.conformance_run` envelope with a matching
    // `args-hash`. The root who approves the *registration* is therefore approving on the strength
    // of a claim that only had to exist. Whoever can emit the run decides what the root is agreeing
    // to, so the run belongs on the same footing as the registration it unlocks (§05 §5.2's rule
    // that policy cannot lower the bar on the mechanism that enforces policy).
    let world = world().await;
    let manifest = stozher_testkit::manifest_object("github", "1.0.0", json!({}));
    let hash = jcs::object_hash(&manifest).expect("manifest hash");
    let unapproved = world
        .effect(
            "kernel.conformance_run",
            "benign",
            json!({ "execution": { "target": format!("manifest:{hash}"), "args-hash": hash } }),
        )
        .await;
    world
        .reject(&unapproved, &[], "gate-authorization-missing")
        .await;
}

//! An envelope that says the action did not apply MUST NOT apply it.
//!
//! Found by external security review on 2026-08-04, as Finding 1 (critical), and reproduced against
//! this kernel three ways before being believed. The composition, in two rules that are each
//! defensible alone:
//!
//! * `ingest.rs` waives the approval requirement when `execution.outcome` is not `applied` or
//!   `failed` — correct for an ordinary effect, where recording that a human said *no* must not
//!   itself require an approval signature;
//! * `store.rs::write_projections` applies `enroll_root`, `retire_root`, `stream_resume`, the
//!   manifest and the policy **without reference to `outcome` at all**.
//!
//! For an ordinary effect the second is harmless: the effect happened in the outside world and the
//! envelope is only its record. For a root-approved action it is the entire security property,
//! because *the effect is the row the kernel writes*. So the kernel read "this did not apply",
//! waived the root approval on that basis, and then applied it — with no approval signature of any
//! kind, and in the `resume_stream` case with no root key involved anywhere.
//!
//! `def2_mandate_swap.rs::def2_a_wedged_stream_is_resumed_only_by_a_root_signed_operator_act`
//! asserts precisely that this is impossible. It passed throughout, because its negative fixture
//! sets `outcome: "applied"` — a negative test that pins one member to the value the bypass needs
//! to be different is a negative test with a hole exactly the shape of the attack.

use serde_json::{Value, json};
use stozher_kernel::clock::Clock;
use stozher_testkit::{EFFECT_STREAM, TestKey, World, mandate_object, revise, world};

/// Publish a mandate object the way the gateway does — the wedging act, borrowed from `def2`.
async fn publish_mandate(world: &World, mandate: &Value) -> Value {
    let (seq, prev) = world.head(EFFECT_STREAM).await;
    world.agent.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "emitted-at": world.clock.now(),
        "stream": EFFECT_STREAM,
        "seq": seq,
        "prev-hash": prev,
        "identity": {
            "subject": world.agent.subject,
            "key": world.agent.id.as_str(),
            "component": "gateway"
        },
        "mandate": mandate
    }))
}

async fn refused_object_hash(world: &World, stream: &str, seq: u64) -> String {
    let rejections = world
        .ingest()
        .store()
        .rejections(None, 50)
        .await
        .expect("rejections");
    rejections
        .iter()
        .find(|r| r["claimed-stream"] == json!(stream) && r["claimed-seq"] == json!(seq))
        .and_then(|r| r["object-hash"].as_str())
        .expect("a rejection is recorded at the wedged position")
        .to_owned()
}

/// A `kernel.resume_stream` effect with **no `authorization` at all**, reporting `outcome`.
///
/// The `outcome` is the parameter because it is the attack: everything else here is the same
/// document the legitimate operator act carries.
async fn unauthorized_resume(
    world: &World,
    stream: &str,
    resume_seq: u64,
    bridge: &str,
    outcome: &str,
) -> (Value, Vec<Value>) {
    let document = json!({
        "stream": stream,
        "resume-seq": resume_seq,
        "refused-object-hash": bridge,
        "reason-code": "mandate-standing-lifetime-exceeded"
    });
    let hash = stozher_core::jcs::object_hash(&document).expect("resume document hash");
    let now = world.clock.now();
    let envelope = world
        .core_envelope(
            "effect",
            json!({
                "mandate-ref": world.standing_mandate,
                "policy-version": world.policy_version,
                "classification": "consequential",
                "execution": {
                    "action": "kernel.resume_stream",
                    "target": format!("stream:{stream}"),
                    "args-hash": hash,
                    "outcome": outcome,
                    "started-at": now,
                    "finished-at": now
                },
                "evidence": {
                    "schema": "kernel.resume_stream.v1",
                    "media-type": "application/json",
                    "payload-hash": hash,
                    "retain-until": "2026-08-01T00:00:00.000Z"
                }
            }),
        )
        .await;
    let payload = json!({
        "payload-hash": hash,
        "media-type": "application/json",
        "payload": document
    });
    (envelope, vec![payload])
}

/// Drive a stream into the refused state and return the position and its bridge hash.
async fn wedge(world: &World) -> (u64, String) {
    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    let replacement = world.root.sign(&mandate_object(
        &world.root,
        &world.agent,
        "000000000000000000000000000000d3",
        json!({ "not-after": "2027-06-01T00:00:00.000Z" }),
    ));
    let wedging = publish_mandate(world, &replacement).await;
    let wedged_at = wedging["seq"].as_u64().expect("seq");
    world
        .reject(&wedging, &[], "mandate-standing-lifetime-exceeded")
        .await;
    let bridge = refused_object_hash(world, EFFECT_STREAM, wedged_at).await;
    (wedged_at, bridge)
}

#[tokio::test]
async fn a_resume_reporting_a_non_applied_outcome_does_not_resume_anything() {
    // The reproduction, run for each outcome the schema admits and the waiver accepts. `denied` was
    // the one the review used; the other two are here because a fix that special-cases one string
    // is not a fix.
    for outcome in ["denied", "blocked", "attempted"] {
        let world = world().await;
        let (wedged_at, bridge) = wedge(&world).await;

        // The emitter's next envelope, sitting one past the refused position: refused until an
        // operator with a root signature bridges the gap. This is the thing the attack buys.
        let draft = world.effect("github.get_file", "read", json!({})).await;
        let after = revise(
            &draft,
            json!({ "seq": wedged_at + 1, "prev-hash": bridge }),
            &world.agent,
        );
        world.reject(&after, &[], "chain-seq-gap").await;

        let (attack, payloads) =
            unauthorized_resume(&world, EFFECT_STREAM, wedged_at, &bridge, outcome).await;
        let _ = world.submit(&attack, &payloads).await;

        assert!(
            world
                .ingest()
                .store()
                .stream_resume(EFFECT_STREAM, wedged_at)
                .await
                .expect("reading the resume set")
                .is_none(),
            "outcome {outcome:?}: an unapproved, unsigned resume authorized a gap — the kernel \
             waived the root approval because nothing applied, and then applied it"
        );

        // The property that actually matters to a reader: not "a row is absent" but "the wedge
        // still holds". A resume that writes no row and lifts the wedge anyway is the same defect.
        world.reject(&after, &[], "chain-seq-gap").await;
    }
}

/// A mandate from the *second* root to the first, so a root acting directly has one to cite.
///
/// Copied from `root_enrollment.rs` rather than shared: §03 §1 forbids self-grant, which is exactly
/// why §03 §6 makes a root change need two enrolled roots, and the fixture has to do it the same way
/// the legitimate path does or the reproduction is testing a different thing.
async fn mandate_between_roots(world: &World) -> String {
    let mandate = world.second_root.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "mandate-kind": "standing",
        "grantor": {
            "subject": world.second_root.subject,
            "key": world.second_root.id.as_str(),
            "role": "human"
        },
        "grantee": { "subject": world.root.subject, "key": world.root.id.as_str() },
        "issued-at": stozher_testkit::NOW,
        "not-before": stozher_testkit::NOW,
        "not-after": "2026-07-27T00:00:00.000Z",
        "parent": Value::Null,
        "max-depth": 2,
        "scope": {
            "components": ["kernel"],
            "actions": ["kernel.*"],
            "classes": ["read", "benign", "consequential"],
            "resources": ["*"]
        },
        "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    }));
    let id = stozher_core::signed::object_id(&mandate).expect("mandate id");
    let (seq, prev) = world.head(stozher_testkit::CORE_STREAM).await;
    let envelope = world.root.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "emitted-at": world.clock.now(),
        "stream": stozher_testkit::CORE_STREAM,
        "seq": seq,
        "prev-hash": prev,
        "identity": {
            "subject": world.root.subject,
            "key": world.root.id.as_str(),
            "component": "kernel"
        },
        "mandate": mandate
    }));
    world.accept(&envelope, &[]).await;
    id
}

#[tokio::test]
async fn an_enrolment_reporting_a_non_applied_outcome_does_not_enrol_a_root() {
    // §03 §6 makes this the two-human act: a root asks and the *other* root answers. Under the
    // bypass one key sufficed — enrol an accomplice with `outcome: "denied"` and no approval, then
    // retire everyone else the same way, and the deployment's trust anchor is yours alone.
    //
    // The signer here is `world.root`, an enrolled root, because `validate_root_change` refuses any
    // other signer outright (`mandate-root-not-enrolled`). An earlier draft of this test signed as
    // an ordinary agent, passed with the fix reverted, and proved nothing — the root set was
    // unchanged for a reason that had nothing to do with the defect.
    let world = world().await;
    let mandate = mandate_between_roots(&world).await;
    let third = TestKey::new(0x33, "human:accomplice");

    let payload = json!({ "subject": "human:accomplice", "key": third.id.as_str() });
    let args_hash = stozher_core::jcs::object_hash(&payload).expect("payload hash");
    let target = format!("root:{}", third.id.as_str());
    let envelope = world
        .effect_as(
            &world.root,
            "kernel.enroll_root",
            "consequential",
            json!({
                // Everything the legitimate act carries, except the approval — and `outcome`, which
                // is what makes the missing approval acceptable to the gate rule.
                "execution": { "target": target, "args-hash": args_hash, "outcome": "denied" },
                "evidence": {
                    "schema": "kernel.enroll_root.v1",
                    "media-type": "application/json",
                    "payload-hash": args_hash,
                    "retain-until": "2027-07-01T00:00:00.000Z"
                },
                "mandate-ref": mandate,
                "identity": { "component": "kernel" }
            }),
        )
        .await;
    let payloads = vec![json!({
        "payload-hash": args_hash,
        "media-type": "application/json",
        "payload": payload
    })];

    let before = world
        .ingest()
        .store()
        .roots_at(world.clock.now().as_str())
        .await
        .expect("the root set");
    let _ = world.submit(&envelope, &payloads).await;
    let after = world
        .ingest()
        .store()
        .roots_at(world.clock.now().as_str())
        .await
        .expect("the root set");

    assert_eq!(
        before, after,
        "the root set changed on an envelope carrying no approval of any kind — the gate was \
         waived because the envelope said the enrolment did not apply, and it was applied"
    );
}

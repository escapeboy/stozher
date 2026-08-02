//! Enrolling and retiring a human root — `spec/03 §6`.
//!
//! # Why this file exists at all
//!
//! The root set is the deployment's trust anchor: `ROOT_APPROVED_ACTIONS` are approved by an
//! enrolled root whatever policy says, so who is in this set decides who can publish policy,
//! register a component, run a conformance attestation, and change the set again. Until this file
//! there was **no test of enrolling one**, and no command that produced such an envelope — so the
//! path was specified, implemented, and never once exercised.
//!
//! What that hid is the subject. `roots` carries `(key, subject)`, and the *subject* is what §06 §5's
//! self-approval prohibition is evaluated over: "a human holding a second key is still the same
//! human". A root enrolled by envelope was recorded with its own `execution.target` as its
//! subject — the string `root:ed25519:<hex>` — so the one mechanism for giving a human a second
//! enrolled key was also the mechanism that made the prohibition unable to see it was the same
//! human. Nothing contradicted it: the configured roots of `Config` are seeded with real subjects,
//! and every existing test uses those.

use serde_json::{Value, json};
use stozher_core::signed;
use stozher_kernel::clock::Clock;
use stozher_testkit::{Ask, TestKey, World, world};

const NEW_ROOT: &str = "human:third";

/// A mandate from the *second* root to the first, so a root acting directly has one to cite.
///
/// §03 §1 forbids self-grant and effect kinds require `mandate-ref`, which is exactly why §03 §6
/// says changing the root set needs two enrolled roots. The fixture has to do it the same way.
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
    let id = signed::object_id(&mandate).expect("mandate id");
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

/// The evidence a root change carries: which key, and — for an enrolment — whose it is.
fn enrollment_evidence(subject: &str, key: &TestKey) -> Value {
    json!({ "subject": subject, "key": key.id.as_str() })
}

/// An `kernel.enroll_root` effect, signed by an enrolled root under a mandate from the other one.
async fn enrol(world: &World, subject: &str, new_root: &TestKey, mandate: &str) -> (Value, Value) {
    let payload = enrollment_evidence(subject, new_root);
    let args_hash = stozher_core::jcs::object_hash(&payload).expect("payload hash");
    let target = format!("root:{}", new_root.id.as_str());
    let request = world.action_request(&Ask {
        requester: &world.root,
        component: "kernel",
        mandate_ref: mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "kernel.enroll_root",
        target: &target,
        args_hash: &args_hash,
    });
    // §06 §5 over the subject: the first root asks, so the *second* one answers. `World::authorize`
    // signs with `root`, which here would be the requester approving itself.
    let decision = world.decide(&request, "approve", None, &world.second_root);
    let authorization = json!({ "request": request, "decision": decision });
    let envelope = world
        .effect_as(
            &world.root,
            "kernel.enroll_root",
            "consequential",
            json!({
                "execution": { "target": target, "args-hash": args_hash },
                "evidence": {
                    "schema": "kernel.enroll_root.v1",
                    "media-type": "application/json",
                    "payload-hash": args_hash,
                    "retain-until": "2027-07-01T00:00:00.000Z"
                },
                "mandate-ref": mandate,
                // The kernel's own action, emitted by the kernel component — `effect_as` defaults
                // to `gateway`, which the between-roots mandate deliberately does not cover.
                "identity": { "component": "kernel" },
                "authorization": authorization
            }),
        )
        .await;
    (
        envelope,
        json!({
            "payload-hash": args_hash,
            "media-type": "application/json",
            "payload": payload
        }),
    )
}

#[tokio::test]
async fn an_enrolled_root_is_recorded_under_the_name_of_the_human_it_belongs_to() {
    let world = world().await;
    let mandate = mandate_between_roots(&world).await;
    let third = TestKey::new(0x33, NEW_ROOT);
    let (envelope, payload) = enrol(&world, NEW_ROOT, &third, &mandate).await;
    world.accept(&envelope, &[payload]).await;

    let roots = world
        .ingest()
        .store()
        .roots_at(&world.clock.now())
        .await
        .expect("the root set");
    let recorded = roots
        .iter()
        .find(|(key, _)| key == &third.id)
        .map(|(_, subject)| subject.as_str());
    assert_eq!(
        recorded,
        Some(NEW_ROOT),
        "the root set records the enrolled key under {:?}, not the human it belongs to",
        recorded.unwrap_or("nothing at all")
    );
}

#[tokio::test]
async fn an_enrolment_that_does_not_name_a_human_is_refused() {
    // The subject is not decoration. It is the value §06 §5's self-approval prohibition compares,
    // so a root enrolled under `root:ed25519:…` — or under an agent subject — is a root the rule
    // cannot recognise as the same human who already holds a key.
    let world = world().await;
    let mandate = mandate_between_roots(&world).await;
    for name in ["agent:not-a-human", "root:ed25519:whatever", ""] {
        let third = TestKey::new(0x34, "human:fourth");
        let (envelope, payload) = enrol(&world, name, &third, &mandate).await;
        world
            .reject(&envelope, &[payload], "root-enrollment-malformed")
            .await;
    }
}

#[tokio::test]
async fn an_enrolment_whose_evidence_is_not_supplied_is_refused() {
    // A referenced payload may legitimately be absent at ingest — that is what decay looks like.
    // Not here: the subject is *only* in the payload, so accepting the envelope without it would
    // record a root under no name and leave nothing to reconstruct it from.
    let world = world().await;
    let mandate = mandate_between_roots(&world).await;
    let third = TestKey::new(0x35, "human:fifth");
    let (envelope, _) = enrol(&world, "human:fifth", &third, &mandate).await;

    world
        .reject(&envelope, &[], "root-enrollment-malformed")
        .await;
}

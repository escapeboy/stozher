//! The ceremony, and what it must and must not allow.
//!
//! §05 §5.2 permits exactly one bootstrap carve-out and bounds it tightly. These tests hold the
//! bound: the first policy exists only because a named human signed its exact document hash, and the
//! carve-out cannot be used for anything else, at any other position, ever again.

use serde_json::{Value, json};
use stozher_testkit::{Ask, CORE_STREAM, NOW, world};

#[tokio::test]
async fn the_ceremony_publishes_a_policy_a_human_signed() {
    let world = world().await;

    let current = world
        .ingest()
        .store()
        .current_policy()
        .await
        .expect("reading the current policy")
        .expect("a policy is in force after bootstrap");
    assert_eq!(current["policy-version"].as_str(), Some("2026.07.1"));
    assert_eq!(current["profile"].as_str(), Some("baseline-conservative"));

    // §05 §5.4: a document served as current has a corresponding appended envelope. The ceremony
    // resolves the specification's circularity without exempting itself from that requirement.
    let published = world
        .ingest()
        .store()
        .query(&stozher_kernel::store::EnvelopeQuery {
            stream: Some(CORE_STREAM),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("querying the core stream");
    let change = published
        .iter()
        .find(|record| record["envelope"]["kind"].as_str() == Some("policy-change"))
        .expect("the policy change is in the chain");
    assert_eq!(change["envelope"]["seq"].as_u64(), Some(1));
    assert_eq!(
        change["envelope"]["execution"]["target"].as_str(),
        Some("policy:2026.07.1")
    );
    // The approval binds the exact bytes of the policy that took effect (§05 §5.3).
    assert_eq!(
        change["envelope"]["execution"]["args-hash"].as_str(),
        Some(
            stozher_core::jcs::object_hash(&current)
                .expect("policy hash")
                .as_str()
        )
    );
    assert_eq!(
        change["envelope"]["authorization"]["decision"]["sig"]["key"].as_str(),
        Some(world.root.id.as_str()),
        "the first policy is approved by an enrolled human root"
    );
    assert_eq!(change["human-root"].as_str(), Some(world.root.subject.as_str()));
}

#[tokio::test]
async fn the_carve_out_cannot_be_used_a_second_time() {
    let world = world().await;

    // The ceremony's positions are occupied, so nothing can take them again.
    let intruder = world
        .core_envelope("mandate", json!({ "mandate": Value::Null }))
        .await;
    match world.submit(&intruder, &[]).await {
        stozher_kernel::Outcome::Rejected { .. } => {}
        other => panic!("a malformed mandate must be refused, got {other:?}"),
    }

    // And a second policy change now goes through the ordinary gated path, not the carve-out: it is
    // refused without an approval even though it is a policy change.
    let document = world
        .policy_key
        .sign(&stozher_kernel::policy::baseline_conservative(
            "2026.07.2",
            NOW,
            &world.root.subject,
        ));
    let hash = stozher_core::jcs::object_hash(&document).expect("policy hash");
    let unapproved = world
        .core_envelope(
            "policy-change",
            json!({
                "mandate-ref": world.standing_mandate,
                "policy-version": world.policy_version,
                "classification": "consequential",
                "execution": {
                    "action": "kernel.publish_policy",
                    "target": "policy:2026.07.2",
                    "args-hash": hash,
                    "outcome": "applied",
                    "started-at": NOW,
                    "finished-at": NOW
                }
            }),
        )
        .await;
    // `policy-change` REQUIRES `authorization` in its member set, so the schema catches it first —
    // which is the point: there is no shape of policy change that lacks an approval.
    world
        .reject(&unapproved, &[], "schema-missing-member")
        .await;
}

#[tokio::test]
async fn a_second_policy_version_publishes_and_both_resolve_forever() {
    let mut world = world().await;
    let document = world
        .policy_key
        .sign(&stozher_kernel::policy::baseline_conservative(
            "2026.07.2",
            NOW,
            &world.root.subject,
        ));
    world.publish_policy(&document).await;

    let store = world.ingest().store();
    assert_eq!(
        store
            .current_policy()
            .await
            .expect("current")
            .expect("some")["policy-version"]
            .as_str(),
        Some("2026.07.2"),
        "the newest published version is the one in force"
    );
    for version in ["2026.07.1", "2026.07.2"] {
        assert!(
            store
                .policy_version(version)
                .await
                .expect("reading a version")
                .is_some(),
            "{version} must resolve forever so an envelope citing it stays interpretable"
        );
    }
}

#[tokio::test]
async fn a_policy_version_is_never_reused() {
    let world = world().await;
    let document = world
        .policy_key
        .sign(&stozher_kernel::policy::baseline_conservative(
            "2026.07.1",
            "2026-07-26T09:30:00.000Z",
            &world.root.subject,
        ));
    let hash = stozher_core::jcs::object_hash(&document).expect("policy hash");
    let authorization = world.authorize(&Ask {
        requester: &world.agent,
        component: "kernel",
        mandate_ref: &world.standing_mandate,
        policy_version: &world.policy_version,
        classification: "consequential",
        action: "kernel.publish_policy",
        target: "policy:2026.07.1",
        args_hash: &hash,
    });
    let envelope = world
        .core_envelope(
            "policy-change",
            json!({
                "mandate-ref": world.standing_mandate,
                "policy-version": world.policy_version,
                "classification": "consequential",
                "execution": {
                    "action": "kernel.publish_policy",
                    "target": "policy:2026.07.1",
                    "args-hash": hash,
                    "outcome": "applied",
                    "started-at": NOW,
                    "finished-at": NOW
                },
                "evidence": {
                    "schema": "kernel.publish_policy.v1",
                    "media-type": "application/json",
                    "payload-hash": hash,
                    "retain-until": "2027-07-26T00:00:00.000Z"
                },
                "authorization": authorization
            }),
        )
        .await;
    let payload = json!({
        "payload-hash": hash,
        "media-type": "application/json",
        "payload": document
    });
    world
        .reject(&envelope, &[payload], "policy-version-reused")
        .await;
}

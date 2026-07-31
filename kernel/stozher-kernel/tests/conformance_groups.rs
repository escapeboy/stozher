//! The three groups of `spec/08 §4` that need no live component, against a real manifest and store.
//!
//! # Which three, and why these
//!
//! §4.6 (durable objects) is decidable from the manifest alone, §4.7 (decay independence) from a
//! store holding the component's samples, and §4.2 from those samples put through the real ingest.
//! The other four have to *drive* something: §4.1 wants the component to reproduce the vector
//! corpus, §4.3 more than `max-samples` calls, §4.4 eight refusals the component signs, and §4.5 the
//! component running with the kernel unreachable. Those live in `conformance_driven_groups.rs`,
//! behind the protocol of §08 §4.8; ADR-0016 records the design.
//!
//! # The negative half is the group
//!
//! §08 §4.4's preamble — "these MUST fail, and the harness MUST fail the component if they succeed" —
//! is the whole design of a harness. So each group here is run twice: once against a conformant
//! component, and once against one built to fail exactly the check under test. A group that only ever
//! saw a good component would certify a state machine that accepts everything, and would look
//! identical to one that worked.

use serde_json::{Value, json};
use stozher_kernel::conformance::{
    GroupResult, check_decay_independence, check_durable_objects, check_per_action_emission,
};
use stozher_kernel::manifest::Manifest;
use stozher_testkit::{TestKey, manifest_object};

/// A manifest with one durable object whose `closed` transition only a human may sign.
fn conformant(overrides: Value) -> Manifest {
    let mut document = manifest_object("github", "1.0.0", json!({}));
    stozher_testkit::merge(&mut document, overrides);
    // Signed with the component key the world uses, because `Manifest::parse` requires a signature —
    // a manifest is a signed object, and a fixture that skipped that would parse something the
    // kernel never sees.
    let component = TestKey::new(0x16, "agent:github-proxy");
    Manifest::parse(&component.sign(&document)).expect("the fixture manifest parses")
}

#[test]
fn a_conformant_manifest_passes_the_durable_object_group() {
    let manifest = conformant(json!({}));
    match check_durable_objects(&manifest) {
        GroupResult::Passed { checks } => assert!(
            checks >= 3,
            "the group passed having made only {checks} assertions"
        ),
        other => panic!("a conformant manifest failed §4.6: {other:?}"),
    }
}

#[test]
fn a_manifest_declaring_no_durable_object_is_not_applicable_rather_than_passing() {
    // "There was nothing to check" and "it was checked and held" are different claims, and an
    // auditor reading the run has to be able to tell them apart.
    let manifest = conformant(json!({ "durable-objects": [] }));
    assert!(matches!(
        check_durable_objects(&manifest),
        GroupResult::NotApplicable { .. }
    ));
}

#[test]
fn a_transition_the_manifest_never_declared_is_refused() {
    // Without this probe, "the state machine accepted the sequence" is equally true of one that
    // accepts everything — which is the same as having no state machine.
    let manifest = conformant(json!({}));
    assert!(
        manifest
            .check_transition("github.ticket", "no-such-transition", "agent", None)
            .is_err(),
        "an undeclared transition was accepted"
    );
    // And an object type nobody declared, for the same reason.
    assert!(
        manifest
            .check_transition("github.nothing", "opened", "agent", None)
            .is_err()
    );
}

#[test]
fn a_human_only_transition_signed_by_an_agent_is_refused() {
    // The boundary between "an agent moved the object" and "a person did". A component that blurs it
    // makes every later record unattributable, which is the one thing this product sells. The
    // fixture declares `approved` as `signers: ["human"]`.
    let manifest = conformant(json!({}));
    assert!(
        manifest
            .check_transition("github.ticket", "approved", "human", Some("open"))
            .is_ok(),
        "a human could not sign the transition declared for humans"
    );
    assert!(
        manifest
            .check_transition("github.ticket", "approved", "agent", Some("open"))
            .is_err(),
        "a human-only transition accepted an agent key"
    );

    // And the group counts that probe: a run whose `checks` did not grow with the human-only
    // transition would be reporting an assertion it never made.
    let without_human = conformant(json!({
        "durable-objects": [{
            "object-type": "github.ticket",
            "id-kind": "ticket-id",
            "transitions": [
                { "transition": "opened", "from": [], "to": "open", "signers": ["agent"] }
            ]
        }]
    }));
    let (with, plain) = (
        check_durable_objects(&manifest),
        check_durable_objects(&without_human),
    );
    match (with, plain) {
        (GroupResult::Passed { checks: a }, GroupResult::Passed { checks: b }) => assert!(
            a > b,
            "the human-only probe added no assertion: {a} against {b}"
        ),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn decay_independence_needs_a_payload_to_have_actually_been_deleted() {
    // Deleting nothing and finding the head unchanged demonstrates nothing at all. A group that
    // passed here would certify decay independence for a component that never decayed — the
    // vacuous-pass shape this repository refuses everywhere else.
    let head = "a".repeat(64);
    assert!(matches!(
        check_decay_independence(&head, &head, true, 0),
        GroupResult::Failed { .. }
    ));
    assert!(matches!(
        check_decay_independence(&head, &head, true, 3),
        GroupResult::Passed { .. }
    ));
}

#[test]
fn a_head_that_moved_across_decay_fails_and_so_does_a_chain_that_stopped_verifying() {
    // Two different failures with two different meanings. A deletion that moved the head would put
    // the audit trail and the GDPR obligation in direct conflict; a chain that stopped verifying is
    // corruption. Reporting them the same way would send an operator to the wrong place.
    let before = "a".repeat(64);
    let after = "b".repeat(64);
    match check_decay_independence(&before, &after, true, 2) {
        GroupResult::Failed { detail } => assert!(detail.contains("head hash moved"), "{detail}"),
        other => panic!("a moved head passed: {other:?}"),
    }
    match check_decay_independence(&before, &before, false, 2) {
        GroupResult::Failed { detail } => assert!(detail.contains("did not verify"), "{detail}"),
        other => panic!("an unverifiable chain passed: {other:?}"),
    }
}

// -- §4.2, against a real ingest -----------------------------------------------------------------

/// A manifest declaring exactly the two actions the fixture world can emit.
fn two_action_manifest() -> Manifest {
    let component = TestKey::new(0x16, "agent:github-proxy");
    let document = manifest_object("github", "1.0.0", json!({}));
    Manifest::parse(&component.sign(&document)).expect("the fixture manifest parses")
}

/// An ingest request as the component would submit it.
fn request(envelope: Value) -> Value {
    json!({ "envelope": envelope, "payloads": [] })
}

#[tokio::test]
async fn per_action_emission_passes_when_every_declared_action_has_a_sample_that_ingests() {
    let world = stozher_testkit::world().await;
    let manifest = two_action_manifest();

    // `get_file` and `create_issue` are what the fixture manifest declares. The gated one carries a
    // real approval, because "passes ingest" includes the gate — a sample that skipped it would be
    // certifying a component against a weaker bar than production applies.
    // Chained, because a component's samples are consecutive positions in its own stream and the
    // harness submits them as such. Building both against the current head would make the second a
    // `chain-seq-duplicate` — a defect in the fixture, not in the component under test.
    let first = world.effect("github.get_file", "read", json!({})).await;
    let first_id = stozher_core::signed::object_id(&first).expect("an envelope id");
    let second = world
        .gated_effect(
            "github.create_issue",
            json!({ "seq": 1, "prev-hash": first_id }),
        )
        .await;
    let samples = vec![request(first), request(second)];

    match check_per_action_emission(world.ingest(), &manifest, &samples).await {
        Ok(GroupResult::Passed { checks }) => assert!(checks >= 3, "only {checks} assertions"),
        other => panic!("a conformant component failed §4.2: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_covers_only_some_of_its_declared_actions_fails() {
    // The failure a happy-path harness misses entirely: one perfect envelope for one action, nothing
    // for the rest, and a group whose whole subject is "for every declared action type" passes.
    let world = stozher_testkit::world().await;
    let manifest = two_action_manifest();
    let samples = vec![request(
        world.effect("github.get_file", "read", json!({})).await,
    )];

    match check_per_action_emission(world.ingest(), &manifest, &samples).await {
        Ok(GroupResult::Failed { detail }) => {
            assert!(detail.contains("github.create_issue"), "{detail}");
        }
        other => panic!("partial coverage was accepted: {other:?}"),
    }
}

#[tokio::test]
async fn a_sample_the_kernel_rejects_fails_the_group_and_says_why() {
    // "Passes ingest" is the check, and it is not a property a harness can evaluate by reading an
    // envelope: it includes the mandate walk, the classification and the payload binding. So the
    // sample goes through the real pipeline, and a refusal is reported with the kernel's own code
    // rather than a paraphrase.
    let world = stozher_testkit::world().await;
    let manifest = two_action_manifest();
    let tampered = stozher_testkit::tamper(
        &world.effect("github.get_file", "read", json!({})).await,
        json!({ "policy-version": "2026.07.99" }),
    );

    match check_per_action_emission(world.ingest(), &manifest, &[request(tampered)]).await {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("sig-invalid"), "{detail}"),
        other => panic!("an envelope the kernel rejects was accepted as a sample: {other:?}"),
    }
}

#[tokio::test]
async fn a_manifest_declaring_no_actions_fails_rather_than_passing_vacuously() {
    // Zero declared actions means zero samples needed, which would make the group pass for a
    // component that conforms to nothing at all.
    let world = stozher_testkit::world().await;
    let component = TestKey::new(0x16, "agent:github-proxy");
    let mut document = manifest_object("github", "1.0.0", json!({}));
    document["actions"] = json!([]);
    // Parsed rather than validated: the kernel refuses an actionless manifest at registration, and
    // this asserts the harness would too if one ever reached it.
    let manifest = Manifest::parse(&component.sign(&document));
    let Ok(manifest) = manifest else {
        // The manifest validator refuses it first, which is the stronger answer. Nothing to check.
        return;
    };
    assert!(matches!(
        check_per_action_emission(world.ingest(), &manifest, &[]).await,
        Ok(GroupResult::Failed { .. })
    ));
}

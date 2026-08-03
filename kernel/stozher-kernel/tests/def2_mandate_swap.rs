//! DEF-2, kernel side — a stream whose emitter is being refused used to read as a healthy one.
//!
//! The gateway half is in `gateway/tests/test_def2_mandate_swap.py`. This half asks what the kernel
//! knows and what it offers, because the classification of DEF-2 turned on it: §09 §4.2 put exactly
//! one obligation on the kernel for this state — *"the kernel MUST track the last accepted `seq` per
//! stream and MUST surface streams that have gone quiet beyond a policy-configured interval"* — and
//! §04 §7 put one more: a rejection MUST be recorded and MUST be visible in the console. The kernel
//! discharged both, which is still asserted below.
//!
//! What no clause asked for, and what nothing therefore provided, was the join between them. The
//! rejection stream knew *now* that an emitter's envelopes were being refused; the stream surface
//! reported the same row it had reported yesterday and would keep reporting until the quiet timer
//! (`checkpoint-interval`) expired. "Actively refused" and "fine" were the same row. That is the
//! seven days the evaluation lost. §09 §4.2's third requirement closes it, and §04 §7.2 gives the
//! state an exit that is not "restore from backup".
//!
//! Nothing here weakens a gate. The recovery act is `consequential`, is in
//! `ingest::ROOT_APPROVED_ACTIONS`, and the negative below submits one without an approval and
//! watches it refused.

use serde_json::{Value, json};
use stozher_core::signed;
use stozher_kernel::clock::Clock;
use stozher_testkit::{Ask, EFFECT_STREAM, World, mandate_object, revise, world};

/// Publish a mandate object the way `runtime.py::_publish_mandate` does — as a `mandate` envelope on
/// the emitter's own stream, signed by the emitter, at the next free position.
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

#[tokio::test]
async fn def2_a_stream_whose_emitter_is_being_refused_reads_as_a_healthy_stream() {
    let world = world().await;

    // A week of ordinary traffic first, so the stream exists and has a head — the state the
    // evaluation's `gw:katsarov-Pro-M4:ops-bot` was in before anyone touched its mandate file.
    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    let (healthy_seq, _) = world.head(EFFECT_STREAM).await;

    // The swap. A root signs a replacement standing grant with a longer life than the policy's
    // `delegation.max-standing-lifetime` allows (§03 §3), the operator drops it in place, and the
    // component publishes it at its next connect. The kernel refuses the grant — correctly.
    let replacement = world.root.sign(&mandate_object(
        &world.root,
        &world.agent,
        "000000000000000000000000000000d2",
        json!({ "not-after": "2027-06-01T00:00:00.000Z" }),
    ));
    let replacement_ref = signed::object_id(&replacement).expect("mandate id");
    let envelope = publish_mandate(&world, &replacement).await;
    world
        .reject(&envelope, &[], "mandate-standing-lifetime-exceeded")
        .await;

    // Everything the component emits from here cites a mandate that exists only on its own disk.
    for _ in 0..3 {
        let effect = world
            .effect(
                "github.get_file",
                "read",
                json!({ "mandate-ref": replacement_ref }),
            )
            .await;
        world.reject(&effect, &[], "mandate-unresolved").await;
    }

    // §04 §7 — the kernel's duty, discharged. Four rejections, each naming its reason.
    let store = world.ingest().store();
    let rejections = store.rejections(None, 50).await.expect("rejections");
    let refused_here: Vec<&Value> = rejections
        .iter()
        .filter(|r| r["claimed-stream"] == json!(EFFECT_STREAM))
        .collect();
    assert_eq!(
        refused_here.len(),
        4,
        "the kernel did not record every refusal: {rejections:?}"
    );
    assert!(
        refused_here
            .iter()
            .any(|r| r["reason"] == json!("mandate-unresolved")),
        "no rejection names the condition the emitter is in"
    );

    // §09 §4.2 — the last accepted `seq`, tracked. It has not moved, which is correct and is also
    // the whole problem: it is identical to the row of a component that simply had nothing to say.
    let streams = store.streams().await.expect("streams");
    let row = streams
        .iter()
        .find(|s| s["stream"] == json!(EFFECT_STREAM))
        .expect("the stream is in the surface")
        .clone();
    assert_eq!(
        row["head-seq"].as_u64(),
        Some(healthy_seq - 1),
        "the head moved; the fixture did not produce the refused state"
    );

    // The assertion that failed while DEF-2 was open. A reader of the quiet-stream surface, at the
    // moment of the refusals, must be able to tell "this emitter is being refused" from "this
    // emitter is idle". No field name is prescribed here — only that the fact reaches the surface
    // that exists to answer the question, instead of living one table away in a stream nobody
    // correlates.
    let rendered = serde_json::to_string(&row).expect("a row");
    assert!(
        rendered.contains("mandate-unresolved"),
        "DEF-2: the stream surface reports {rendered} while the kernel is refusing every envelope \
         this emitter offers; a reader cannot tell it from a stream that is merely quiet, and \
         nothing will say otherwise until the quiet interval elapses"
    );

    // And the predicate behind the row says so in the vocabulary `spec/vectors/stream-status.json`
    // fixes, rather than leaving each surface to decide what "wrong" looks like. The quiet interval
    // has not elapsed and never needs to: quiet is the absence of evidence, refused is evidence.
    let status = stozher_core::sync::stream_status(
        row["last-appended-at"].as_str(),
        row["last-refused-at"].as_str(),
        Some(0),
        3_600,
    );
    assert_eq!(status, stozher_core::sync::StreamStatus::Refused);
}

/// The resume act of §04 §7.2, as an operator would submit it.
///
/// `authorized` is the whole of the negative test: an unapproved resume is an envelope of a gated
/// class with no `authorization`, and it is refused exactly like any other.
async fn resume(
    world: &World,
    stream: &str,
    resume_seq: u64,
    bridge: &str,
    reason: &str,
    authorized: bool,
) -> (Value, Vec<Value>) {
    let document = json!({
        "stream": stream,
        "resume-seq": resume_seq,
        "refused-object-hash": bridge,
        "reason-code": reason
    });
    let hash = stozher_core::jcs::object_hash(&document).expect("resume document hash");
    let target = format!("stream:{stream}");
    let now = world.clock.now();
    let mut extra = json!({
        "mandate-ref": world.standing_mandate,
        "policy-version": world.policy_version,
        "classification": "consequential",
        "execution": {
            "action": "kernel.resume_stream",
            "target": target,
            "args-hash": hash,
            "outcome": "applied",
            "started-at": now,
            "finished-at": now
        },
        "evidence": {
            "schema": "kernel.resume_stream.v1",
            "media-type": "application/json",
            "payload-hash": hash,
            // Inside the `benign` ceiling as well as the `consequential` one, so a test that
            // reclassifies this action is testing the rule it means to and not the TTL.
            "retain-until": "2026-08-01T00:00:00.000Z"
        }
    });
    if authorized {
        extra["authorization"] = world.authorize(&Ask {
            requester: &world.agent,
            component: "kernel",
            mandate_ref: &world.standing_mandate,
            policy_version: &world.policy_version,
            classification: "consequential",
            action: "kernel.resume_stream",
            target: &target,
            args_hash: &hash,
        });
    }
    let envelope = world.core_envelope("effect", extra).await;
    let payload = json!({
        "payload-hash": hash,
        "media-type": "application/json",
        "payload": document
    });
    (envelope, vec![payload])
}

/// The `object-hash` of the bytes this kernel refused at a claimed position — §04 §7's own record,
/// which is where an operator reads the bridge hash from.
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

#[tokio::test]
async fn def2_a_wedged_stream_is_resumed_only_by_a_root_signed_operator_act() {
    let world = world().await;

    // Ordinary traffic, then the swap: a root signs a replacement standing grant longer-lived than
    // the policy's ceiling, the component publishes it, and the kernel refuses — correctly. From
    // here the emitter's stream is wedged: §04 §3 admits no gap.
    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    let replacement = world.root.sign(&mandate_object(
        &world.root,
        &world.agent,
        "000000000000000000000000000000d3",
        json!({ "not-after": "2027-06-01T00:00:00.000Z" }),
    ));
    let wedging = publish_mandate(&world, &replacement).await;
    let wedged_at = wedging["seq"].as_u64().expect("seq");
    world
        .reject(&wedging, &[], "mandate-standing-lifetime-exceeded")
        .await;
    let bridge = refused_object_hash(&world, EFFECT_STREAM, wedged_at).await;

    // The emitter's own next envelope: it does not renumber and does not rewrite, so it sits one
    // past the refused position and chains onto the refused bytes (§05 §7.1 clause 3).
    let draft = world.effect("github.get_file", "read", json!({})).await;
    let after = revise(
        &draft,
        json!({ "seq": wedged_at + 1, "prev-hash": bridge }),
        &world.agent,
    );
    world.reject(&after, &[], "chain-seq-gap").await;

    // A halted fleet with no exit is not a security posture — and an exit with no signature is not
    // a gate. The unapproved resume is refused like any other gated effect.
    let (unapproved, payloads) = resume(
        &world,
        EFFECT_STREAM,
        wedged_at,
        &bridge,
        "mandate-standing-lifetime-exceeded",
        false,
    )
    .await;
    world
        .reject(&unapproved, &payloads, "gate-authorization-missing")
        .await;
    assert!(
        world
            .ingest()
            .store()
            .stream_resume(EFFECT_STREAM, wedged_at)
            .await
            .expect("reading the resume set")
            .is_none(),
        "a refused resume authorized a gap"
    );
    world.reject(&after, &[], "chain-seq-gap").await;

    // The approved one, and only then does the emitter's chain continue.
    let (approved, payloads) = resume(
        &world,
        EFFECT_STREAM,
        wedged_at,
        &bridge,
        "mandate-standing-lifetime-exceeded",
        true,
    )
    .await;
    world.accept(&approved, &payloads).await;
    world.accept(&after, &[]).await;

    let (next, head) = world.head(EFFECT_STREAM).await;
    assert_eq!(next, wedged_at + 2, "the emitter did not resume in place");
    assert_eq!(head.as_deref(), signed::object_id(&after).ok().as_deref());
}

/// §05 §5.6 — policy cannot lower the bar on the mechanism that enforces policy, and the resume act
/// is now part of that mechanism: it is the only thing in the system that changes what
/// [`stozher_kernel::store::Store`] will accept at a chain position.
///
/// The negative above proves an unapproved resume is refused, but it would prove that even if
/// `kernel.resume_stream` were not in `ROOT_APPROVED_ACTIONS`, because the baseline profile gates
/// `consequential` anyway. So this one takes the profile away: an organization publishes a policy
/// classifying the resume `benign`, which the baseline allows outright. If the act rested on the
/// gate rule, it would now be free.
#[tokio::test]
async fn def2_no_policy_can_make_a_resume_free() {
    let mut world = world().await;
    let mut document = stozher_kernel::policy::baseline_conservative(
        "2026.07.2",
        &world.clock.now(),
        &[world.root.subject.as_str()],
    );
    document["classification"]["by-action"]["kernel.resume_stream"] = json!("benign");
    let signed_document = world.policy_key.sign(&document);
    world.publish_policy(&signed_document).await;

    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    let replacement = world.root.sign(&mandate_object(
        &world.root,
        &world.agent,
        "000000000000000000000000000000d5",
        json!({ "not-after": "2027-06-01T00:00:00.000Z" }),
    ));
    let wedging = publish_mandate(&world, &replacement).await;
    let wedged_at = wedging["seq"].as_u64().expect("seq");
    world
        .reject(&wedging, &[], "mandate-standing-lifetime-exceeded")
        .await;
    let bridge = refused_object_hash(&world, EFFECT_STREAM, wedged_at).await;

    let (unapproved, payloads) = resume(
        &world,
        EFFECT_STREAM,
        wedged_at,
        &bridge,
        "mandate-standing-lifetime-exceeded",
        false,
    )
    .await;
    world
        .reject(&unapproved, &payloads, "gate-authorization-missing")
        .await;
}

#[tokio::test]
async fn def2_a_resume_does_not_revalidate_the_envelope_that_was_refused() {
    let world = world().await;
    let effect = world.effect("github.get_file", "read", json!({})).await;
    world.accept(&effect, &[]).await;
    let replacement = world.root.sign(&mandate_object(
        &world.root,
        &world.agent,
        "000000000000000000000000000000d4",
        json!({ "not-after": "2027-06-01T00:00:00.000Z" }),
    ));
    let wedging = publish_mandate(&world, &replacement).await;
    let wedged_at = wedging["seq"].as_u64().expect("seq");
    world
        .reject(&wedging, &[], "mandate-standing-lifetime-exceeded")
        .await;
    let bridge = refused_object_hash(&world, EFFECT_STREAM, wedged_at).await;
    let before = world
        .ingest()
        .store()
        .rejections(None, 50)
        .await
        .expect("rejections")
        .len();

    let (approved, payloads) = resume(
        &world,
        EFFECT_STREAM,
        wedged_at,
        &bridge,
        "mandate-standing-lifetime-exceeded",
        true,
    )
    .await;
    world.accept(&approved, &payloads).await;

    // A resume is an operator saying "this stream may continue", never "that envelope was fine
    // after all" (§04 §7.2 rule 4). If one act could say both, every refusal would be appealable by
    // whoever can obtain one signature.
    world
        .reject(&wedging, &[], "mandate-standing-lifetime-exceeded")
        .await;
    let rejections = world
        .ingest()
        .store()
        .rejections(None, 50)
        .await
        .expect("rejections");
    assert!(
        rejections.len() > before,
        "the second refusal of the same bytes was not recorded"
    );
    assert!(
        rejections.iter().any(|r| r["object-hash"] == json!(bridge)
            && r["reason"] == json!("mandate-standing-lifetime-exceeded")),
        "the original rejection record did not survive the resume"
    );
    assert!(
        world
            .ingest()
            .store()
            .range(EFFECT_STREAM, wedged_at, wedged_at)
            .await
            .expect("reading the resumed position")
            .is_empty(),
        "the refused position was filled; a bridge is not a backfill"
    );

    // And the chain after recovery verifies — anchored on the refused bytes, which is the honest
    // statement: the position is genuinely absent from the kernel's copy (§04 §7.2 rule 6).
    let draft = world.effect("github.get_file", "read", json!({})).await;
    let after = revise(
        &draft,
        json!({ "seq": wedged_at + 1, "prev-hash": bridge }),
        &world.agent,
    );
    world.accept(&after, &[]).await;
    let range = world
        .ingest()
        .store()
        .range(EFFECT_STREAM, wedged_at + 1, wedged_at + 1)
        .await
        .expect("the resumed range");
    let verified = stozher_core::chain::verify_chain(&range, EFFECT_STREAM, Some(&bridge))
        .expect("the chain after recovery verifies");
    assert!(verified.anchored);
    assert_eq!(
        verified.head_hash,
        signed::object_id(&after).expect("head hash")
    );
}

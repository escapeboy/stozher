//! DEF-2, kernel side — a stream whose emitter is being refused reads as a healthy one.
//!
//! Run with `cargo test --manifest-path kernel/Cargo.toml --test def2_mandate_swap -- --ignored`.
//!
//! The gateway half is in `gateway/tests/test_def2_mandate_swap.py`. This half asks what the kernel
//! knows and what it offers, because the classification of DEF-2 turns on it: §09 §4.2 puts exactly
//! one obligation on the kernel for this state — *"the kernel MUST track the last accepted `seq` per
//! stream and MUST surface streams that have gone quiet beyond a policy-configured interval"* — and
//! §04 §7 puts one more: a rejection MUST be recorded and MUST be visible in the console. The kernel
//! discharges both, which is asserted below.
//!
//! What no clause asks for, and what nothing therefore provides, is the join between them. The
//! rejection stream knows *now* that this emitter's envelopes are being refused; the stream surface
//! reports the same row it reported yesterday and will keep reporting until the quiet timer
//! (`checkpoint-interval`) expires. "Actively refused" and "fine" are the same row. That is the
//! seven days the evaluation lost.
//!
//! Nothing here weakens a gate: the test submits envelopes and reads two projections.

use serde_json::{Value, json};
use stozher_core::signed;
use stozher_kernel::clock::Clock;
use stozher_testkit::{EFFECT_STREAM, World, mandate_object, world};

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
#[ignore = "DEF-2 open"]
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

    // The assertion that fails while DEF-2 is open. A reader of the quiet-stream surface, at the
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
}

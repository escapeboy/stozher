//! What a checkpoint actually attests — `spec/04-chain-and-checkpoints.md` §2.1 and §4.
//!
//! A checkpoint's whole job is to turn "this chain is internally consistent" into "this chain is
//! consistent *and* is the one whose head was published". That upgrade rests on two things the
//! verifier has to establish and cannot infer from the bytes in front of it:
//!
//! * that the range it was handed **is** the range the checkpoint names — `[from-seq, to-seq]`,
//!   `count` records of it; and
//! * that the range is tied to history by an anchor the **caller** supplied, because §04 §2.1 says
//!   so in as many words: *"Verification of a range that does not start at `seq == 0` requires the
//!   caller to supply the expected `prev-hash` of the first record."*
//!
//! An anchor read out of the range being verified is the range vouching for itself, and a `count`
//! compared only against `to-seq - from-seq + 1` is the checkpoint agreeing with its own arithmetic.
//! Neither tells a verifier anything about the records it was given.

use serde_json::{Value, json};
use stozher_core::signed::KeyId;
use stozher_core::{chain, crypto, signed};

const STREAM: &str = "signals:gateway:0001";
const SECRET: [u8; 32] = [0x31; 32];
const DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn key_id() -> KeyId {
    KeyId::from_public_key(&crypto::public_key_of(&SECRET))
}

/// A signed `signal` envelope at `seq`, chained onto `prev`.
///
/// `signal` is the lightest kind that carries no mandate, class or execution — this is a test about
/// linkage and range shape, and any authority-bearing member would be noise in it.
fn envelope(seq: u64, prev: Option<&str>) -> Value {
    let body = json!({
        "v": "stozher/0.1",
        "kind": "signal",
        "emitted-at": "2026-07-26T09:00:00.000Z",
        "stream": STREAM,
        "seq": seq,
        "prev-hash": prev.map_or(Value::Null, Value::from),
        "identity": {
            "subject": "agent:gateway",
            "key": key_id().as_str(),
            "component": "gateway"
        },
        "signal": {
            "source": "webhook:github",
            "received-at": "2026-07-26T09:00:00.000Z",
            "media-type": "application/json",
            "payload-hash": DIGEST,
            "sender-verified": true
        }
    });
    signed::sign_object(&body, &SECRET).expect("signing a test envelope")
}

/// A chain of `len` signal envelopes, seq 0..len, each linked to the last.
fn chain_of(len: u64) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut prev: Option<String> = None;
    for seq in 0..len {
        let next = envelope(seq, prev.as_deref());
        prev = Some(signed::object_id(&next).expect("hashing a test envelope"));
        out.push(next);
    }
    out
}

/// A checkpoint body attesting `[from, to]` of [`STREAM`] with `head` as the head hash.
///
/// Unsigned: [`chain::verify_checkpoint`] reads the `checkpoint` member and never verifies the
/// checkpoint envelope's own signature — that is ingest's job (`checkpoint-signer-not-kernel`), and
/// conflating the two would let this test pass for the wrong reason.
fn checkpoint(from: u64, to: u64, count: u64, head: &str) -> Value {
    json!({
        "checkpoint": {
            "stream": STREAM,
            "from-seq": from,
            "to-seq": to,
            "head-hash": head,
            "count": count,
            "observed-at": "2026-07-26T09:05:00.000Z"
        }
    })
}

fn head_of(range: &[Value]) -> String {
    signed::object_id(range.last().expect("a non-empty range")).expect("hashing the head")
}

// -- the range must be the attested range --------------------------------------------------------

#[test]
fn a_checkpoint_over_the_whole_stream_is_not_satisfied_by_a_suffix_of_it() {
    // The exploit, and the reason this is not a tidiness complaint. The checkpoint attests
    // "10 envelopes, seq 0 through 9". The verifier is handed only seq 5 through 9 — five records,
    // none of the first five, no evidence any of them ever existed.
    //
    // Every check the old implementation performed still passes on this input: `count` agrees with
    // the checkpoint's own `to - from + 1`; the range is internally contiguous; the head hash is the
    // real one because the suffix really does end at seq 9. And the anchor it compares against is
    // read from `range[0].prev-hash`, so it is comparing the record to itself.
    //
    // The result was `Ok(())`: a verifier could report a stream as attested from genesis having been
    // shown half of it.
    let all = chain_of(10);
    let attested = checkpoint(0, 9, 10, &head_of(&all));
    let suffix = &all[5..];

    let error = chain::verify_checkpoint(&attested, suffix, None)
        .expect_err("a checkpoint over [0, 9] must not accept the range [5, 9]");
    assert_eq!(error.code(), "x-checkpoint-range-mismatch", "got {error}");
}

#[test]
fn a_range_holding_the_wrong_number_of_records_is_refused_before_its_head_is_read() {
    // §04 §4 rule 2 bounds `count` against the checkpoint's own two numbers, which says nothing
    // about what was verified. `count` is only an attestation if it also counts the records handed
    // over.
    //
    // The refusal is `checkpoint-count-mismatch` rather than `checkpoint-head-mismatch` on purpose:
    // the head *would* also fail here, but reporting it that way tells an operator their chain has
    // been tampered with when in fact they passed the wrong range. The two are different incidents
    // and must not share a code.
    let all = chain_of(10);
    let attested = checkpoint(0, 4, 5, &head_of(&all));

    let error = chain::verify_checkpoint(&attested, &all, None)
        .expect_err("a checkpoint counting 5 must not accept 10 records");
    assert_eq!(error.code(), "checkpoint-count-mismatch", "got {error}");
}

#[test]
fn a_checkpoint_still_accepts_exactly_the_range_it_names() {
    // The companion the refusals above need: this must stay a check on the range's *shape*, not a
    // check that refuses ranges.
    let all = chain_of(10);
    let attested = checkpoint(0, 9, 10, &head_of(&all));

    let result = chain::verify_checkpoint(&attested, &all, None).expect("the attested range");
    assert_eq!(result.count, 10);
    assert_eq!(result.head_hash, head_of(&all));
    // Starts at genesis, so it is anchored by `prev-hash: null` and needs nothing from the caller.
    assert!(result.anchored, "a range from seq 0 is anchored by genesis");
}

// -- the anchor comes from the caller, never from the range ---------------------------------------

#[test]
fn a_range_that_does_not_start_at_genesis_is_unanchored_without_a_caller_supplied_anchor() {
    // §04 §2.1: the result states whether the range was anchored. The old implementation synthesized
    // the anchor out of `range.first().prev-hash` and handed it to `verify_chain`, which sets
    // `anchored = expected_first_prev.is_some()` — so it reported `anchored: true` for every range,
    // on the strength of a value that came out of the range itself.
    //
    // "An unanchored range proves internal consistency only", and a verifier is entitled to be told
    // which of the two it is holding.
    let all = chain_of(10);
    let tail = &all[5..];
    let attested = checkpoint(5, 9, 5, &head_of(&all));

    let result = chain::verify_checkpoint(&attested, tail, None).expect("internally consistent");
    assert!(
        !result.anchored,
        "a range starting at seq 5 with no caller anchor must not report itself anchored"
    );
}

#[test]
fn a_caller_supplied_anchor_is_actually_checked() {
    // The other half: an anchor the caller does supply has to be load-bearing. Previously the
    // parameter did not exist and the comparison in `verify_chain` was `claimed != claimed`, which
    // no forged suffix could ever fail.
    let all = chain_of(10);
    let tail = &all[5..];
    let attested = checkpoint(5, 9, 5, &head_of(&all));

    let real = signed::object_id(&all[4]).expect("hashing seq 4");
    let result = chain::verify_checkpoint(&attested, tail, Some(&real)).expect("the true anchor");
    assert!(result.anchored, "a correct caller anchor anchors the range");

    let error = chain::verify_checkpoint(&attested, tail, Some(DIGEST))
        .expect_err("a wrong anchor must be detected");
    assert_eq!(error.code(), "chain-prev-hash-mismatch", "got {error}");
}

#[test]
fn a_signed_branch_that_never_happened_does_not_anchor_itself() {
    // The forgery the self-anchor actually enabled, as opposed to the mechanism that enabled it.
    // Every case above hands the verifier a real suffix of a real stream; this hands it a chain that
    // is correctly signed, internally perfect, and entirely invented — seq 5 through 9 linked to a
    // `prev-hash` of the fabricator's choosing, descending from nothing.
    //
    // Reading the anchor out of `range[0]` made this indistinguishable from history. It verifies
    // still, because it *is* internally consistent — but it now reports itself unanchored, and the
    // moment a caller supplies the real predecessor it is refused.
    let real = chain_of(10);
    let mut fabricated: Vec<Value> = Vec::new();
    let mut prev = Some(DIGEST.to_owned());
    for seq in 5..10 {
        let next = envelope(seq, prev.as_deref());
        prev = Some(signed::object_id(&next).expect("hashing a test envelope"));
        fabricated.push(next);
    }
    let attested = checkpoint(5, 9, 5, &head_of(&fabricated));

    let result = chain::verify_checkpoint(&attested, &fabricated, None)
        .expect("a fabricated branch is still internally consistent");
    assert!(
        !result.anchored,
        "nothing external was supplied, so nothing external was proved"
    );

    let real_anchor = signed::object_id(&real[4]).expect("hashing seq 4");
    let error = chain::verify_checkpoint(&attested, &fabricated, Some(&real_anchor))
        .expect_err("the fabricated branch does not descend from the real seq 4");
    assert_eq!(error.code(), "chain-prev-hash-mismatch", "got {error}");
}

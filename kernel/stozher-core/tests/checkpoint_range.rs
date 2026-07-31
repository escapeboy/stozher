//! The `from-seq` half of what a checkpoint attests — `spec/04-chain-and-checkpoints.md` §4.
//!
//! `checkpoint_attestation.rs` covers the count, the anchor, and the forged branch. This file exists
//! for the one case those cannot reach: a range holding **exactly** the attested number of records,
//! correctly linked, ending at the attested head — and beginning somewhere else entirely. The count
//! barrier is satisfied, so only the range-identity check stands between that and a valid verdict.

use serde_json::{Value, json};
use stozher_core::signed::KeyId;
use stozher_core::{chain, crypto, signed};

const STREAM: &str = "signals:gateway:0001";
const SECRET: [u8; 32] = [0x31; 32];
const DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn envelope(seq: u64, prev: Option<&str>) -> Value {
    let key = KeyId::from_public_key(&crypto::public_key_of(&SECRET));
    let body = json!({
        "v": "stozher/0.1",
        "kind": "signal",
        "emitted-at": "2026-07-26T09:00:00.000Z",
        "stream": STREAM,
        "seq": seq,
        "prev-hash": prev.map_or(Value::Null, Value::from),
        "identity": { "subject": "agent:gateway", "key": key.as_str(), "component": "gateway" },
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

#[test]
fn a_range_of_the_attested_length_must_still_begin_where_it_is_attested_to() {
    let all = chain_of(4);
    let head = signed::object_id(&all[3]).expect("hashing the head");
    // Four records attested, four supplied, ending at the attested head — every count check agrees.
    // Only the starting position disagrees, and it disagrees by a hundred.
    let attested = json!({
        "checkpoint": {
            "stream": STREAM,
            "from-seq": 100,
            "to-seq": 103,
            "head-hash": head,
            "count": 4,
            "observed-at": "2026-07-26T09:05:00.000Z"
        }
    });

    let error = chain::verify_checkpoint(&attested, &all, None)
        .expect_err("a range beginning at seq 0 does not attest seq 100..=103");
    assert_eq!(error.code(), "checkpoint-range-mismatch", "got {error}");
}

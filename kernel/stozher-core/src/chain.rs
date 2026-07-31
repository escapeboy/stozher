//! Hash chain verification — `spec/04-chain-and-checkpoints.md` §2.
//!
//! Verification never reads an evidence payload. That is not an optimization: it is the property
//! that makes payload decay compatible with chain integrity (§04 §5.1), and it is asserted by the
//! `payload-binding` vectors.

use serde_json::Value;

use crate::envelope;
use crate::error::{Result, err};
use crate::signed::{object_id, verify_signed_object};

/// The outcome of verifying a contiguous range of one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainResult {
    /// Number of envelopes verified.
    pub count: usize,
    /// `id()` of the highest `seq` in the range.
    pub head_hash: String,
    /// Whether the range is anchored: it starts at `seq` 0, or the caller supplied the expected
    /// `prev-hash` of the first record. An unanchored range proves internal consistency only.
    pub anchored: bool,
}

/// Verify a contiguous range of one stream.
///
/// `expected_first_prev` anchors a range that does not start at `seq` 0.
///
/// # Errors
///
/// `sig-invalid`, `chain-stream-mismatch`, `chain-seq-gap`, `chain-seq-duplicate`,
/// `chain-prev-hash-mismatch`, `chain-genesis-prev-not-null`, or any structural code from
/// [`envelope::validate`]. The error carries the `seq` at which verification failed.
pub fn verify_chain(
    envelopes: &[Value],
    stream: &str,
    expected_first_prev: Option<&str>,
) -> Result<ChainResult> {
    let Some(first) = envelopes.first() else {
        return Err(err!("chain-empty-range", "no envelopes supplied"));
    };

    // Read the starting position without validating yet: the loop validates every record and
    // attaches the failing `seq` to the error, including for the first one.
    let first_seq = first.get("seq").and_then(Value::as_u64).unwrap_or_default();
    let anchored = first_seq == 0 || expected_first_prev.is_some();

    let mut previous_id: Option<String> = None;
    for (index, current) in envelopes.iter().enumerate() {
        let observed_seq = current.get("seq").and_then(Value::as_u64);

        // Signature first, over the bytes as received (§04 §2.1 step 1, §02 §9.2). The order is
        // normative, not stylistic: a schema check that runs first answers an *unsigned* object with
        // a structural code, which turns the verifier into a schema oracle — an attacker learns
        // which member a forged envelope is missing without ever holding a key. Authenticate, then
        // interpret. `attach` supplies the `seq` because a malformed record may not have a usable
        // one to fail at.
        let seq = observed_seq.unwrap_or_default();
        verify_signed_object(current).map_err(|e| attach(e, observed_seq))?;

        // Then structure: it decides genesis/prev-hash consistency and member sets.
        envelope::validate(current).map_err(|e| e.at_seq(seq))?;

        // Then that this envelope belongs to this stream at all. `stream` is a signed member, so
        // an envelope cannot be moved between streams without invalidating its signature; this
        // catches a validly re-signed envelope spliced in from elsewhere.
        let observed_stream = current["stream"].as_str().unwrap_or_default();
        if observed_stream != stream {
            return Err(err!(
                "chain-stream-mismatch",
                "expected {stream:?}, found {observed_stream:?}"
            )
            .at_seq(seq));
        }

        // Then position.
        let expected_seq = first_seq + index as u64;
        if seq != expected_seq {
            let code = if seq < expected_seq {
                "chain-seq-duplicate"
            } else {
                "chain-seq-gap"
            };
            return Err(err!(code, "expected seq {expected_seq}, found {seq}").at_seq(seq));
        }

        // Then linkage.
        let prev_hash = current["prev-hash"].as_str();
        match (&previous_id, prev_hash) {
            (None, None) => {
                // Genesis; envelope::validate already required seq == 0.
            }
            (None, Some(claimed)) => {
                if let Some(anchor) = expected_first_prev {
                    if claimed != anchor {
                        return Err(err!(
                            "chain-prev-hash-mismatch",
                            "prev-hash {claimed} does not match the supplied anchor {anchor}"
                        )
                        .at_seq(seq));
                    }
                }
            }
            (Some(actual), Some(claimed)) => {
                if claimed != actual {
                    return Err(err!(
                        "chain-prev-hash-mismatch",
                        "prev-hash {claimed} != predecessor id {actual}"
                    )
                    .at_seq(seq));
                }
            }
            (Some(_), None) => {
                return Err(
                    err!("chain-prev-hash-missing", "seq {seq} has no prev-hash").at_seq(seq),
                );
            }
        }

        previous_id = Some(object_id(current)?);
    }

    Ok(ChainResult {
        count: envelopes.len(),
        head_hash: previous_id.unwrap_or_default(),
        anchored,
    })
}

fn attach(error: crate::error::Error, seq: Option<u64>) -> crate::error::Error {
    match seq {
        Some(seq) => error.at_seq(seq),
        None => error,
    }
}

/// The supplied range is not the range the checkpoint attests.
///
/// Implementation-local, hence the `x-` prefix: §04 §4 names `checkpoint-count-mismatch` for
/// `count != to-seq - from-seq + 1` and `checkpoint-head-mismatch` for the head, but names nothing
/// for a range that simply begins somewhere else. Registered in `stozher_kernel::codes::REGISTER`.
pub const CHECKPOINT_RANGE_MISMATCH: &str = "checkpoint-range-mismatch";

/// Verify a signed checkpoint against the chain range it attests (§04 §4).
///
/// `expected_first_prev` anchors a checkpoint whose range does not start at `seq` 0. It is the
/// caller's to supply — deliberately, because it is the one input that cannot come from the
/// material under examination. Anchoring a range with a `prev-hash` read out of that same range
/// compares a value with itself: it always passes, and it certifies a signed branch that never
/// happened just as readily as the real history. Without it the result is honest but weaker, and
/// says so in [`ChainResult::anchored`].
///
/// # Errors
///
/// `checkpoint-count-mismatch`, `checkpoint-head-mismatch`, [`CHECKPOINT_RANGE_MISMATCH`],
/// `schema-missing-member`, or a code propagated from [`verify_chain`].
pub fn verify_checkpoint(
    checkpoint: &Value,
    range: &[Value],
    expected_first_prev: Option<&str>,
) -> Result<ChainResult> {
    let body = checkpoint
        .get("checkpoint")
        .ok_or_else(|| err!("schema-missing-member", "checkpoint"))?;
    let stream = body
        .get("stream")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "checkpoint.stream"))?;
    let from_seq = body
        .get("from-seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("schema-missing-member", "checkpoint.from-seq"))?;
    let to_seq = body
        .get("to-seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("schema-missing-member", "checkpoint.to-seq"))?;
    let count = body
        .get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("schema-missing-member", "checkpoint.count"))?;
    let head_hash = body
        .get("head-hash")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "checkpoint.head-hash"))?;

    // §04 §4 rule 2, on the checkpoint's own members.
    if count != to_seq.saturating_sub(from_seq) + 1 {
        return Err(err!(
            "checkpoint-count-mismatch",
            "count {count} does not match the attested range {from_seq}..={to_seq}"
        ));
    }
    // …and then against what was actually supplied. `count` is the number of envelopes the
    // checkpoint attests, so a range of a different length does not satisfy it however consistent
    // that range is with itself: a checkpoint over `[0, 999]` verifying against four envelopes is
    // the difference between "these thousand records are the history" and "some records are".
    if range.len() as u64 != count {
        return Err(err!(
            "checkpoint-count-mismatch",
            "attests {count} envelopes, supplied {}",
            range.len()
        ));
    }
    // The right number of records is still not the right records. A range of the attested length
    // that begins somewhere else is a different slice of the stream, and saying so with its own
    // code matters: `checkpoint-count-mismatch` reads as "your chain does not add up" to an
    // operator who has simply passed the wrong range.
    let observed_first = range
        .first()
        .and_then(|e| e.get("seq"))
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("schema-missing-member", "range[0].seq"))?;
    if observed_first != from_seq {
        return Err(err!(
            CHECKPOINT_RANGE_MISMATCH,
            "attests from seq {from_seq}, supplied range begins at {observed_first}"
        ));
    }

    let result = verify_chain(range, stream, expected_first_prev)?;
    if result.head_hash != head_hash {
        return Err(err!(
            "checkpoint-head-mismatch",
            "head {} != attested {head_hash}",
            result.head_hash
        ));
    }
    Ok(result)
}

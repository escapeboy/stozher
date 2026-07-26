//! Signed checkpoints — `spec/04-chain-and-checkpoints.md` §4.
//!
//! A checkpoint converts "the chain is internally consistent" into "the chain is consistent *and* has
//! not been rebuilt", because a rebuilt chain cannot reproduce a previously published head hash.
//!
//! Checkpoints are emitted **through ingest**, like everything else. That is deliberate: a kernel
//! that appended its own envelopes through a private path would have exactly the administrative
//! side door §06 §2 forbids, and the fact that checkpoints are the kernel's own records is not a
//! reason to trust them more.

use serde_json::Value;
use stozher_core::error::{Error, Result};

use crate::ingest::{Ingest, Outcome};
use crate::store::Appended;

/// Emit a checkpoint covering everything in `stream` that no checkpoint covers yet.
///
/// Returns `None` when there is nothing new to attest.
///
/// # Errors
///
/// Any ingest rejection code, or [`crate::codes::STORE_UNAVAILABLE`].
pub async fn emit(
    ingest: &Ingest,
    stream: &str,
    checkpoint_stream: &str,
) -> Result<Option<Appended>> {
    let store = ingest.store();
    let Some((head_seq, head_hash)) = store.stream_head(stream).await? else {
        return Ok(None);
    };
    let from_seq = match store.last_checkpoint(stream).await? {
        Some((_, to_seq, _)) if to_seq >= head_seq => return Ok(None),
        Some((_, to_seq, _)) => to_seq + 1,
        None => 0,
    };

    let now = ingest.clock().now();
    let prev_hash = store
        .stream_head(checkpoint_stream)
        .await?
        .map(|(_, id)| id);
    let seq = match store.stream_head(checkpoint_stream).await? {
        Some((head, _)) => head + 1,
        None => 0,
    };

    let body = serde_json::json!({
        "v": stozher_core::VERSION,
        "kind": "checkpoint",
        "emitted-at": now,
        "stream": checkpoint_stream,
        "seq": seq,
        "prev-hash": prev_hash,
        "identity": {
            "subject": "agent:kernel",
            "key": ingest.kernel_key().id().as_str(),
            "component": "kernel"
        },
        "checkpoint": {
            "stream": stream,
            "from-seq": from_seq,
            "to-seq": head_seq,
            "head-hash": head_hash,
            "count": head_seq - from_seq + 1,
            "observed-at": now
        }
    });
    let envelope = ingest.kernel_key().sign(&body)?;
    let request = serde_json::json!({ "envelope": envelope, "payloads": [] });
    let raw = stozher_core::jcs::canonicalize(&request)?;

    match ingest.submit(raw.as_bytes(), Some("agent:kernel")).await {
        Outcome::Accepted(appended) => Ok(Some(appended)),
        Outcome::Rejected { reason, detail, .. } => Err(Error::new(
            leak_code(&reason),
            format!("the kernel's own checkpoint was rejected: {detail}"),
        )),
        Outcome::Unavailable(detail) => Err(Error::new(crate::codes::STORE_UNAVAILABLE, detail)),
    }
}

/// Checkpoint every stream that has advanced past its last checkpoint (§04 §4.6).
///
/// Returns the streams checkpointed. Errors on individual streams are reported rather than
/// swallowed: a stream that cannot be checkpointed is a stream whose head is not publicly fixed.
///
/// # Errors
///
/// [`crate::codes::STORE_UNAVAILABLE`] if the stream list cannot be read.
pub async fn emit_all(
    ingest: &Ingest,
    checkpoint_stream: &str,
) -> Result<Vec<(String, std::result::Result<Option<u64>, String>)>> {
    let mut results = Vec::new();
    for stream in ingest.store().streams().await? {
        let Some(name) = stream["stream"].as_str() else {
            continue;
        };
        // The checkpoint stream would attest itself one envelope behind, forever. Checkpointing it
        // is still meaningful — its history must be as tamper-evident as what it attests (§04 §4.5) —
        // but it is emitted last so the run does not chase its own tail.
        if name == checkpoint_stream {
            continue;
        }
        let outcome = emit(ingest, name, checkpoint_stream)
            .await
            .map(|appended| appended.map(|a| a.seq))
            .map_err(|e| e.to_string());
        results.push((name.to_owned(), outcome));
    }
    let self_attestation = emit(ingest, checkpoint_stream, checkpoint_stream)
        .await
        .map(|appended| appended.map(|a| a.seq))
        .map_err(|e| e.to_string());
    results.push((checkpoint_stream.to_owned(), self_attestation));
    Ok(results)
}

/// Run [`emit_all`] forever, once per `policy.checkpoint-interval` (§04 §4.6).
///
/// "The kernel MUST emit a checkpoint per stream at least every `policy.checkpoint-interval`" — so
/// this is a loop the service owns, not an operator's cron entry. The interval is re-read from the
/// policy each tick, so publishing a policy that checkpoints more often takes effect without a
/// restart. Failures are logged and the loop continues: a stream that cannot be checkpointed now
/// must not stop every other stream from being checkpointed.
pub async fn run_interval(ingest: Ingest, checkpoint_stream: String) {
    loop {
        let seconds = match ingest.store().current_policy().await {
            Ok(Some(document)) => crate::policy::Policy::parse(&document, ingest.policy_key())
                .map_or(3_600, |policy| policy.checkpoint_interval_seconds()),
            // With no policy in force there is nothing to checkpoint yet, and nothing has been
            // appended that could need it. Wait a short while and look again.
            Ok(None) => 60,
            Err(e) => {
                tracing::error!(error = %e, "cannot read the policy for the checkpoint interval");
                60
            }
        };
        tokio::time::sleep(std::time::Duration::from_secs(
            u64::try_from(seconds).unwrap_or(3_600).max(1),
        ))
        .await;

        match emit_all(&ingest, &checkpoint_stream).await {
            Ok(results) => {
                for (stream, outcome) in results {
                    match outcome {
                        Ok(Some(seq)) => {
                            tracing::info!(stream = %stream, seq, "checkpointed");
                        }
                        Ok(None) => {}
                        Err(reason) => {
                            tracing::error!(stream = %stream, %reason, "checkpoint failed");
                        }
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "the checkpoint run could not list streams"),
        }
    }
}

/// Payload decay, with the checkpoint that must precede it (§04 §4.6, §5.4).
///
/// "Deletion MUST be preceded by a checkpoint of every affected stream", so the pre-deletion head is
/// publicly fixed before any payload disappears. This function will not delete anything if a required
/// checkpoint fails.
///
/// # Errors
///
/// [`crate::codes::STORE_UNAVAILABLE`], or the reason a required checkpoint could not be emitted.
pub async fn decay_with_checkpoints(
    ingest: &Ingest,
    checkpoint_stream: &str,
) -> Result<DecayReport> {
    let now = ingest.clock().now();
    let affected = ingest.store().streams_with_expiring_payloads(&now).await?;
    let mut checkpointed = Vec::new();
    for stream in &affected {
        if let Some(appended) = emit(ingest, stream, checkpoint_stream).await? {
            checkpointed.push(format!("{stream}@{}", appended.seq));
        }
    }
    let deleted = ingest.store().decay_payloads(&now).await?;
    Ok(DecayReport {
        at: now,
        streams_checkpointed: checkpointed,
        payloads_deleted: deleted.len(),
        // The hashes stay resolvable as commitments: an auditor who independently holds the content
        // can still prove it is the content that was recorded (§04 §5.4).
        deleted_hashes: deleted,
    })
}

/// What a decay run did.
#[derive(Debug, Clone)]
pub struct DecayReport {
    /// When the run happened.
    pub at: String,
    /// Streams whose head was fixed before deletion.
    pub streams_checkpointed: Vec<String>,
    /// How many payloads were erased.
    pub payloads_deleted: usize,
    /// Which hashes are now decayed — still present in every envelope that committed to them.
    pub deleted_hashes: Vec<String>,
}

/// Rejection codes are `&'static str` in [`stozher_core::error::Error`], and a reason travelling back
/// from ingest is an owned `String`. Rather than leak an allocation per call, map the ones this
/// module can actually provoke and fall back to a generic marker.
fn leak_code(reason: &str) -> &'static str {
    match reason {
        "checkpoint-count-mismatch" => "checkpoint-count-mismatch",
        "checkpoint-head-mismatch" => "checkpoint-head-mismatch",
        "checkpoint-range-discontinuous" => "checkpoint-range-discontinuous",
        "checkpoint-signer-not-kernel" => "checkpoint-signer-not-kernel",
        "chain-seq-duplicate" => "chain-seq-duplicate",
        "chain-seq-gap" => "chain-seq-gap",
        "chain-prev-hash-mismatch" => "chain-prev-hash-mismatch",
        "policy-not-published" => "policy-not-published",
        _ => crate::codes::CHECKPOINT_STREAM_UNKNOWN,
    }
}

/// Verify a stream end to end and check it against every checkpoint recorded for it.
///
/// # Errors
///
/// Any chain code, `checkpoint-head-mismatch`, or [`crate::codes::STORE_UNAVAILABLE`].
pub async fn verify_stream(ingest: &Ingest, stream: &str) -> Result<Value> {
    let store = ingest.store();
    let Some((head_seq, _)) = store.stream_head(stream).await? else {
        return Err(Error::new(
            "chain-empty-range",
            format!("stream {stream} holds no envelopes"),
        ));
    };
    let envelopes = store.range(stream, 0, head_seq).await?;
    let result = crate::ingest::verify_range(&envelopes, stream, None)?;
    let attested = match store.last_checkpoint(stream).await? {
        Some((from_seq, to_seq, head_hash)) => {
            let range = store.range(stream, 0, to_seq).await?;
            let observed = crate::ingest::verify_range(&range, stream, None)?;
            if observed.head_hash != head_hash {
                return Err(Error::new(
                    "checkpoint-head-mismatch",
                    format!(
                        "the checkpoint of {stream}[{from_seq}, {to_seq}] attests {head_hash}, \
                         the chain reproduces {}",
                        observed.head_hash
                    ),
                ));
            }
            serde_json::json!({ "from-seq": from_seq, "to-seq": to_seq, "head-hash": head_hash })
        }
        None => Value::Null,
    };
    Ok(serde_json::json!({
        "stream": stream,
        "count": result.count,
        "head-hash": result.head_hash,
        "anchored": result.anchored,
        "last-checkpoint": attested,
        // Stated in the response because it is the property that matters and is easy to forget:
        // nothing above read a payload.
        "payloads-consulted": 0
    }))
}

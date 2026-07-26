//! Evidence payload binding and decay — `spec/04-chain-and-checkpoints.md` §5.
//!
//! The payload is never inside the signed envelope. Deleting it therefore changes no signed byte,
//! which is why chain integrity is independent of payload presence *by construction* rather than by
//! a tombstone convention. An empty payload set is always valid: a missing payload is a decayed
//! payload, not an error.

use serde_json::Value;

use crate::crypto::sha256_hex;
use crate::error::{Result, err};
use crate::jcs;

/// The JSON media type, for which the payload hash is `object-hash(payload)`.
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// Outcome of validating an ingest record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestOk {
    /// `id()` of the envelope — unchanged by whether payloads were supplied.
    pub envelope_hash: String,
    /// Number of payloads stored.
    pub stored: usize,
    /// True when the envelope references evidence whose payload was not supplied.
    pub decayed: bool,
}

/// Collect every payload hash the envelope commits to.
fn referenced_hashes(envelope: &Value) -> Vec<String> {
    ["evidence", "signal"]
        .iter()
        .filter_map(|parent| envelope.get(*parent))
        .filter_map(|section| section.get("payload-hash"))
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Validate an ingest record: `{ "envelope": …, "payloads": [ … ] }`.
///
/// # Errors
///
/// `payload-hash-mismatch` if a submitted payload does not hash to its declared value,
/// `payload-not-referenced` if the envelope does not commit to it, `schema-missing-member` /
/// `schema-type-mismatch` for malformed records, plus any structural code from the envelope.
pub fn verify_ingest(envelope: &Value, payloads: &[Value]) -> Result<IngestOk> {
    crate::envelope::validate(envelope)?;
    let referenced = referenced_hashes(envelope);

    for payload in payloads {
        let declared = payload
            .get("payload-hash")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("schema-missing-member", "payloads[].payload-hash"))?;
        let media_type = payload
            .get("media-type")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("schema-missing-member", "payloads[].media-type"))?;
        let body = payload
            .get("payload")
            .ok_or_else(|| err!("schema-missing-member", "payloads[].payload"))?;

        let computed = if media_type == JSON_MEDIA_TYPE {
            jcs::object_hash(body)?
        } else {
            let hex_body = body.as_str().ok_or_else(|| {
                err!(
                    "schema-type-mismatch",
                    "a non-JSON payload must be a lowercase hex string"
                )
            })?;
            let octets = hex::decode(hex_body)
                .map_err(|e| err!("encoding-not-lowercase-hex", "payloads[].payload: {e}"))?;
            if hex_body.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(err!(
                    "encoding-not-lowercase-hex",
                    "payloads[].payload is not lowercase"
                ));
            }
            sha256_hex(&octets)
        };

        if computed != declared {
            return Err(err!(
                "payload-hash-mismatch",
                "payload hashes to {computed}, declared {declared}"
            ));
        }
        if !referenced.contains(&declared.to_owned()) {
            return Err(err!(
                "payload-not-referenced",
                "payload {declared} is not referenced by the envelope"
            ));
        }
    }

    let supplied: Vec<&str> = payloads
        .iter()
        .filter_map(|p| p.get("payload-hash"))
        .filter_map(Value::as_str)
        .collect();
    let decayed = referenced
        .iter()
        .any(|hash| !supplied.contains(&hash.as_str()));

    Ok(IngestOk {
        envelope_hash: crate::signed::object_id(envelope)?,
        stored: payloads.len(),
        decayed,
    })
}

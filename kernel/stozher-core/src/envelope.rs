//! Envelope structural validation — `spec/02-envelope.md`.
//!
//! Validation is strict and closed: unknown members are rejected rather than ignored, and the
//! member sets per `kind` are what make "there is no boolean anywhere that means approved" a
//! mechanical property rather than a promise (§00 §4).

use serde_json::Value;

use crate::crypto::is_digest_hex;
use crate::error::{Result, err};
use crate::signed::KeyId;

/// The four weight classes. The taxonomy is closed.
pub const CLASSES: [&str; 4] = ["read", "benign", "consequential", "prohibited"];
/// The five execution outcomes. Refusals are records, so they are outcomes, not absences.
pub const OUTCOMES: [&str; 5] = ["applied", "failed", "denied", "blocked", "attempted"];
/// The nine envelope kinds (§02 §2). Closed, and named here so a reader — a console filter, a
/// report — can offer the vocabulary instead of asking someone to recall it.
pub const KINDS: [&str; 9] = [
    "effect",
    "policy-change",
    "aggregate",
    "cognition",
    "signal",
    "mandate",
    "revocation",
    "gate-decision",
    "checkpoint",
];
/// The wire version this implementation speaks.
pub const VERSION: &str = "stozher/0.1";
/// Largest integer a protocol object may carry (§01 §2.5).
pub const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;
/// Maximum length in octets of `correlation-ref`.
pub const CORRELATION_REF_MAX: usize = 512;

/// The most distinct actions one `aggregate` window may fold.
///
/// `spec/02 §7` bounds `sample-hashes` at 16 but leaves `counts.by-action` unbounded, which makes
/// one envelope an unbounded amount of work for every consumer that iterates it — including the
/// kernel's own mandate walk, which does a signature-verifying ancestry query per distinct action.
///
/// 1024 is chosen so that `i64` accumulation over the counts cannot leave its range even in
/// principle: `check_numbers` caps each count at [`MAX_SAFE_INTEGER`], and
/// `1024 * MAX_SAFE_INTEGER` is 9223372036854774784, which is below `i64::MAX`, while 1025 of them
/// is not. It is also two orders of magnitude above any real window: `by-action` keys are
/// `<manifest name>.<action>` identifiers, so the cardinality is bounded in practice by how many
/// distinct actions one component declares, not by traffic.
pub const AGGREGATE_MAX_ACTIONS: usize = 1024;

/// `counts.by-action` folds more than [`AGGREGATE_MAX_ACTIONS`] distinct actions.
///
/// Implementation-local, hence the `x-` prefix: `spec/02 §9.1` tabulates no code for this because
/// it states no bound. It is registered alongside the kernel's other local codes in
/// `stozher_kernel::codes::REGISTER` so the set stays reviewable in one place.
pub const AGGREGATE_CARDINALITY: &str = "x-aggregate-cardinality";

const COMMON: [&str; 8] = [
    "v",
    "kind",
    "emitted-at",
    "stream",
    "seq",
    "prev-hash",
    "identity",
    "sig",
];

struct KindSpec {
    required: &'static [&'static str],
    optional: &'static [&'static str],
    forbidden: &'static [&'static str],
    forbidden_code: &'static str,
}

fn kind_spec(kind: &str) -> Option<KindSpec> {
    Some(match kind {
        "effect" => KindSpec {
            required: &[
                "mandate-ref",
                "policy-version",
                "classification",
                "execution",
            ],
            optional: &[
                "evidence",
                "authorization",
                "trigger",
                "memory-ref",
                "commitment-ref",
                "correlation-ref",
            ],
            forbidden: &[],
            forbidden_code: "",
        },
        "policy-change" => KindSpec {
            required: &[
                "mandate-ref",
                "policy-version",
                "classification",
                "execution",
                "authorization",
            ],
            optional: &["evidence", "memory-ref", "correlation-ref"],
            forbidden: &[],
            forbidden_code: "",
        },
        "aggregate" => KindSpec {
            required: &[
                "mandate-ref",
                "policy-version",
                "classification",
                "window",
                "counts",
                "sample-hashes",
            ],
            optional: &["correlation-ref", "memory-ref"],
            forbidden: &["execution", "evidence", "authorization"],
            forbidden_code: "schema-unknown-member",
        },
        "cognition" => KindSpec {
            required: &["mandate-ref", "resource", "cost"],
            optional: &["policy-version", "correlation-ref"],
            forbidden: &[
                "execution",
                "evidence",
                "classification",
                "authorization",
                "commitment-ref",
            ],
            forbidden_code: "cognition-envelope-has-effect-fields",
        },
        "signal" => KindSpec {
            required: &["signal"],
            optional: &["correlation-ref"],
            forbidden: &[
                "mandate-ref",
                "classification",
                "execution",
                "evidence",
                "authorization",
                "commitment-ref",
            ],
            forbidden_code: "signal-envelope-has-effect-fields",
        },
        "mandate" => KindSpec {
            required: &["mandate"],
            optional: &[],
            forbidden: &[],
            forbidden_code: "",
        },
        "revocation" => KindSpec {
            required: &["revokes", "revoked-at"],
            optional: &["reason"],
            forbidden: &[],
            forbidden_code: "",
        },
        "gate-decision" => KindSpec {
            required: &["decision-of"],
            optional: &["decision"],
            forbidden: &[],
            forbidden_code: "",
        },
        "checkpoint" => KindSpec {
            required: &["checkpoint"],
            optional: &[],
            forbidden: &[],
            forbidden_code: "",
        },
        _ => return None,
    })
}

/// `(required, optional)` members of a known sub-object, if it is one this version models.
fn sub_object_spec(name: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match name {
        "identity" => (&["subject", "key", "component"], &[]),
        "execution" => (
            &[
                "action",
                "target",
                "args-hash",
                "outcome",
                "started-at",
                "finished-at",
            ],
            &[],
        ),
        "evidence" => (
            &["schema", "media-type", "payload-hash", "retain-until"],
            &[],
        ),
        "authorization" => (&["request", "decision"], &[]),
        "sig" => (&["alg", "key", "value"], &[]),
        "resource" => (&["kind", "name"], &[]),
        "window" => (&["from", "to"], &[]),
        "counts" => (&["total", "by-action"], &[]),
        "trigger" => (&["signal-ref", "standing-mandate-ref"], &["rule"]),
        "commitment-ref" => (&["object-type", "object-id", "transition"], &[]),
        "signal" => (
            &[
                "source",
                "received-at",
                "media-type",
                "payload-hash",
                "sender-verified",
            ],
            &["source-ref", "retain-until", "sender-verification"],
        ),
        _ => return None,
    })
}

const COST_DIMENSIONS: [&str; 6] = [
    "tokens",
    "tokens-in",
    "tokens-out",
    "requests",
    "wall-clock-ms",
    "wall-clock-seconds",
];

/// Validate an envelope's structure (§02 §9).
///
/// Signature verification is deliberately *not* part of this function: ingest verifies the
/// signature over the received bytes first, then validates structure (§02 §9.2). The one
/// signature-adjacent check here is `identity.key == sig.key`, which is a consistency rule about
/// the envelope's own claims rather than a cryptographic one.
///
/// # Errors
///
/// One of the structural codes tabulated in §02 §9.1, or an encoding code from §01 §2.
pub fn validate(envelope: &Value) -> Result<()> {
    let map = envelope
        .as_object()
        .ok_or_else(|| err!("schema-type-mismatch", "an envelope must be a JSON object"))?;

    // (2) version
    match map.get("v").map(|v| v.as_str()) {
        Some(Some(VERSION)) => {}
        Some(Some(other)) => return Err(err!("envelope-version-unsupported", "v is {other:?}")),
        Some(None) => return Err(err!("schema-type-mismatch", "v must be a string")),
        None => return Err(err!("schema-missing-member", "v")),
    }

    // (3) kind
    let kind = match map.get("kind").map(|v| v.as_str()) {
        Some(Some(k)) => k,
        Some(None) => return Err(err!("schema-type-mismatch", "kind must be a string")),
        None => return Err(err!("schema-missing-member", "kind")),
    };
    let spec = kind_spec(kind).ok_or_else(|| err!("envelope-unknown-kind", "kind {kind:?}"))?;

    // (4) members forbidden for this kind, reported with the kind's own code
    for forbidden in spec.forbidden {
        if map.contains_key(*forbidden) {
            return Err(err!(
                spec.forbidden_code,
                "{kind} envelope carries {forbidden}"
            ));
        }
    }

    // (5) unknown top-level members
    for key in map.keys() {
        let known = COMMON.contains(&key.as_str())
            || spec.required.contains(&key.as_str())
            || spec.optional.contains(&key.as_str());
        if !known {
            return Err(err!("schema-unknown-member", "{key}"));
        }
    }

    // (6) required top-level members
    for required in COMMON.iter().chain(spec.required.iter()) {
        if !map.contains_key(*required) {
            return Err(err!("schema-missing-member", "{required}"));
        }
    }

    // (7) sub-objects
    for (name, value) in map {
        if name == "cost" {
            validate_cost(value)?;
            continue;
        }
        let Some((required, optional)) = sub_object_spec(name) else {
            continue;
        };
        let sub = value
            .as_object()
            .ok_or_else(|| err!("schema-type-mismatch", "{name} must be an object"))?;
        for key in sub.keys() {
            if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
                return Err(err!("schema-unknown-member", "{name}.{key}"));
            }
        }
        for req in required {
            if !sub.contains_key(*req) {
                return Err(err!("schema-missing-member", "{name}.{req}"));
            }
        }
    }

    // (8) every number is an integer in the safe range
    check_numbers(envelope, "")?;

    // (9) digest-shaped members are lowercase hex
    for path in ["mandate-ref", "prev-hash"] {
        if let Some(v) = map.get(path).filter(|v| !v.is_null()) {
            require_digest(v, path)?;
        }
    }
    for (parent, child) in [
        ("execution", "args-hash"),
        ("evidence", "payload-hash"),
        ("signal", "payload-hash"),
    ] {
        if let Some(v) = map.get(parent).and_then(|p| p.get(child)) {
            require_digest(v, child)?;
        }
    }
    if let Some(trigger) = map.get("trigger") {
        for child in ["signal-ref", "standing-mandate-ref"] {
            if let Some(v) = trigger.get(child) {
                require_digest(v, child)?;
            }
        }
    }
    if let Some(samples) = map.get("sample-hashes") {
        let list = samples
            .as_array()
            .ok_or_else(|| err!("schema-type-mismatch", "sample-hashes must be an array"))?;
        for sample in list {
            require_digest(sample, "sample-hashes[]")?;
        }
    }

    // (10) timestamps
    require_timestamp(&map["emitted-at"], "emitted-at")?;
    for (parent, child) in [
        ("execution", "started-at"),
        ("execution", "finished-at"),
        ("evidence", "retain-until"),
        ("window", "from"),
        ("window", "to"),
        ("signal", "received-at"),
        ("signal", "retain-until"),
    ] {
        if let Some(v) = map.get(parent).and_then(|p| p.get(child)) {
            require_timestamp(v, child)?;
        }
    }

    // (11) stream and chain position
    let stream = map["stream"]
        .as_str()
        .ok_or_else(|| err!("schema-type-mismatch", "stream must be a string"))?;
    validate_stream_id(stream)?;
    let seq = map["seq"]
        .as_u64()
        .ok_or_else(|| err!("schema-type-mismatch", "seq must be a non-negative integer"))?;
    let prev_is_null = map["prev-hash"].is_null();
    if seq == 0 && !prev_is_null {
        return Err(err!(
            "chain-genesis-prev-not-null",
            "seq 0 must have prev-hash null"
        ));
    }
    if seq > 0 && prev_is_null {
        return Err(err!(
            "chain-prev-hash-missing",
            "seq {seq} must carry a predecessor hash"
        ));
    }

    // (12) the envelope is signed by the subject it names
    let identity_key = map["identity"]
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "identity.key"))?;
    KeyId::parse(identity_key)?;
    let sig_key = map["sig"]
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "sig.key"))?;
    if identity_key != sig_key {
        return Err(err!(
            "identity-key-sig-mismatch",
            "identity.key {identity_key} != sig.key {sig_key}"
        ));
    }

    // (13) classification
    if let Some(class) = map.get("classification") {
        let class = class
            .as_str()
            .ok_or_else(|| err!("schema-type-mismatch", "classification must be a string"))?;
        if !CLASSES.contains(&class) {
            return Err(err!(
                "envelope-classification-unknown",
                "classification {class:?}"
            ));
        }
    }

    // (14) execution
    if let Some(execution) = map.get("execution") {
        let outcome = execution
            .get("outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("schema-type-mismatch", "execution.outcome must be a string"))?;
        if !OUTCOMES.contains(&outcome) {
            return Err(err!(
                "envelope-outcome-unknown",
                "execution.outcome {outcome:?}"
            ));
        }
        let started = execution["started-at"].as_str().unwrap_or_default();
        let finished = execution["finished-at"].as_str().unwrap_or_default();
        if finished < started {
            return Err(err!(
                "execution-time-inverted",
                "{finished} precedes {started}"
            ));
        }
    }

    // (15) aggregation record arithmetic
    if kind == "aggregate" {
        validate_aggregate(
            map.get("classification"),
            &map["counts"],
            &map["sample-hashes"],
        )?;
    }

    // (16) correlation-ref is opaque, bounded, and never interpreted
    if let Some(correlation) = map.get("correlation-ref") {
        let s = correlation
            .as_str()
            .ok_or_else(|| err!("schema-type-mismatch", "correlation-ref must be a string"))?;
        if s.len() > CORRELATION_REF_MAX {
            return Err(err!(
                "correlation-ref-too-long",
                "{} octets exceeds {CORRELATION_REF_MAX}",
                s.len()
            ));
        }
    }

    Ok(())
}

fn validate_aggregate(
    classification: Option<&Value>,
    counts: &Value,
    samples: &Value,
) -> Result<()> {
    if classification.and_then(Value::as_str) != Some("read") {
        return Err(err!(
            "aggregate-class-not-read",
            "only class read may be aggregated"
        ));
    }
    let total = counts["total"]
        .as_i64()
        .ok_or_else(|| err!("schema-type-mismatch", "counts.total must be an integer"))?;
    let by_action = counts["by-action"]
        .as_object()
        .ok_or_else(|| err!("schema-type-mismatch", "counts.by-action must be an object"))?;
    if by_action.len() > AGGREGATE_MAX_ACTIONS {
        return Err(err!(
            AGGREGATE_CARDINALITY,
            "{} distinct actions exceeds {AGGREGATE_MAX_ACTIONS}",
            by_action.len()
        ));
    }
    // Accumulated in `i128`, not `i64`. Each count is already bounded at `MAX_SAFE_INTEGER` by
    // `check_numbers`, but the *sum* of many of them is not, and an accumulator that wraps turns
    // `aggregate-count-mismatch` into a check an emitter can choose to pass: land the wrap on the
    // declared total and a window of 1.8e19 reads records as one.
    let mut sum: i128 = 0;
    for value in by_action.values() {
        sum += i128::from(value.as_i64().ok_or_else(|| {
            err!(
                "schema-type-mismatch",
                "counts.by-action values must be integers"
            )
        })?);
    }
    if sum != i128::from(total) {
        return Err(err!(
            "aggregate-count-mismatch",
            "total {total} != sum {sum}"
        ));
    }
    let samples = samples
        .as_array()
        .ok_or_else(|| err!("schema-type-mismatch", "sample-hashes must be an array"))?;
    if samples.is_empty() || samples.len() > 16 {
        return Err(err!(
            "aggregate-sample-bounds",
            "{} samples, expected 1..=16",
            samples.len()
        ));
    }
    Ok(())
}

fn validate_cost(cost: &Value) -> Result<()> {
    let map = cost
        .as_object()
        .ok_or_else(|| err!("schema-type-mismatch", "cost must be an object"))?;
    for (key, value) in map {
        if let Some(currency) = key.strip_prefix("money-") {
            if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(err!("schema-unknown-member", "cost.{key}"));
            }
            if !value.is_string() {
                return Err(err!(
                    "schema-type-mismatch",
                    "cost.{key} must be a decimal string"
                ));
            }
        } else if !COST_DIMENSIONS.contains(&key.as_str()) {
            return Err(err!("schema-unknown-member", "cost.{key}"));
        }
    }
    Ok(())
}

fn validate_stream_id(stream: &str) -> Result<()> {
    let ok = !stream.is_empty()
        && stream.len() <= 128
        && stream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(err!("stream-id-malformed", "stream {stream:?}"))
    }
}

fn require_digest(value: &Value, what: &str) -> Result<()> {
    let s = value
        .as_str()
        .ok_or_else(|| err!("schema-type-mismatch", "{what} must be a string"))?;
    if is_digest_hex(s) {
        Ok(())
    } else {
        Err(err!(
            "encoding-not-lowercase-hex",
            "{what} = {s:?} is not 64 lowercase hex digits"
        ))
    }
}

/// Validate an RFC 3339 UTC timestamp with exactly three fractional digits (§01 §2.3).
fn require_timestamp(value: &Value, what: &str) -> Result<()> {
    let s = value
        .as_str()
        .ok_or_else(|| err!("schema-type-mismatch", "{what} must be a string"))?;
    if is_timestamp(s) {
        Ok(())
    } else {
        Err(err!("encoding-bad-timestamp", "{what} = {s:?}"))
    }
}

/// Whether a string is an RFC 3339 UTC timestamp in §01 §2.3's fixed form.
///
/// The form is fixed-width, so lexicographic order over two of these is chronological order — which
/// is what lets `gate.rs` compare approval windows with `<` and why anything that is *not* one of
/// these must be refused before such a comparison, not after.
#[must_use]
pub fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24 {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| b[range].iter().all(u8::is_ascii_digit);
    if !(digits(0..4)
        && digits(5..7)
        && digits(8..10)
        && digits(11..13)
        && digits(14..16)
        && digits(17..19)
        && digits(20..23))
    {
        return false;
    }
    if !(b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[23] == b'Z')
    {
        return false;
    }
    let num = |range: std::ops::Range<usize>| s[range].parse::<u32>().unwrap_or(u32::MAX);
    (1..=12).contains(&num(5..7))
        && (1..=31).contains(&num(8..10))
        && num(11..13) <= 23
        && num(14..16) <= 59
        && num(17..19) <= 60
}

/// Every JSON number in a protocol object must be an integer in the binary64-exact range.
fn check_numbers(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Number(n) => {
            let as_int = n
                .as_i64()
                .map(i128::from)
                .or_else(|| n.as_u64().map(i128::from));
            match as_int {
                Some(i) if i.abs() <= MAX_SAFE_INTEGER => Ok(()),
                Some(i) => Err(err!(
                    "encoding-integer-out-of-range",
                    "{path} = {i} exceeds the safe integer range"
                )),
                None => Err(err!(
                    "encoding-non-integer-number",
                    "{path} = {n} is not an integer"
                )),
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                check_numbers(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, item) in map {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                check_numbers(item, &child)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_named_kind_vocabulary_is_the_one_validation_uses() {
        // `KINDS` exists so a reader can be offered the vocabulary rather than made to recall it,
        // which is only true while it is the same vocabulary `kind_spec` enforces.
        for kind in KINDS {
            assert!(kind_spec(kind).is_some(), "{kind} has no schema");
        }
        assert!(kind_spec("park-request").is_none());
    }

    #[test]
    fn timestamp_format_is_exact() {
        assert!(is_timestamp("2026-07-26T09:15:01.300Z"));
        assert!(!is_timestamp("2026-07-26T09:15:01Z"));
        assert!(!is_timestamp("2026-07-26T11:15:01.300+02:00"));
        assert!(!is_timestamp("2026-13-26T09:15:01.300Z"));
        assert!(!is_timestamp("2026-07-26t09:15:01.300z"));
    }

    #[test]
    fn there_is_no_kind_in_which_a_boolean_could_mean_approved() {
        for kind in [
            "effect",
            "cognition",
            "aggregate",
            "signal",
            "policy-change",
        ] {
            let spec = kind_spec(kind).unwrap();
            for member in spec.required.iter().chain(spec.optional.iter()) {
                assert_ne!(*member, "approved");
                assert!(!member.contains("bypass"));
            }
        }
    }
}

//! The kernel-native pending queue — `spec/06-gates.md` §1.1 and §4.3.
//!
//! # What ADR-0008 §A asked, and what this answers
//!
//! §06 §4.3 obliges the kernel to "record the parked request, notify the approvers … and expose it
//! in the console pending queue", but the party that knows a park happened is the *emitting
//! component*, and `spec/02 §2`'s `kind` vocabulary is closed with no member for one. ADR-0008 §A
//! left two ways out: give `spec/02` a `park-request` kind, or give `spec/06` a request-submission
//! route. **This module is the second.**
//!
//! It is the reading `spec/06 §1.1` already implies: *"The action request is **not** signed by the
//! subject in `stozher/0.1`; it is submitted over an authenticated channel (§10 §1) … Its integrity
//! as an object comes from `request-hash` being covered by the approver's signature."* The spec had
//! already decided the shape; only the route was missing.
//!
//! Why not a new envelope kind:
//!
//! * §02 §2 states its own admission rule — "everything that **changes what the system will
//!   permit** is itself an audited, chained, signed event". A request changes nothing. It is a
//!   question, and answering it is what changes anything.
//! * An envelope occupies a `seq` on the emitter's chain. A request that later expires unanswered
//!   would hold a chain position for something that never happened, and a park the kernel refused
//!   would wedge that emitter's effect stream for every later envelope (ADR-0007 §6). A question
//!   must not be able to stall the audit.
//! * Nothing is lost. The **decision** is an envelope (§06 §5), and the effect that consumes the
//!   approval embeds this request verbatim in `authorization.request` (§06 §1.3), so an auditor with
//!   a JSON parser and an Ed25519 library can still recompute everything years later.
//!
//! # A queued request is not authority
//!
//! Submitting one appends nothing and permits nothing. [`crate::store::Store::append`] stays
//! crate-private and [`crate::ingest::Ingest::submit`] stays the only path to it; the row this
//! module writes lives in a table with no chain-bearing column. And because the approval binds
//! `request.key` (§06 §2 step 10), a caller that submits a request naming a subject whose key it
//! does not hold has asked a question it can never act on — which is why the kernel records *who
//! submitted* alongside *who the request claims*, and the console shows both.

use serde_json::Value;
use stozher_core::crypto::is_digest_hex;
use stozher_core::envelope::CLASSES;
use stozher_core::error::{Error, Result};
use stozher_core::signed::KeyId;
use stozher_core::{jcs, signed};

use crate::clock;

/// The members of an action request (§06 §1.1). Closed, and every one is REQUIRED.
const MEMBERS: [&str; 14] = [
    "v",
    "kind",
    "requested-at",
    "subject",
    "key",
    "component",
    "mandate-ref",
    "policy-version",
    "classification",
    "action",
    "target",
    "args-hash",
    "nonce",
    "not-after",
];

/// A `nonce` carries at least 128 bits of entropy, so an approval of one request is not an approval
/// of an otherwise identical one (§06 §1.1).
const NONCE_HEX_DIGITS: usize = 32;

/// The members of a submission (§06 §4.4 rule 1). Closed, and only `request` is required.
const SUBMISSION_MEMBERS: [&str; 2] = ["request", "arguments"];

/// §06 §4.4 rule 3 — the canonical form of `arguments` may not exceed this.
///
/// Far above what an approver reads and what a call needs, and the number that can be held at once
/// is already bounded by the per-subject cap of §09 §7.
pub const ARGUMENTS_MAX_BYTES: usize = 16_384;

/// §06 §4.4 rule 4's refusal — the one §4.4 refusal that earns a durable record (rule 9).
///
/// A constant rather than a literal because it is now compared in three places as well as produced
/// in one, and a code that is only ever written out by hand is a rename waiting to reach some of
/// its sites.
pub const ARGUMENTS_HASH_MISMATCH: &str = "gate-arguments-hash-mismatch";

/// Split a `POST /v1/gate/requests` body into the action request and the argument values.
///
/// §06 §4.4 rule 1 admits two spellings and they mean the same thing: a submission object, and a
/// bare action request, which *is* a submission with `arguments` absent. There is one hashed object
/// under either — always `object-hash(request)`, never of the submission — so the ambiguity this
/// project usually refuses (one instant, one spelling) does not arise: no signature covers the outer
/// shape, and the two forms cannot disagree about what was asked.
///
/// The older spelling is kept because refusing it would make an upgrade in which the kernel moves
/// before its components empty the queue, and a request that does not park is a gate no human can
/// see while the call it belongs to stays blocked.
///
/// # Errors
///
/// `schema-type-mismatch` for a body that is not an object or a `request` that is not one, and
/// `schema-unknown-member` for a submission carrying a third member.
pub fn submission(body: &Value) -> Result<(Value, Option<Value>)> {
    let map = body.as_object().ok_or_else(|| {
        Error::new(
            "schema-type-mismatch",
            "a gate-request submission must be an object",
        )
    })?;
    // The two forms are told apart by `request`, which §06 §1.1's closed member set does not
    // contain and a submission requires. Dispatching on its absence rather than on `kind`'s presence
    // keeps every malformed *action request* reaching `validate`, and therefore refused by the code
    // that names the member it is actually missing.
    if !map.contains_key("request") {
        return Ok((body.clone(), None));
    }
    for key in map.keys() {
        if !SUBMISSION_MEMBERS.contains(&key.as_str()) {
            return Err(Error::new("schema-unknown-member", key.clone()));
        }
    }
    let request = map
        .get("request")
        .ok_or_else(|| Error::new("schema-missing-member", "request"))?;
    if !request.is_object() {
        return Err(Error::new(
            "schema-type-mismatch",
            "submission.request must be an action-request object",
        ));
    }
    Ok((request.clone(), map.get("arguments").cloned()))
}

/// Check submitted argument values against the digest the approver's signature will cover, and
/// return the canonical bytes to record — §06 §4.4 rules 3 and 4.
///
/// This is the whole of what makes displaying them safe. Without the hash check a component could
/// show a human one call and execute another, and the display would be worth less than the blank it
/// replaced; with it, what the approver reads is what §06 §2 step (10) enforces, and they can repeat
/// the check themselves with a canonicalizer and SHA-256.
///
/// # Errors
///
/// `gate-arguments-too-large` past [`ARGUMENTS_MAX_BYTES`], `gate-arguments-hash-mismatch` when the
/// values are not what `args-hash` commits to, or a canonicalization failure for values with no
/// canonical form.
pub fn check_arguments(arguments: &Value, args_hash: &str) -> Result<String> {
    let canonical = jcs::canonicalize(arguments)?;
    if canonical.len() > ARGUMENTS_MAX_BYTES {
        return Err(Error::new(
            "gate-arguments-too-large",
            format!(
                "{} bytes of canonical arguments, above the cap of {ARGUMENTS_MAX_BYTES}. Park \
                 without them rather than not parking.",
                canonical.len()
            ),
        ));
    }
    let hash = stozher_core::crypto::sha256_hex(canonical.as_bytes());
    if hash != args_hash {
        return Err(Error::new(
            ARGUMENTS_HASH_MISMATCH,
            format!("the arguments hash to {hash}, and the request commits to {args_hash}"),
        ));
    }
    Ok(canonical)
}

/// A validated action request, flattened into the columns the queue indexes.
#[derive(Debug, Clone)]
pub struct GateRequest {
    /// `object-hash` of the request — what the approver's signature covers.
    pub request_hash: String,
    /// The request object itself, verbatim.
    pub request: Value,
    /// Acting subject the request names.
    pub subject: String,
    /// The key that will sign the effect, and that the approval binds.
    pub subject_key: String,
    /// Emitting component.
    pub component: String,
    /// The mandate the effect will cite.
    pub mandate_ref: String,
    /// The policy version in force when the call was classified.
    pub policy_version: String,
    /// Weight class.
    pub classification: String,
    /// Action type.
    pub action: String,
    /// Thing acted upon.
    pub target: String,
    /// `object-hash` of the call's arguments.
    pub args_hash: String,
    /// When the component built the request.
    pub requested_at: String,
    /// When it stops being answerable (§06 §1.1).
    pub not_after: String,
}

/// Validate an action request and compute its hash.
///
/// Strictness matches ingest's: unknown members are refused rather than ignored, because a member
/// this kernel does not understand is a member the approver was not shown.
///
/// # Errors
///
/// `schema-type-mismatch`, `schema-unknown-member`, `schema-missing-member`,
/// `envelope-version-unsupported`, `envelope-unknown-kind`, `envelope-classification-unknown`,
/// `key-id-malformed`, `encoding-not-lowercase-hex`, `encoding-bad-timestamp`, or
/// `gate-request-expired` for a request that was already dead when it arrived.
pub fn validate(request: &Value, at: &str) -> Result<GateRequest> {
    let map = request.as_object().ok_or_else(|| {
        Error::new(
            "schema-type-mismatch",
            "an action request must be an object",
        )
    })?;
    for key in map.keys() {
        if !MEMBERS.contains(&key.as_str()) {
            return Err(Error::new("schema-unknown-member", key.clone()));
        }
    }
    let text = |name: &str| -> Result<&str> {
        match map.get(name) {
            None => Err(Error::new("schema-missing-member", name.to_owned())),
            Some(Value::String(value)) => Ok(value.as_str()),
            Some(_) => Err(Error::new(
                "schema-type-mismatch",
                format!("{name} must be a string"),
            )),
        }
    };

    if text("v")? != stozher_core::VERSION {
        return Err(Error::new(
            "envelope-version-unsupported",
            format!("an action request is {}", stozher_core::VERSION),
        ));
    }
    if text("kind")? != "action-request" {
        return Err(Error::new(
            "envelope-unknown-kind",
            format!("kind is {:?}, not \"action-request\"", map["kind"]),
        ));
    }

    let subject = text("subject")?;
    if !subject.contains(':') {
        // §02 §3: `<class>:<name>`. The string is a label for humans reading the queue; authority
        // comes from `key` and the mandate chain, never from it.
        return Err(Error::new(
            "schema-type-mismatch",
            "subject must be of the form <class>:<name>",
        ));
    }
    let subject_key = KeyId::parse(text("key")?)?;
    let classification = text("classification")?;
    if !CLASSES.contains(&classification) {
        return Err(Error::new(
            "envelope-classification-unknown",
            classification.to_owned(),
        ));
    }
    for (name, value) in [
        ("mandate-ref", text("mandate-ref")?),
        ("args-hash", text("args-hash")?),
    ] {
        if !is_digest_hex(value) {
            return Err(Error::new(
                "encoding-not-lowercase-hex",
                format!("{name} must be 64 lowercase hex digits"),
            ));
        }
    }
    let nonce = text("nonce")?;
    if nonce.len() != NONCE_HEX_DIGITS || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::new(
            "encoding-not-lowercase-hex",
            "nonce must be 32 lowercase hex digits (128 bits of entropy)",
        ));
    }
    if nonce.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Error::new(
            "encoding-not-lowercase-hex",
            "nonce must be lowercase",
        ));
    }
    let component = text("component")?;
    let policy_version = text("policy-version")?;
    let action = text("action")?;
    let target = text("target")?;
    for (name, value) in [
        ("component", component),
        ("policy-version", policy_version),
        ("action", action),
        ("target", target),
    ] {
        if value.is_empty() {
            return Err(Error::new(
                "schema-missing-member",
                format!("{name} must not be empty"),
            ));
        }
    }

    let requested_at = text("requested-at")?;
    let not_after = text("not-after")?;
    clock::parse_timestamp(requested_at)?;
    clock::parse_timestamp(not_after)?;
    if not_after <= requested_at {
        return Err(Error::new(
            "gate-request-expired",
            format!("not-after {not_after} does not follow requested-at {requested_at}"),
        ));
    }
    // A request that is already dead cannot be answered: §06 §2 step (8) would refuse any decision
    // over it, so accepting it here would put a row in the approver's queue that can only waste
    // their attention.
    if not_after <= at {
        return Err(Error::new(
            "gate-request-expired",
            format!("not-after {not_after} has already passed at {at}"),
        ));
    }

    Ok(GateRequest {
        request_hash: jcs::object_hash(request)?,
        request: request.clone(),
        subject: subject.to_owned(),
        subject_key: subject_key.as_str().to_owned(),
        component: component.to_owned(),
        mandate_ref: text("mandate-ref")?.to_owned(),
        policy_version: policy_version.to_owned(),
        classification: classification.to_owned(),
        action: action.to_owned(),
        target: target.to_owned(),
        args_hash: text("args-hash")?.to_owned(),
        requested_at: requested_at.to_owned(),
        not_after: not_after.to_owned(),
    })
}

/// The members of a gate decision (§06 §1.2). Closed, like the request's.
const DECISION_MEMBERS: [&str; 9] = [
    "v",
    "kind",
    "request-hash",
    "decision",
    "decided-at",
    "not-after",
    "single-use",
    "reason",
    "sig",
];

/// Check an `authorization` object carried *inside an envelope* against §06 §1.1 and §1.2.
///
/// [`validate`] and [`check_decision`] run when a human submits a request or answers one. This runs
/// on the other path — the one a component takes — where the two objects arrive already assembled
/// and, until this exists, met no shape rule at all: `envelope::validate`'s sub-object spec stops at
/// `{request, decision}` and does not descend. The consequence was that §06 §1.1's "unknown members
/// MUST be rejected" was enforced only on the route an attacker has no reason to use.
///
/// This is deliberately *only* the shape. Every semantic check — the hash, the signature,
/// self-approval, both windows, the member-by-member binding — stays in
/// [`stozher_core::gate::verify_authorization`], which is where §06 §2 says it lives.
///
/// # Errors
///
/// `schema-type-mismatch`, `schema-unknown-member`, `schema-missing-member`,
/// `envelope-version-unsupported`, `envelope-unknown-kind`, `envelope-classification-unknown`,
/// `key-id-malformed`, `encoding-not-lowercase-hex`, `encoding-bad-timestamp`, or
/// `gate-request-expired`.
pub fn validate_embedded(authorization: &Value) -> Result<()> {
    let request = authorization
        .get("request")
        .ok_or_else(|| Error::new("schema-missing-member", "authorization.request"))?;
    let decision = authorization
        .get("decision")
        .ok_or_else(|| Error::new("schema-missing-member", "authorization.decision"))?;

    // §06 §1.3 makes `authorization` exactly two members; a third is a member no signature covers.
    if let Some(map) = authorization.as_object() {
        for key in map.keys() {
            if !["request", "decision"].contains(&key.as_str()) {
                return Err(Error::new(
                    "schema-unknown-member",
                    format!("authorization.{key}"),
                ));
            }
        }
    }

    // `requested-at` rather than the envelope's clock: an effect may legitimately be emitted after
    // its request's `not-after` — the *decision's* window is what bounds the effect (§06 §2 step 9)
    // — so judging the request's liveness against the emission instant would refuse valid work. The
    // ordering constraint `not-after > requested-at` is checked either way.
    let requested_at = request
        .get("requested-at")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("schema-missing-member", "requested-at"))?
        .to_owned();
    validate(request, &requested_at)?;

    let map = decision
        .as_object()
        .ok_or_else(|| Error::new("schema-type-mismatch", "a gate decision must be an object"))?;
    for key in map.keys() {
        if !DECISION_MEMBERS.contains(&key.as_str()) {
            return Err(Error::new(
                "schema-unknown-member",
                format!("decision.{key}"),
            ));
        }
    }
    if map.get("v").and_then(Value::as_str) != Some(stozher_core::VERSION) {
        return Err(Error::new(
            "envelope-version-unsupported",
            format!("a gate decision is {}", stozher_core::VERSION),
        ));
    }
    if map.get("kind").and_then(Value::as_str) != Some("gate-decision") {
        return Err(Error::new(
            "envelope-unknown-kind",
            "a decision object is kind \"gate-decision\"",
        ));
    }
    for name in ["request-hash", "decision", "decided-at", "not-after"] {
        let value = map
            .get(name)
            .ok_or_else(|| Error::new("schema-missing-member", format!("decision.{name}")))?;
        if !value.is_string() {
            return Err(Error::new(
                "schema-type-mismatch",
                format!("decision.{name} must be a string"),
            ));
        }
    }
    if !is_digest_hex(map["request-hash"].as_str().unwrap_or_default()) {
        return Err(Error::new(
            "encoding-not-lowercase-hex",
            "decision.request-hash must be 64 lowercase hex digits",
        ));
    }
    // The timestamps `gate.rs` steps (8) and (9) order with `<`. A value that is not one of these
    // makes that comparison meaningless rather than false.
    clock::parse_timestamp(map["decided-at"].as_str().unwrap_or_default())?;
    clock::parse_timestamp(map["not-after"].as_str().unwrap_or_default())?;
    Ok(())
}

/// A decision as the queue records it, already checked against §06 §1.2's shape.
#[derive(Debug, Clone)]
pub struct GateDecision {
    /// The request it answers.
    pub request_hash: String,
    /// `approve` or `deny`.
    pub verdict: String,
    /// Why, REQUIRED for a denial and absent for an approval.
    pub reason: Option<String>,
    /// The key that signed it.
    pub decided_by: KeyId,
    /// When.
    pub decided_at: String,
    /// The signed object, verbatim — this is what travels in the envelope.
    pub decision: Value,
}

/// Check a signed gate decision against §06 §1.2 and against the request it claims to answer.
///
/// This performs the decision-side half of §06 §2 — steps (2), (3), (4), (6), (7) and (8) — at the
/// moment a human submits it, so a decision that could never authorize anything is refused where the
/// human can see the refusal, rather than silently recorded and refused later at ingest. It does
/// **not** replace §06 §2: [`stozher_core::gate::verify_authorization`] still runs in full over the
/// effect envelope that eventually carries this decision, and it is that run, not this one, that
/// permits the effect.
///
/// # Errors
///
/// `gate-authorization-request-hash-mismatch`, `gate-decision-sig-invalid`, `gate-self-approval`,
/// `gate-decision-unknown`, `gate-denial-without-reason`, `gate-request-expired`,
/// `gate-approval-expired`, `schema-missing-member`, or `envelope-unknown-kind`.
pub fn check_decision(decision: &Value, request: &GateRequest) -> Result<GateDecision> {
    if decision.get("kind").and_then(Value::as_str) != Some("gate-decision") {
        return Err(Error::new(
            "envelope-unknown-kind",
            "a decision object is kind \"gate-decision\"",
        ));
    }
    // (2) the signature covers this exact request body.
    if decision.get("request-hash").and_then(Value::as_str) != Some(request.request_hash.as_str()) {
        return Err(Error::new(
            "gate-authorization-request-hash-mismatch",
            format!(
                "the decision does not cover request {}",
                request.request_hash
            ),
        ));
    }
    // (3) it verifies.
    let decided_by = signed::verify_signed_object(decision)
        .map_err(|e| Error::new("gate-decision-sig-invalid", e.detail().to_owned()))?;
    // (4) nobody approves their own action. §06 §5 states this over both the key and the subject;
    // the subject half is checked by the caller, which can resolve an approver's subject.
    if decided_by.as_str() == request.subject_key {
        return Err(Error::new(
            "gate-self-approval",
            format!("{decided_by} decided its own request"),
        ));
    }
    let decided_at = decision
        .get("decided-at")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("schema-missing-member", "decision.decided-at"))?;
    let not_after = decision
        .get("not-after")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("schema-missing-member", "decision.not-after"))?;
    clock::parse_timestamp(decided_at)?;
    clock::parse_timestamp(not_after)?;

    // (6) the vocabulary is closed, and (7) a denial carries its reason.
    let verdict = decision
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("schema-missing-member", "decision.decision"))?;
    let reason = decision.get("reason").and_then(Value::as_str);
    match verdict {
        "approve" => {}
        "deny" => {
            if reason.unwrap_or_default().is_empty() {
                return Err(Error::new(
                    "gate-denial-without-reason",
                    "a denial must state why — the reason is what the agent is owed and what \
                     policy tier 3 learns from",
                ));
            }
        }
        other => {
            return Err(Error::new(
                "gate-decision-unknown",
                format!("decision {other:?}"),
            ));
        }
    }

    // (8) the request had not already timed out when it was decided.
    if decided_at > request.not_after.as_str() {
        return Err(Error::new(
            "gate-request-expired",
            format!(
                "decided at {decided_at}, the request expired at {}",
                request.not_after
            ),
        ));
    }
    // §06 §1.2: `not-after` MUST be after `decided-at`. An approval that is dead on arrival would
    // fail step (9) for every effect, so it is refused where the approver can still fix it.
    if not_after <= decided_at {
        return Err(Error::new(
            "gate-approval-expired",
            format!("the approval window [{decided_at}, {not_after}] is empty"),
        ));
    }

    Ok(GateDecision {
        request_hash: request.request_hash.clone(),
        verdict: verdict.to_owned(),
        reason: reason.map(str::to_owned),
        decided_by,
        decided_at: decided_at.to_owned(),
        decision: decision.clone(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const AT: &str = "2026-07-26T09:00:00.000Z";

    fn request() -> Value {
        json!({
            "v": stozher_core::VERSION,
            "kind": "action-request",
            "requested-at": AT,
            "subject": "agent:claude-code/ivan-mbp",
            "key": format!("ed25519:{}", "aa".repeat(32)),
            "component": "gateway",
            "mandate-ref": "7c".repeat(32),
            "policy-version": "2026.07.1",
            "classification": "consequential",
            "action": "github.create_issue",
            "target": "repo:acme/backend",
            "args-hash": "91".repeat(32),
            "nonce": "0f".repeat(16),
            "not-after": "2026-07-26T10:00:00.000Z"
        })
    }

    #[test]
    fn a_well_formed_request_validates_and_hashes_to_its_object_hash() {
        let value = request();
        let ok = validate(&value, AT).unwrap();
        assert_eq!(ok.request_hash, jcs::object_hash(&value).unwrap());
        assert_eq!(ok.action, "github.create_issue");
    }

    #[test]
    fn an_unknown_member_is_refused_rather_than_ignored() {
        let mut value = request();
        value["approved"] = Value::Bool(true);
        // The point is not that this member would have been believed — nothing reads it — but that
        // a request carrying a member the approver was never shown is not the request they approve.
        assert_eq!(
            validate(&value, AT).unwrap_err().code(),
            "schema-unknown-member"
        );
    }

    #[test]
    fn every_member_is_required() {
        for member in MEMBERS {
            let mut value = request();
            value.as_object_mut().unwrap().remove(member);
            assert_eq!(
                validate(&value, AT).unwrap_err().code(),
                "schema-missing-member",
                "{member} was not required"
            );
        }
    }

    #[test]
    fn a_short_nonce_is_refused_because_it_is_what_makes_two_requests_distinct() {
        let mut value = request();
        value["nonce"] = Value::from("0f0f");
        assert_eq!(
            validate(&value, AT).unwrap_err().code(),
            "encoding-not-lowercase-hex"
        );
    }

    #[test]
    fn a_request_that_is_already_dead_never_enters_the_queue() {
        let value = request();
        assert_eq!(
            validate(&value, "2026-07-26T11:00:00.000Z")
                .unwrap_err()
                .code(),
            "gate-request-expired"
        );
    }
}

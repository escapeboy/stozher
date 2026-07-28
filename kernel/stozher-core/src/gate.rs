//! Gate authorization verification — `spec/06-gates.md` §2.
//!
//! This module is the whole answer to ADR-0002's anti-lesson. There is no function here that takes
//! a boolean, no flag that suppresses a check, and no code path that satisfies `requires_gate`
//! other than a verified signature over the request hash. If you are reading this to add a bypass
//! for a re-execution path: the approval object is data — carry it with the work (§06 §3).

use std::collections::HashSet;

use serde_json::Value;

use crate::envelope::is_timestamp;
use crate::error::{Result, err};
use crate::jcs;
use crate::signed::{KeyId, verify_signed_object};

/// A key permitted to approve a scope, and the subject it signs as.
///
/// §06 §5 states self-approval as two conjoined MUSTs — `decision.sig.key` MUST NOT equal
/// `request.key`, **and** the approver subject MUST NOT be the requesting subject. The second is
/// checkable only if the verifier can name the human behind the key, and a caller that resolved
/// these keys resolved them *from* subjects (§06 §5: "entries name subjects; the permitted keys are
/// those subjects' enrolled keys"), so it already holds the answer. Carrying it here is what stops
/// this module from having to ask the store a question a library has no business asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    /// The key permitted to sign a decision.
    pub key: KeyId,
    /// The subject that key acts as, when the deployment can name one.
    pub subject: Option<String>,
}

impl Approver {
    /// An approver whose subject is known.
    #[must_use]
    pub fn named(key: KeyId, subject: impl Into<String>) -> Self {
        Self {
            key,
            subject: Some(subject.into()),
        }
    }
}

/// A verified authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationOk {
    /// `object-hash` of the action request the approval covers.
    pub request_hash: String,
    /// The key of the human who signed the approval.
    pub decided_by: KeyId,
    /// Whether the approval may be used more than once.
    pub single_use: bool,
}

/// The nine envelope members an approval binds, plus the two paths they live at.
const BOUND: [(&str, &[&str]); 9] = [
    ("subject", &["identity", "subject"]),
    ("key", &["identity", "key"]),
    ("component", &["identity", "component"]),
    ("mandate-ref", &["mandate-ref"]),
    ("policy-version", &["policy-version"]),
    ("classification", &["classification"]),
    ("action", &["execution", "action"]),
    ("target", &["execution", "target"]),
    ("args-hash", &["execution", "args-hash"]),
];

/// Verify the `authorization` member of an envelope.
///
/// `requires_gate` is the policy decision for this envelope (§05 §3 step 4). `approvers` are the
/// keys permitted to approve this scope. `seen_request_hashes` is the kernel's replay set.
///
/// Returns `Ok(None)` when there is nothing to verify and nothing was required.
///
/// # Errors
///
/// The `gate-*` codes of §06 §2, in the normative order.
pub fn verify_authorization(
    envelope: &Value,
    requires_gate: bool,
    approvers: &[Approver],
    seen_request_hashes: &HashSet<String>,
) -> Result<Option<AuthorizationOk>> {
    // (1) A gated effect without an approval signature is rejected. This is the only step that is
    // conditional on policy, and it is the step that has no alternative satisfaction path.
    let Some(authorization) = envelope.get("authorization") else {
        if requires_gate {
            return Err(err!(
                "gate-authorization-missing",
                "a gated action carries no approval signature"
            ));
        }
        return Ok(None);
    };

    let request = authorization
        .get("request")
        .ok_or_else(|| err!("schema-missing-member", "authorization.request"))?;
    let decision = authorization
        .get("decision")
        .ok_or_else(|| err!("schema-missing-member", "authorization.decision"))?;

    // (2) the signature covers this exact request body
    let request_hash = jcs::object_hash(request)?;
    let claimed_hash = decision
        .get("request-hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            err!(
                "schema-missing-member",
                "authorization.decision.request-hash"
            )
        })?;
    if request_hash != claimed_hash {
        return Err(err!(
            "gate-authorization-request-hash-mismatch",
            "request hashes to {request_hash}, decision covers {claimed_hash}"
        ));
    }

    // (3) the approver's signature verifies
    let decided_by = verify_signed_object(decision)
        .map_err(|e| err!("gate-decision-sig-invalid", "{}", e.detail()))?;

    // (4) nobody approves their own action — §06 §5 states this over the key *and* the subject.
    let requester = request
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "authorization.request.key"))?;
    if decided_by.as_str() == requester {
        return Err(err!(
            "gate-self-approval",
            "{decided_by} approved its own request"
        ));
    }
    // A human holding a second key is still one human, and "escalation terminates at a named human"
    // (maxim 3) is about the person, not the keypair. The keypair comparison above is satisfied by
    // any second key, which is the cheapest thing in the protocol to mint — so on its own it stops
    // nobody. An approver whose subject the caller could not name is left to step (5), which is
    // where a key nobody can place is refused anyway.
    let approver = approvers
        .iter()
        .find(|candidate| candidate.key == decided_by);
    if let (Some(acting_as), Some(requested_by)) = (
        approver.and_then(|a| a.subject.as_deref()),
        request.get("subject").and_then(Value::as_str),
    ) {
        if acting_as == requested_by {
            return Err(err!(
                "gate-self-approval",
                "{decided_by} acts as {acting_as}, the subject that requested the action"
            ));
        }
    }

    // (5) the approver is permitted to approve this scope
    if approver.is_none() {
        return Err(err!(
            "gate-approver-not-permitted",
            "{decided_by} is not an approver here"
        ));
    }

    // (6) the decision vocabulary is closed
    let verdict = decision
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "authorization.decision.decision"))?;
    match verdict {
        "approve" => {}
        "deny" => {
            // (7) a denial must carry its reason, and is never authorization
            let reason = decision
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if reason.is_empty() {
                return Err(err!(
                    "gate-denial-without-reason",
                    "a denial must state why"
                ));
            }
            return Err(err!("gate-denied", "denied by {decided_by}: {reason}"));
        }
        other => return Err(err!("gate-decision-unknown", "decision {other:?}")),
    }

    let decided_at = decision
        .get("decided-at")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "authorization.decision.decided-at"))?;
    let decision_not_after = decision
        .get("not-after")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "authorization.decision.not-after"))?;
    let request_not_after = request
        .get("not-after")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "authorization.request.not-after"))?;

    // Steps (8) and (9) compare timestamps as strings, which is exact for §01 §2.3's fixed-width
    // form and meaningless for anything else: `"z"` sorts above every real timestamp, so an approval
    // bounded by it is bounded by nothing and step (9) becomes vacuous. Nothing upstream is entitled
    // to have checked these — `envelope::validate` does not descend into `authorization` — so the
    // comparison validates its own operands rather than assuming someone else did.
    let at = envelope
        .get("emitted-at")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "emitted-at"))?;
    for (what, value) in [
        ("authorization.decision.decided-at", decided_at),
        ("authorization.decision.not-after", decision_not_after),
        ("authorization.request.not-after", request_not_after),
        ("emitted-at", at),
    ] {
        if !is_timestamp(value) {
            return Err(err!("encoding-bad-timestamp", "{what} = {value:?}"));
        }
    }

    // (8) the request had not already timed out when it was decided
    if decided_at > request_not_after {
        return Err(err!(
            "gate-request-expired",
            "decided at {decided_at}, request expired at {request_not_after}"
        ));
    }

    // (9) the effect happened inside the approval's window
    if at < decided_at || at > decision_not_after {
        return Err(err!(
            "gate-approval-expired",
            "emitted at {at}, approval valid [{decided_at}, {decision_not_after}]"
        ));
    }

    // (10) the effect IS the approved effect, member by member
    for (request_member, envelope_path) in BOUND {
        let approved = request.get(request_member).and_then(Value::as_str);
        let mut cursor = Some(envelope);
        for key in envelope_path {
            cursor = cursor.and_then(|value| value.get(*key));
        }
        let performed = cursor.and_then(Value::as_str);
        if approved != performed {
            return Err(err!(
                "gate-authorization-action-mismatch",
                "{request_member}: approved {approved:?}, performed {performed:?}"
            ));
        }
    }

    // (11) single use
    let single_use = decision
        .get("single-use")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if single_use && seen_request_hashes.contains(&request_hash) {
        return Err(err!(
            "gate-authorization-replayed",
            "request {request_hash} was already used"
        ));
    }

    Ok(Some(AuthorizationOk {
        request_hash,
        decided_by,
        single_use,
    }))
}

/// `request-hash` of an action request (§06 §1.1).
///
/// # Errors
///
/// Propagates canonicalization.
pub fn request_hash(request: &Value) -> Result<String> {
    jcs::object_hash(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bound_set_covers_every_field_an_approval_must_pin() {
        let bound: Vec<&str> = BOUND.iter().map(|(name, _)| *name).collect();
        for required in [
            "subject",
            "key",
            "component",
            "mandate-ref",
            "policy-version",
            "classification",
            "action",
            "target",
            "args-hash",
        ] {
            assert!(
                bound.contains(&required),
                "{required} is not bound by the approval"
            );
        }
    }

    #[test]
    fn missing_authorization_on_a_gated_effect_is_rejected() {
        let envelope = serde_json::json!({ "emitted-at": "2026-07-26T09:15:01.300Z" });
        let error = verify_authorization(&envelope, true, &[], &HashSet::new()).unwrap_err();
        assert_eq!(error.code(), "gate-authorization-missing");
    }

    #[test]
    fn absent_authorization_is_fine_when_no_gate_applies() {
        let envelope = serde_json::json!({ "emitted-at": "2026-07-26T09:15:01.300Z" });
        assert!(
            verify_authorization(&envelope, false, &[], &HashSet::new())
                .unwrap()
                .is_none()
        );
    }
}

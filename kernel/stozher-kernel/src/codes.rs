//! Rejection codes that the specification requires but does not name.
//!
//! Every code the specification defines is used **verbatim** from `spec/` — this module holds none
//! of them. What it holds is the small set of conditions the specification states as a MUST while
//! giving no machine-readable identifier for the refusal. Skipping such a check to avoid naming it
//! would trade a documented gap for an undocumented hole, so the checks are implemented and their
//! names are quarantined here, in one list, clearly marked as **not normative**.
//!
//! Each entry cites the requirement it enforces. They are candidates for the next specification
//! revision; an ADR should either adopt them into §02 §9.1's table or replace them. Until then a
//! reader can tell at a glance which codes are part of the wire contract (everywhere else) and
//! which are this implementation's own (here).
//!
//! [`REGISTER`] exists so a test can assert that the set has not grown silently.

/// §05 §7 — "The default profile MUST set `consequential: "block"` and MUST NOT allow
/// `consequential` while a gate rule applies to it." No code is given for the refusal.
pub const POLICY_OFFLINE_ALLOWS_GATED: &str = "x-policy-offline-allows-gated";

/// §05 §5.1 — `policy-change` identifies the new version by `execution.target`, which must be
/// `policy:<policy-version>` of the document `execution.args-hash` commits to. No code is given.
pub const POLICY_CHANGE_TARGET_MISMATCH: &str = "x-policy-change-target-mismatch";

/// §05 §5.3 — "`execution.args-hash` MUST equal `object-hash` of the new policy document, so the
/// approval signature binds the exact bytes of the policy that took effect." No code is given.
pub const POLICY_CHANGE_DOCUMENT_UNBOUND: &str = "x-policy-change-document-unbound";

/// §02 §7.5 — "A window MUST be closed and emitted within the policy's `aggregate-max-window`."
/// No code is given.
pub const AGGREGATE_WINDOW_TOO_LONG: &str = "x-aggregate-window-too-long";

/// §02 §7.2 — "All aggregated actions MUST share one `identity`, one `mandate-ref` and one
/// `policy-version`", which requires the window itself to be well formed (`from <= to`). No code is
/// given for an inverted window.
pub const AGGREGATE_WINDOW_INVERTED: &str = "x-aggregate-window-inverted";

/// §04 §4.1 — a checkpoint "MUST be signed by a key derived at role `3'` and enrolled as the
/// kernel's checkpoint key"; §04 §4 gives `checkpoint-signer-not-kernel` for that, but gives no
/// code for a checkpoint whose `checkpoint.stream` is unknown to the store.
pub const CHECKPOINT_STREAM_UNKNOWN: &str = "x-checkpoint-stream-unknown";

/// §08 §1.2 — an action identifier must be `<manifest name>.<action>`; §08 gives
/// `manifest-action-namespace` for a manifest declaring outside its namespace, but gives no code
/// for a registration whose embedded manifest object is not a well-formed manifest at all.
pub const MANIFEST_MALFORMED: &str = "x-manifest-malformed";

/// §03 §6 — the root set "is changed only by an envelope of `kind: "effect"`,
/// `action: "kernel.enroll_root"` / `kernel.retire_root`". No code is given for such an envelope
/// whose evidence does not identify a well-formed key to enrol or retire.
pub const ROOT_ENROLLMENT_MALFORMED: &str = "x-root-enrollment-malformed";

/// §06 §5 — "Approval decisions MUST themselves be recorded as envelopes … so the approval history
/// is chained". It does not name the refusal for a *second* decision over a request a named human
/// has already answered, which must not be representable: one request, one answer.
pub const GATE_DECISION_ALREADY_RECORDED: &str = "x-gate-decision-already-recorded";

/// An infrastructure failure — the database is unreachable or corrupt.
///
/// **Not a rejection.** A rejection means "this object is invalid"; this means "the kernel could not
/// answer". It is never written to a rejection record and never reported to a submitter as a reason
/// their envelope was refused, because recording it would put the kernel's own outages into the
/// audit as if they were emitter misbehaviour. It maps to HTTP 503, and the submitter retries.
pub const STORE_UNAVAILABLE: &str = "x-store-unavailable";

/// Too many gate requests from one subject in one window (§09 §7).
///
/// §09 §7 requires the kernel to rate-limit gate requests per subject per interval and to surface a
/// spike as a finding, but names no reason code for the refusal.
///
/// The cap lives in the kernel's own configuration rather than in policy, which §09 §7's
/// "policy-configured" implies. That is a deliberate, recorded deviation: `spec/05 §1`'s member set
/// is closed **and every member is required**, so a new policy member is a breaking wire change
/// that invalidates every existing document and every vector at once. It is also the wrong home for
/// it — a queue-depth bound authorizes nothing and changes nobody's rights; it is a resource bound
/// on kernel-side state that no component pulls or evaluates.
///
/// Refusing a *request* is not refusing an *action*. The call the request was for is still
/// gated, and still blocked; what the flooding subject loses is the ability to keep growing the
/// queue an approver has to read.
pub const GATE_RATE_LIMITED: &str = "x-gate-rate-limited";

/// The caller presented no credential, or one that does not resolve (§05 §2.2, §10 §1.1).
///
/// Also not a rejection: there is no authenticated subject to attribute one to.
pub const CALLER_UNAUTHENTICATED: &str = "x-caller-unauthenticated";

/// The complete register. A test asserts on this so the list cannot grow without the growth being
/// a visible, reviewed diff.
pub const REGISTER: [&str; 11] = [
    GATE_RATE_LIMITED,
    POLICY_OFFLINE_ALLOWS_GATED,
    POLICY_CHANGE_TARGET_MISMATCH,
    POLICY_CHANGE_DOCUMENT_UNBOUND,
    AGGREGATE_WINDOW_TOO_LONG,
    AGGREGATE_WINDOW_INVERTED,
    CHECKPOINT_STREAM_UNKNOWN,
    MANIFEST_MALFORMED,
    ROOT_ENROLLMENT_MALFORMED,
    GATE_DECISION_ALREADY_RECORDED,
    crate::notify::NOTIFY_FAILED,
];

#[cfg(test)]
mod tests {
    use super::REGISTER;

    #[test]
    fn every_local_code_is_marked_as_non_normative() {
        // The `x-` prefix is the marker: no specification code carries it, so a reader of a
        // rejection record can tell immediately whether the refusal is part of the wire contract.
        for code in REGISTER {
            assert!(
                code.starts_with("x-"),
                "{code} is not marked as an implementation-local code"
            );
        }
    }

    #[test]
    fn the_register_has_no_duplicates() {
        let mut seen = REGISTER.to_vec();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "the register lists a code twice");
    }
}

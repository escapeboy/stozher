//! Reason codes this crate names, and the small set that is still its own.
//!
//! # What this module was, and what happened to it
//!
//! It held the conditions the specification states as a MUST while giving no machine-readable
//! identifier for the refusal. Skipping such a check to avoid naming it would trade a documented gap
//! for an undocumented hole, so the checks were implemented and their names quarantined here under
//! an `x-` prefix, clearly marked as not normative and explicitly a candidate for the next
//! specification revision.
//!
//! v0.9 is that revision. Fifteen of them were adopted into `spec/` and dropped the prefix; each one
//! still cites the requirement it enforces, because that citation is what earned it a place in the
//! wire contract. ADR-0018 records the adoption and, more importantly, the rule for the rejection
//! records already chained under the old names: **renaming does not rewrite a chained past**, and
//! `spec/00 §1` says what a reader must do with an `x-` code it finds in a historical record.
//!
//! # What [`REGISTER`] means now
//!
//! Not "codes the specification forgot" — those are gone. It is the set of codes that are **not
//! refusals of an object at all**: a store that could not answer, a caller that presented no
//! credential, a schema newer than this build, a component that would not speak the conformance
//! protocol. None of them says "what you sent is invalid", so none of them belongs in a wire
//! contract about objects, and each keeps the `x-` prefix to say so. A test asserts on the set, so
//! it cannot grow without the growth being a visible, reviewed diff.

/// §05 §7 — "The default profile MUST set `consequential: "block"` and MUST NOT allow
/// `consequential` while a gate rule applies to it." No code is given for the refusal.
pub const POLICY_OFFLINE_ALLOWS_GATED: &str = "policy-offline-allows-gated";

/// §05 §5.1 — `policy-change` identifies the new version by `execution.target`, which must be
/// `policy:<policy-version>` of the document `execution.args-hash` commits to. No code is given.
pub const POLICY_CHANGE_TARGET_MISMATCH: &str = "policy-change-target-mismatch";

/// §05 §5.3 — "`execution.args-hash` MUST equal `object-hash` of the new policy document, so the
/// approval signature binds the exact bytes of the policy that took effect." No code is given.
pub const POLICY_CHANGE_DOCUMENT_UNBOUND: &str = "policy-change-document-unbound";

/// §02 §7.5 — "A window MUST be closed and emitted within the policy's `aggregate-max-window`."
/// No code is given.
pub const AGGREGATE_WINDOW_TOO_LONG: &str = "aggregate-window-too-long";

/// §02 §7.2 — "All aggregated actions MUST share one `identity`, one `mandate-ref` and one
/// `policy-version`", which requires the window itself to be well formed (`from <= to`). No code is
/// given for an inverted window.
pub const AGGREGATE_WINDOW_INVERTED: &str = "aggregate-window-inverted";

/// §04 §4.1 — a checkpoint "MUST be signed by a key derived at role `3'` and enrolled as the
/// kernel's checkpoint key"; §04 §4 gives `checkpoint-signer-not-kernel` for that, but gives no
/// code for a checkpoint whose `checkpoint.stream` is unknown to the store.
pub const CHECKPOINT_STREAM_UNKNOWN: &str = "checkpoint-stream-unknown";

/// §08 §1.2 — an action identifier must be `<manifest name>.<action>`; §08 gives
/// `manifest-action-namespace` for a manifest declaring outside its namespace, but gives no code
/// for a registration whose embedded manifest object is not a well-formed manifest at all.
pub const MANIFEST_MALFORMED: &str = "manifest-malformed";

/// §03 §6 — the root set "is changed only by an envelope of `kind: "effect"`,
/// `action: "kernel.enroll_root"` / `kernel.retire_root`". No code is given for such an envelope
/// whose evidence does not identify a well-formed key to enrol or retire.
pub const ROOT_ENROLLMENT_MALFORMED: &str = "root-enrollment-malformed";

/// §06 §5 — "Approval decisions MUST themselves be recorded as envelopes … so the approval history
/// is chained". It does not name the refusal for a *second* decision over a request a named human
/// has already answered, which must not be representable: one request, one answer.
pub const GATE_DECISION_ALREADY_RECORDED: &str = "gate-decision-already-recorded";

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
pub const GATE_RATE_LIMITED: &str = "gate-rate-limited";

/// §02 §7 — `sample-hashes` is bounded at 16 but `counts.by-action` is left unbounded, so one
/// envelope is an unbounded amount of work for every consumer that iterates it. Defined in
/// `stozher_core::envelope` because the check is structural; listed here so the register stays the
/// single place the local codes can be read.
pub use stozher_core::envelope::AGGREGATE_CARDINALITY;

/// §02 §7 rule 3 constrains `counts.total` to the sum of `by-action` and says nothing about the
/// sign, so the sum was satisfiable by cancellation. No code is given for a negative count.
pub use stozher_core::envelope::AGGREGATE_COUNT_NEGATIVE;

/// §04 §4 — a checkpoint whose attested range simply begins somewhere other than the range
/// supplied to verify it against. §04 names codes for the count and the head, but not for this.
/// Defined in `stozher_core::chain`; listed here so the register stays the one place to read them.
pub use stozher_core::chain::CHECKPOINT_RANGE_MISMATCH;

/// §02 §4 — "any other IANA media type" is the right rule for a format and the wrong one for
/// something the kernel serves back over HTTP from the origin its console runs on. No code is given
/// for a payload whose declared type the kernel will not serve. Defined in `stozher_core::payload`.
pub use stozher_core::payload::MEDIA_TYPE_NOT_ALLOWED;

/// The caller presented no credential, or one that does not resolve (§05 §2.2, §10 §1.1).
///
/// Also not a rejection: there is no authenticated subject to attribute one to.
pub const CALLER_UNAUTHENTICATED: &str = "x-caller-unauthenticated";

/// An effect reported as `applied` whose accrual exceeds a budget in its mandate chain (§03 §4.3).
///
/// A `policy_violation` marker rather than a rejection reason, and deliberately so: §03 §4.3 puts
/// the blocking on the emitter ("outcome: blocked, envelope still emitted"), so an envelope that
/// arrives here claiming `applied` past a cap is a component confessing that it acted anyway. The
/// effect has already happened, and refusing the record would delete the only evidence of it — the
/// same reasoning as `prohibited-applied`. See [`crate::budget`] and ADR-0015.
pub const BUDGET_EXCEEDED_APPLIED: &str = "x-budget-exceeded-applied";

/// The store's schema is newer than this build understands.
///
/// Not a rejection either — nothing was submitted. It is a startup refusal, and it is deliberately
/// distinct from [`SCHEMA_MIGRATION_FAILED`]: "you are running an old kernel against a new store"
/// and "the upgrade did not work" send an operator to different places, and only one of them is
/// fixed by putting the previous binary back.
pub const SCHEMA_VERSION_AHEAD: &str = "x-schema-version-ahead";

/// A migration step failed, or the append-only enforcement was not intact once the steps had run.
///
/// The run is one transaction, so this is reported over a store that is still at the version it
/// started at. See [`crate::migrate`].
pub const SCHEMA_MIGRATION_FAILED: &str = "x-schema-migration-failed";

/// The component under test could not be driven — §08 §4.8's transport failed.
///
/// Not a rejection: nothing was submitted, and the component may be perfectly correct in every way
/// this run failed to observe. It is nevertheless a conformance failure and is recorded as one,
/// because a component that cannot be certified has not been certified. See [`crate::driver`].
pub const CONFORMANCE_DRIVER_FAILED: &str = "x-conformance-driver-failed";

/// The harness could not build the throwaway kernel a run is performed against.
///
/// Never a statement about the component: nothing had been asked of it yet. It is deliberately
/// distinct from [`CONFORMANCE_DRIVER_FAILED`], because "our own bootstrap is broken" and "the
/// component would not talk to us" send an operator to opposite ends of the problem.
pub const CONFORMANCE_HARNESS_FAILED: &str = "x-conformance-harness-failed";

/// The codes that are this implementation's own, because they refuse nothing.
///
/// See the module documentation: every entry here reports a condition of the *kernel*, not a verdict
/// about a submitted object, so none of them is part of the wire contract and every one keeps its
/// `x-` prefix.
pub const REGISTER: [&str; 7] = [
    STORE_UNAVAILABLE,
    CALLER_UNAUTHENTICATED,
    BUDGET_EXCEEDED_APPLIED,
    SCHEMA_VERSION_AHEAD,
    SCHEMA_MIGRATION_FAILED,
    CONFORMANCE_DRIVER_FAILED,
    CONFORMANCE_HARNESS_FAILED,
];

/// The codes v0.9 adopted into `spec/`, in the order the module declares them.
///
/// Listed so a test can assert they did **not** keep the `x-` prefix. A code that is in the
/// specification and still marked as this implementation's own would tell a reader of a rejection
/// record the opposite of the truth.
pub const ADOPTED: [&str; 15] = [
    POLICY_OFFLINE_ALLOWS_GATED,
    POLICY_CHANGE_TARGET_MISMATCH,
    POLICY_CHANGE_DOCUMENT_UNBOUND,
    AGGREGATE_WINDOW_TOO_LONG,
    AGGREGATE_WINDOW_INVERTED,
    CHECKPOINT_STREAM_UNKNOWN,
    MANIFEST_MALFORMED,
    ROOT_ENROLLMENT_MALFORMED,
    GATE_DECISION_ALREADY_RECORDED,
    GATE_RATE_LIMITED,
    AGGREGATE_CARDINALITY,
    AGGREGATE_COUNT_NEGATIVE,
    CHECKPOINT_RANGE_MISMATCH,
    MEDIA_TYPE_NOT_ALLOWED,
    crate::notify::NOTIFY_FAILED,
];

#[cfg(test)]
mod tests {
    use super::{ADOPTED, REGISTER};

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
    fn no_adopted_code_still_claims_to_be_local() {
        // The other half of the same marker, and the half a rename forgets. A code the
        // specification now names, still carrying `x-`, tells a reader of a rejection record the
        // opposite of the truth.
        for code in ADOPTED {
            assert!(
                !code.starts_with("x-"),
                "{code} was adopted into spec/ and still carries the local prefix"
            );
        }
    }

    #[test]
    fn the_two_sets_are_disjoint_and_have_no_duplicates() {
        let mut seen: Vec<&str> = REGISTER.iter().chain(ADOPTED.iter()).copied().collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "a code appears twice, or is claimed as both adopted and local"
        );
    }
}

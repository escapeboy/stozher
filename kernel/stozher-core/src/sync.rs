//! What a component may do when the kernel has answered "no" — §05 §7.1.
//!
//! A submission has three outcomes and not two. `accepted` and `unreachable` were the only ones the
//! specification modelled, and it treated the distance between a local chain and a synced one as
//! *latency* (§04 §3). A **refusal** is the third state, and it is not a slower second one: the
//! `offline` map governs a kernel that cannot answer, never one that has answered.
//!
//! # Why this lives in `stozher-core` when the kernel is not an emitter
//!
//! Because the rule is one both halves of a deployment have to agree about, and a rule stated once
//! per implementation is a rule two implementations diverge on. `spec/vectors/sync-outcome.json`
//! carries `role: "primitive"` for the same reason: it is the emitter's obligation, and a kernel
//! that could not compute it could not tell an operator what its emitters owe. The Python gateway's
//! `stozher_gateway.sync` is the other statement of it, and the corpus is what keeps them the same.
//!
//! # The shape of the rule
//!
//! * **The reason decides whether grace exists at all.** Under a `mandate-*` reason or
//!   `policy-not-published`, no class has any — authority the organization cannot resolve is not
//!   authority (ADR-0001), and a `read` performed without authority is still an effect.
//! * **The class decides who may use it when it does.** `read` and `benign` may run out the
//!   `policy.wedge-grace` window, loudly and counted; `consequential` and `prohibited` stop at
//!   once, because grace over `consequential` is exactly the window an auditor asks "what else was
//!   still permitted" about.
//!
//! Stopping unilaterally on any refusal would be a denial-of-service weapon — one malformed
//! envelope halts a fleet — and unbounded grace is an accountability hole. The corpus pins both
//! ends, including a vector an implementation that simply refused everything would fail.

/// The kernel appended it.
pub const ACCEPTED: &str = "accepted";
/// No answer: transport failure, timeout, no route. §05 §7's `offline` map governs.
pub const UNREACHABLE: &str = "unreachable";
/// The kernel answered with a rejection (§04 §7). This module governs.
pub const REFUSED: &str = "refused";

/// `policy.wedge-grace`, default `PT5M` (§05 §1).
pub const WEDGE_GRACE_DEFAULT_SECONDS: i64 = 300;

/// Whether a call may proceed, and what a refusal of it must say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// `true` when the call may proceed as asked.
    pub serve: bool,
    /// The reason code a refusal carries **verbatim**; `None` when serving.
    pub reason_code: Option<String>,
    /// Whether serving it must also be recorded as a finding (§05 §7.1 clause 4).
    pub finding: bool,
}

/// The state a component is deciding from.
#[derive(Debug, Clone)]
pub struct SyncState<'a> {
    /// `accepted`, `unreachable` or `refused`.
    pub outcome: &'a str,
    /// The kernel's reason code, present exactly when the outcome is `refused`.
    pub reason_code: Option<&'a str>,
    /// The effective weight class of the call being decided.
    pub classification: &'a str,
    /// Seconds since the **first** refusal on this stream, so a later one cannot restart the window.
    pub elapsed_seconds: i64,
    /// The policy's `offline` behaviour for this class. Consulted only when `unreachable`.
    pub offline: &'a str,
    /// `policy.wedge-grace` in seconds.
    pub wedge_grace_seconds: i64,
}

/// Whether this refusal reason leaves no grace for any class (§05 §7.1 clause 4).
///
/// The whole `mandate-*` family, not one code: what the kernel refused was the authority, and a
/// component acting under authority its organization will not resolve is acting under none.
#[must_use]
pub fn denies_every_class(reason_code: &str) -> bool {
    reason_code.starts_with("mandate-") || reason_code == "policy-not-published"
}

/// §05 §7.1 clauses 1, 4 and 5, as a pure function of the state.
#[must_use]
pub fn decide(state: &SyncState<'_>) -> Decision {
    if state.outcome == ACCEPTED {
        return Decision {
            serve: true,
            reason_code: None,
            finding: false,
        };
    }
    if state.outcome == UNREACHABLE {
        return if state.offline == "allow" {
            Decision {
                serve: true,
                reason_code: None,
                finding: false,
            }
        } else {
            Decision {
                serve: false,
                reason_code: Some("policy-stale-offline".to_owned()),
                finding: false,
            }
        };
    }
    let reason = state.reason_code.unwrap_or("x-kernel-refused");
    let refuse = Decision {
        serve: false,
        reason_code: Some(reason.to_owned()),
        finding: false,
    };
    if denies_every_class(reason) {
        return refuse;
    }
    if matches!(state.classification, "consequential" | "prohibited") {
        return refuse;
    }
    if state.elapsed_seconds < state.wedge_grace_seconds {
        return Decision {
            serve: true,
            reason_code: None,
            finding: true,
        };
    }
    refuse
}

/// Where a stream stands, for the surface §09 §4.2 requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStatus {
    /// Something was accepted within the quiet interval.
    Healthy,
    /// Nothing has been accepted within the quiet interval. The **absence** of evidence.
    Quiet,
    /// The most recent thing that happened was a refusal. Evidence.
    Refused,
}

impl StreamStatus {
    /// The name this status is reported under, on every surface and in the corpus.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Quiet => "quiet",
            Self::Refused => "refused",
        }
    }
}

/// §09 §4.2 — quiet is the absence of evidence; refused is evidence.
///
/// `seconds_since_accepted` is `None` when nothing has ever been accepted on the stream. The
/// comparison against the quiet interval is strict, so a row does not flicker on the boundary
/// second.
#[must_use]
pub fn stream_status(
    last_accepted_at: Option<&str>,
    last_refused_at: Option<&str>,
    seconds_since_accepted: Option<i64>,
    quiet_after_seconds: i64,
) -> StreamStatus {
    // Timestamps are RFC 3339 UTC with exactly three fractional digits (§01 §2.3), so the string
    // order is the instant order and no parser is needed to compare two of them.
    //
    // `>=`, so a refusal recorded in the same millisecond as the last append reads as refused. The
    // tie is reachable — three decimals, and a deployment may run a coarse clock — and breaking it
    // the other way would hide the finding, which is the failure this state exists to stop.
    if let Some(refused) = last_refused_at {
        if last_accepted_at.is_none_or(|accepted| refused >= accepted) {
            return StreamStatus::Refused;
        }
    }
    match seconds_since_accepted {
        None => StreamStatus::Quiet,
        Some(silent) if silent > quiet_after_seconds => StreamStatus::Quiet,
        Some(_) => StreamStatus::Healthy,
    }
}

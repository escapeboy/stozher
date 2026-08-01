//! Triggers — `spec/07 §4`. The only way a signal leads to an effect.
//!
//! # Why this is a function and not four lines inside ingest
//!
//! It was four lines inside ingest, and that made §07 §4 unreachable from anything but a running
//! kernel with a populated store: no vector could ask it, and the other implementation could not
//! run the same rule even if it wanted to. §07 §4 is a rule about the *content* of an envelope, in
//! the same family as the mandate chain rule that already lives in this crate — what it needs from
//! a store is two lookups, and a lookup is an input.
//!
//! So the resolution stays with the caller (it owns the store) and the judgement is here. That is
//! also what lets `spec/vectors/trigger.json` state the whole rule as a table.
//!
//! # What the rule buys
//!
//! "Why did this happen at 03:00 with nobody awake" has one answer and the envelope has to carry it:
//! *this signal, under this human's standing rule, which expires on this date*. Each of the three
//! checks removes a way of not answering it — a trigger citing a mandate the effect is not judged
//! against, a signal nobody appended, and an `interactive` mandate, which by definition means
//! somebody was watching and therefore cannot authorize something that happened while nobody was.

use serde_json::Value;

use crate::error::{Error, Result};

/// Apply `spec/07 §4` rules 1–3 to an envelope that may carry a `trigger`.
///
/// `mandate` is the mandate object the envelope's `mandate-ref` resolves to, and `signal` the
/// envelope its `trigger.signal-ref` resolves to; `None` means the store does not hold it. An
/// envelope with no `trigger` is trivially fine — §07 §4 constrains triggered effects, not every
/// effect.
///
/// Rule 4 is deliberately absent: the `rule` string is descriptive, scope enforcement comes from the
/// mandate's own `scope`, and a rule matching more signals than intended cannot widen what the
/// effect may do. There is nothing here to check.
///
/// # Errors
///
/// `schema-missing-member`, `trigger-mandate-mismatch`, `trigger-signal-unresolved`,
/// `mandate-unresolved`, `trigger-mandate-not-standing`.
pub fn check(envelope: &Value, mandate: Option<&Value>, signal: Option<&Value>) -> Result<()> {
    let Some(trigger) = envelope.get("trigger") else {
        return Ok(());
    };
    let standing_ref = trigger["standing-mandate-ref"]
        .as_str()
        .ok_or_else(|| Error::new("schema-missing-member", "trigger.standing-mandate-ref"))?;
    if envelope["mandate-ref"].as_str() != Some(standing_ref) {
        return Err(Error::new(
            "trigger-mandate-mismatch",
            "the authority for a triggered action is the mandate the effect is judged against",
        ));
    }
    let signal_ref = trigger["signal-ref"]
        .as_str()
        .ok_or_else(|| Error::new("schema-missing-member", "trigger.signal-ref"))?;
    let Some(signal) = signal else {
        return Err(Error::new(
            "trigger-signal-unresolved",
            format!("no appended signal envelope with id {signal_ref}"),
        ));
    };
    if signal["kind"].as_str() != Some("signal") {
        // Resolving to *something* is not resolving to a signal. Without this, an effect could cite
        // another effect as its cause and the audit would render a chain of reasons that never
        // happened.
        return Err(Error::new(
            "trigger-signal-unresolved",
            format!("{signal_ref} is not a signal envelope"),
        ));
    }
    let mandate = mandate
        .ok_or_else(|| Error::new("mandate-unresolved", format!("no mandate {standing_ref}")))?;
    if mandate["mandate-kind"].as_str() != Some("standing") {
        return Err(Error::new(
            "trigger-mandate-not-standing",
            "a triggered effect must cite a standing mandate",
        ));
    }
    Ok(())
}

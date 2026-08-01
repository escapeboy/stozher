//! Time: the one fixed timestamp form, ISO 8601 duration arithmetic, and an injectable clock.
//!
//! Timestamps are the single RFC 3339 UTC form of spec §01 §2.3 — exactly three fractional digits,
//! literal `Z` — and are compared as strings everywhere else in this crate. Real date arithmetic is
//! needed in exactly three places: the future-emission bound (§09 §5), the retention ceiling
//! (§05 §4), and the checkpoint interval (§04 §4.6). It lives here so nothing else has to know about
//! calendars.
//!
//! # Why there is no date library here
//!
//! This module parses attacker-controlled input: `emitted-at` arrives inside an envelope from an
//! emitter the kernel does not trust (§09 §3). A general-purpose date parser is a large surface for
//! that job — `time 0.3.45` carried RUSTSEC-2026-0009, a stack-exhaustion denial of service in
//! exactly that path, and its fix raised the minimum toolchain past this workspace's.
//!
//! The format here is **24 bytes, fixed, non-recursive**: seven integer fields at known offsets. The
//! calendar arithmetic is Howard Hinnant's `days_from_civil` / `civil_from_days`, which are branch
//! free, allocation free and exact across the proleptic Gregorian range. Dropping the dependency
//! removed the vulnerability class rather than the vulnerability, and cost ninety lines that the
//! tests below round-trip exhaustively over three centuries.
//!
//! The clock is a trait because the ingest freshness check is otherwise untestable: the vectors
//! deliberately exclude anything relative to *now* and hand those cases to S1 with an injected clock
//! (`spec/vectors/README.md` §7).

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use stozher_core::envelope;
use stozher_core::error::{Error, Result};

/// A source of the current instant.
///
/// Implementations must be cheap to call and must never block: ingest calls this on every request.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// The current instant, in the fixed timestamp form.
    fn now(&self) -> String;
}

/// The host clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> String {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        format_millis(millis)
    }
}

/// A clock that stands still until moved, for tests that need to be on one side of a deadline.
#[derive(Debug)]
pub struct FixedClock(AtomicI64);

impl FixedClock {
    /// A clock reading `at`.
    ///
    /// # Errors
    ///
    /// `encoding-bad-timestamp` if `at` is not in the fixed form.
    pub fn new(at: &str) -> Result<Self> {
        Ok(Self(AtomicI64::new(parse_timestamp(at)?)))
    }

    /// Move the clock by a whole number of seconds, which may be negative.
    pub fn advance_seconds(&self, seconds: i64) {
        self.0.fetch_add(seconds * 1000, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> String {
        format_millis(self.0.load(Ordering::SeqCst))
    }
}

/// A shared clock handle.
pub type SharedClock = Arc<dyn Clock>;

/// The largest advance this kernel will accept: ten years (ADR-0023).
///
/// Retention ceilings are expressed in days (§05 §6), so ten years crosses any commitment a policy
/// can express and then some. The bound exists so the advance cannot be used to push the clock out
/// of the fixed form's range, and so the number in the file is one a reader can weigh.
pub const MAX_CLOCK_ADVANCE_SECONDS: i64 = 3_650 * 86_400;

/// The reason code under which an advanced clock declares itself into the kernel's record stream.
pub const CLOCK_ADVANCE_DECLARED: &str = "clock-advance-in-force";

/// The refusal code for every way of asking for a clock this kernel will not run.
pub const CLOCK_ADVANCE_REFUSED: &str = "clock-advance-refused";

/// The sentence an operator must copy into the configuration for the advance to be honoured.
///
/// It is not a password and it stops nobody: an attacker who can write the configuration file can
/// write this line too. It is there for the reader — the file gets diffed, pasted into tickets and
/// attached to reports, and the one thing everybody downstream needs to know about a deployment
/// running this way should be in the same paragraph as the number that made it true.
pub const CLOCK_ADVANCE_ACKNOWLEDGEMENT: &str =
    "records emitted by this deployment are not evidence of when anything happened";

/// The last instant the fixed form can express, and where an advance saturates.
const LAST_REPRESENTABLE_INSTANT: &str = "9999-12-31T23:59:59.999Z";

/// A configured clock advance: how far forward, and the duration exactly as written.
#[derive(Debug, Clone)]
pub struct ClockAdvance {
    /// The advance in whole seconds. Always strictly positive and at most
    /// [`MAX_CLOCK_ADVANCE_SECONDS`].
    pub seconds: i64,
    /// The ISO 8601 duration as it appears in the configuration, for the record and the banner.
    pub duration: String,
}

/// A clock advanced by a fixed, non-negative offset from another clock.
///
/// This is the one facility in the shipped binary that moves time, and its whole design is the
/// direction it can move. The offset is an **advance**: `now()` is never earlier than the clock it
/// wraps, on any input, in any configuration. That is not a check that could be bypassed — a
/// negative advance cannot be constructed ([`AdvancedClock::new`]) and cannot be written
/// (`spec/01 §2.4` durations have no sign), so no arrangement of configuration produces a kernel
/// whose clock reads earlier than the host's.
///
/// The consequence is the property this exists to preserve: **an advance can never lengthen
/// anybody's authority**. A mandate past its `not-after`, a revocation already published, a budget
/// window already closed — all of them stay closed under every clock this type can produce. What it
/// *can* do is bring a deadline forward, which is what makes retention, expiry and the checkpoint
/// interval observable inside an engagement instead of only in a year's time. What it can also do,
/// and this is the price, is erase a payload earlier than reality would have; ADR-0023 §4 weighs
/// that and [`declare_advance`] is why it cannot be done quietly.
#[derive(Debug)]
pub struct AdvancedClock {
    base: SharedClock,
    advance: ClockAdvance,
}

impl AdvancedClock {
    /// A clock reading `base + advance`.
    ///
    /// # Errors
    ///
    /// [`CLOCK_ADVANCE_REFUSED`] if the advance is not strictly positive, or exceeds
    /// [`MAX_CLOCK_ADVANCE_SECONDS`]. Zero is refused too: the absence of the configuration member
    /// is how a deployment says its clock is real, and a second spelling for that would be a
    /// deployment that declares a moved clock while running an unmoved one.
    pub fn new(base: SharedClock, advance: ClockAdvance) -> Result<Self> {
        if advance.seconds <= 0 {
            return Err(Error::new(
                CLOCK_ADVANCE_REFUSED,
                format!(
                    "an advance must be strictly positive, {} is not — this clock moves forward or \
                     it does not move",
                    advance.seconds
                ),
            ));
        }
        if advance.seconds > MAX_CLOCK_ADVANCE_SECONDS {
            return Err(Error::new(
                CLOCK_ADVANCE_REFUSED,
                format!(
                    "an advance of {}s exceeds the bound of {MAX_CLOCK_ADVANCE_SECONDS}s",
                    advance.seconds
                ),
            ));
        }
        Ok(Self { base, advance })
    }

    /// The advance in force.
    #[must_use]
    pub fn advance(&self) -> &ClockAdvance {
        &self.advance
    }

    /// What the clock underneath reads — the host's own time, unmoved.
    #[must_use]
    pub fn base_now(&self) -> String {
        self.base.now()
    }

    /// The line this kernel says on every start while the advance is in force.
    #[must_use]
    pub fn banner(&self) -> String {
        format!(
            "THE CLOCK IS ADVANCED BY {} ({}s). It reads {} while the host reads {}. {}.",
            self.advance.duration,
            self.advance.seconds,
            self.now(),
            self.base_now(),
            CLOCK_ADVANCE_ACKNOWLEDGEMENT
        )
    }
}

impl Clock for AdvancedClock {
    fn now(&self) -> String {
        let base = self.base.now();
        // Saturating at the last representable instant rather than falling back to `base`: the
        // invariant callers rely on is that this clock is never *behind* the one it wraps, and
        // returning the unmoved time to escape an arithmetic edge would break exactly that. The
        // branch is unreachable for a bounded advance over any host clock this side of the year
        // 9989; it is written so the invariant holds without depending on that.
        shift(&base, self.advance.seconds).unwrap_or_else(|_| LAST_REPRESENTABLE_INSTANT.to_owned())
    }
}

/// Build the clock a configuration describes.
///
/// # Errors
///
/// [`CLOCK_ADVANCE_REFUSED`].
pub fn from_config(config: &crate::Config) -> Result<SharedClock> {
    let base: SharedClock = Arc::new(SystemClock);
    match &config.clock_advance {
        None => Ok(base),
        Some(advance) => Ok(Arc::new(AdvancedClock::new(base, advance.clone())?)),
    }
}

/// Write the advance into the kernel's own record stream, and refuse to run if the clock has gone
/// backwards since the last time it did (§04 §7.1, ADR-0023 §3).
///
/// Two things happen here, and both have to happen before the kernel serves anything.
///
/// **The advance is declared.** A record lands in the kernel's rejection stream — signed by the
/// kernel key, chained to the record before it, in a table the storage engine will not let anything
/// update or delete. Its `received-at` is the **host's** time while every record the process goes on
/// to emit carries the advanced one, so the discontinuity is not merely visible, it is measurable:
/// a reader subtracts one from the other and knows exactly how far ahead everything after this
/// point was written. The declaration is not optional and not best-effort — if it cannot be written,
/// [`crate::Kernel::open`] fails and there is no kernel.
///
/// It is in the rejection stream rather than in an envelope because `spec/02 §2`'s `kind` vocabulary
/// is closed at nine and a tenth is a wire change that invalidates every existing document and every
/// vector at once. That stream already exists for precisely this — the kernel's own durable records
/// that are not envelopes ([`crate::store::Store::record_rejection`]) — and this is one: the kernel
/// recording that it is refusing to let its own timestamps be read as evidence of when.
///
/// **The advance ratchets.** If the store already carries a declaration whose effective instant is
/// later than the one this process would start at, the kernel refuses to start. So a deployment
/// cannot be run forward, used, and quietly returned to reality: once moved, the only clocks it will
/// ever accept are ones at least as far ahead. Moving a deployment forward costs you that
/// deployment, permanently, which is the intended price of pointing this at anything real.
///
/// Returns the id of the declaration when one was written.
///
/// # Errors
///
/// [`CLOCK_ADVANCE_REFUSED`] if the clock has gone backwards, or
/// [`crate::codes::STORE_UNAVAILABLE`].
pub async fn declare_advance(
    store: &crate::Store,
    signer: &crate::keys::SigningKey,
    clock: &SharedClock,
    advance: Option<&ClockAdvance>,
) -> Result<Option<String>> {
    let effective = clock.now();
    // The check runs whether or not this process is advanced: returning to the real clock is itself
    // a move backwards, and it is the one an attacker would make to cover the trip.
    if let Some(prior) = last_declared_instant(store).await? {
        // Both are the fixed form, whose lexical order is its chronological order (§01 §2.3).
        if effective < prior {
            return Err(Error::new(
                CLOCK_ADVANCE_REFUSED,
                format!(
                    "this deployment has already run at {prior} and would now start at {effective}. \
                     Its clock does not go backwards: the records it holds were written ahead of \
                     real time and moving back would put new ones behind them. Configure a \
                     clock-advance that reaches {prior} or later, or start from a fresh store"
                ),
            ));
        }
    }
    let Some(advance) = advance else {
        return Ok(None);
    };

    let detail = stozher_core::jcs::canonicalize(&serde_json::json!({
        "acknowledged": CLOCK_ADVANCE_ACKNOWLEDGEMENT,
        "advance": advance.duration,
        "advance-seconds": advance.seconds,
        "effective": effective,
        "real": unmoved(&effective, advance.seconds),
    }))?;
    let record = store
        .record_rejection(
            signer,
            &crate::store::RejectionInput {
                reason: CLOCK_ADVANCE_DECLARED.to_owned(),
                detail: detail.clone(),
                object_hash: stozher_core::crypto::sha256_hex(detail.as_bytes()),
                submitted_by: Some("agent:kernel".to_owned()),
                // The host's time, not the advanced one. This is the single field in the store that
                // still says when any of this actually happened.
                received_at: unmoved(&effective, advance.seconds),
                claimed_stream: None,
                claimed_seq: None,
                claimed_kind: None,
            },
        )
        .await?;
    Ok(Some(record.id))
}

/// The effective instant of the most recent declaration, if this store carries one.
async fn last_declared_instant(store: &crate::Store) -> Result<Option<String>> {
    let records = store.rejections(Some(CLOCK_ADVANCE_DECLARED), 1).await?;
    Ok(records.first().and_then(|record| {
        serde_json::from_str::<serde_json::Value>(record["detail"].as_str()?)
            .ok()?
            .get("effective")?
            .as_str()
            .map(str::to_owned)
    }))
}

/// The unmoved instant behind `effective`.
///
/// Derived by subtraction rather than by reading the base clock again, so the two timestamps in one
/// declaration are exactly one advance apart instead of one advance plus however long the write
/// took.
fn unmoved(effective: &str, advance_seconds: i64) -> String {
    shift(effective, -advance_seconds).unwrap_or_else(|_| effective.to_owned())
}

/// Parse a timestamp in the fixed form, returning milliseconds since the Unix epoch.
///
/// Any other shape is a rejection, not a repair: offsets other than `Z`, absent or differing
/// fractional precision, and lowercase `z` are refused (§01 §2.3).
///
/// A leap second (`:60`) is accepted — the specification's own validator allows it — and is treated
/// as the first instant of the following minute, so ordering and arithmetic stay monotone.
///
/// # Errors
///
/// `encoding-bad-timestamp`.
pub fn parse_timestamp(text: &str) -> Result<i64> {
    let bad = || Error::new("encoding-bad-timestamp", format!("{text:?}"));
    let b = text.as_bytes();
    if b.len() != 24 {
        return Err(bad());
    }
    if !(b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[23] == b'Z')
    {
        return Err(bad());
    }
    let field = |range: std::ops::Range<usize>| -> Result<i64> {
        let mut value: i64 = 0;
        for byte in &b[range] {
            if !byte.is_ascii_digit() {
                return Err(bad());
            }
            value = value * 10 + i64::from(byte - b'0');
        }
        Ok(value)
    };
    let year = field(0..4)?;
    let month = field(5..7)?;
    let day = field(8..10)?;
    let hour = field(11..13)?;
    let minute = field(14..16)?;
    let second = field(17..19)?;
    let millis = field(20..23)?;

    // Year 0 exists in the proleptic Gregorian calendar and not in this form: `format_millis`
    // renders it, but the other implementation refuses it, and a value one side can express and the
    // other cannot is a disagreement waiting for an envelope to carry it (§01 §2.3, ADR-0020).
    if year < 1 || !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err(bad());
    }
    // `:60` is a real UTC second and not a value of this form. It has no distinct millisecond
    // representation, so it renders back as the following minute: accepting it gives one instant
    // two spellings, which is exactly what a fixed-width form exists to prevent.
    if hour > 23 || minute > 59 || second > 59 {
        return Err(bad());
    }

    let days = days_from_civil(year, month, day);
    Ok(((days * 86_400 + hour * 3_600 + minute * 60 + second) * 1_000) + millis)
}

/// Render milliseconds since the Unix epoch in the fixed form.
#[must_use]
pub fn format_millis(millis: i64) -> String {
    // Floor division, so instants before 1970 render correctly rather than truncating toward zero.
    let (seconds, sub) = (millis.div_euclid(1_000), millis.rem_euclid(1_000));
    let (days, time_of_day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{sub:03}Z")
}

/// Shift a timestamp by whole seconds, staying in the fixed form.
///
/// # Errors
///
/// `encoding-bad-timestamp` if the input is malformed or the result leaves the representable range.
pub fn shift(text: &str, seconds: i64) -> Result<String> {
    let out_of_range = || {
        Error::new(
            "encoding-bad-timestamp",
            format!("{text:?} shifted by {seconds}s leaves the representable range"),
        )
    };
    let millis = parse_timestamp(text)?;
    let shifted = seconds
        .checked_mul(1_000)
        .and_then(|delta| millis.checked_add(delta))
        .ok_or_else(out_of_range)?;
    // Outside four-digit years the fixed form cannot represent the result, and silently widening it
    // would produce a string nothing else in the system accepts.
    // Year 0001-01-01T00:00:00.000Z to 9999-12-31T23:59:59.999Z. The lower bound is year *one*: a
    // shift that produced year 0000 would emit a string this module's own parser refuses.
    if !(-62_135_596_800_000..=253_402_300_799_999).contains(&shifted) {
        return Err(out_of_range());
    }
    Ok(format_millis(shifted))
}

/// Parse an ISO 8601 duration restricted to `P[nD][T[nH][nM][nS]]` (§01 §2.4) into seconds.
///
/// Months and years are rejected: their length is ambiguous and retention windows are legal
/// commitments.
///
/// # Errors
///
/// `encoding-bad-duration`.
pub fn parse_duration_seconds(text: &str) -> Result<i64> {
    let bad = || Error::new("encoding-bad-duration", format!("{text:?}"));
    let overflow = || Error::new("encoding-bad-duration", format!("{text:?} overflows"));
    let rest = text.strip_prefix('P').ok_or_else(bad)?;
    if rest.is_empty() {
        return Err(bad());
    }
    let (date_part, time_part) = match rest.split_once('T') {
        Some((_, "")) => return Err(bad()),
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };

    let mut total: i64 = 0;
    let mut digits: i64 = 0;
    let mut have_digits = false;
    let mut saw_component = false;

    for (part, units) in [(date_part, "D"), (time_part.unwrap_or(""), "HMS")] {
        for ch in part.chars() {
            match ch {
                '0'..='9' => {
                    digits = digits
                        .checked_mul(10)
                        .and_then(|d| d.checked_add(i64::from(ch as u8 - b'0')))
                        .ok_or_else(overflow)?;
                    have_digits = true;
                }
                // `Y` and `M` in the date position are years and months: forbidden outright, which
                // is why the permitted unit set differs between the two parts.
                unit if units.contains(unit) => {
                    if !have_digits {
                        return Err(bad());
                    }
                    let scale = match unit {
                        'D' => 86_400,
                        'H' => 3_600,
                        'M' => 60,
                        _ => 1,
                    };
                    total = digits
                        .checked_mul(scale)
                        .and_then(|seconds| total.checked_add(seconds))
                        .ok_or_else(overflow)?;
                    digits = 0;
                    have_digits = false;
                    saw_component = true;
                }
                _ => return Err(bad()),
            }
        }
        if have_digits {
            return Err(bad());
        }
    }
    if !saw_component {
        return Err(bad());
    }
    Ok(total)
}

/// `at + duration`, in the fixed timestamp form.
///
/// # Errors
///
/// `encoding-bad-timestamp` or `encoding-bad-duration`.
pub fn add_duration(at: &str, duration: &str) -> Result<String> {
    shift(at, parse_duration_seconds(duration)?)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse (`civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month, day)
}

/// Delegates to `stozher_core::envelope`, which is where the deployment's one calendar lives.
///
/// There used to be two — this one and `envelope::is_timestamp`'s `1..=31` range check — and they
/// disagreed about whether `2026-02-31` exists. Two calendars in one binary is a bug waiting for
/// the code path that reaches the wrong one, so this is a forwarder rather than a second opinion.
/// Years outside `u32` are outside the representable range anyway and admit no day.
fn days_in_month(year: i64, month: i64) -> i64 {
    let (Ok(year), Ok(month)) = (u32::try_from(year), u32::try_from(month)) else {
        return 0;
    };
    i64::from(envelope::days_in_month(year, month))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_days_and_time_only() {
        assert_eq!(parse_duration_seconds("P30D").unwrap(), 2_592_000);
        assert_eq!(parse_duration_seconds("PT15M").unwrap(), 900);
        assert_eq!(parse_duration_seconds("PT1H").unwrap(), 3_600);
        assert_eq!(parse_duration_seconds("P0D").unwrap(), 0);
        assert_eq!(parse_duration_seconds("P1DT2H3M4S").unwrap(), 93_784);
        assert_eq!(parse_duration_seconds("P3650D").unwrap(), 315_360_000);
        for bad in [
            "P1Y", "P1M", "P1YT1H", "30D", "P", "PT", "P1", "PT1X", "", "P-1D", "PT1H1", "PT1D",
        ] {
            assert_eq!(
                parse_duration_seconds(bad).unwrap_err().code(),
                "encoding-bad-duration",
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn timestamps_round_trip_in_exactly_one_form() {
        for at in [
            "2026-07-26T09:15:01.300Z",
            "1970-01-01T00:00:00.000Z",
            "1969-12-31T23:59:59.999Z",
            "2000-02-29T12:00:00.000Z",
            "2024-02-29T00:00:00.000Z",
            "1900-03-01T00:00:00.000Z",
            "2099-12-31T23:59:59.999Z",
        ] {
            assert_eq!(format_millis(parse_timestamp(at).unwrap()), at, "{at}");
        }
        for bad in [
            "2026-07-26T09:15:01Z",
            "2026-07-26T09:15:01.3Z",
            "2026-07-26T11:15:01.300+02:00",
            "2026-07-26t09:15:01.300z",
            "2026-13-26T09:15:01.300Z",
            "2026-02-30T09:15:01.300Z",
            "2026-07-26T24:15:01.300Z",
            "2026-07-26T09:60:01.300Z",
            "2026-07-2xT09:15:01.300Z",
            "",
        ] {
            assert_eq!(
                parse_timestamp(bad).unwrap_err().code(),
                "encoding-bad-timestamp",
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn the_calendar_round_trips_over_three_centuries() {
        // Every day from 1900 to 2200. The arithmetic is hand-written, so it is checked
        // exhaustively rather than at a few convenient points.
        let mut days = days_from_civil(1900, 1, 1);
        let end = days_from_civil(2200, 1, 1);
        let mut previous: Option<i64> = None;
        while days < end {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(
                days_from_civil(year, month, day),
                days,
                "{year:04}-{month:02}-{day:02} does not round-trip"
            );
            assert!((1..=12).contains(&month));
            assert!(day >= 1 && day <= days_in_month(year, month));
            // Dates advance by exactly one day, with no gaps and no repeats.
            if let Some(prior) = previous {
                assert_eq!(days - prior, 1);
            }
            previous = Some(days);
            days += 1;
        }
    }

    #[test]
    fn a_leap_second_is_refused_rather_than_folded_into_the_next_minute() {
        // This test used to assert the opposite, on the reasoning that "the specification's own
        // validator accepts `:60`" — which cited `stozher_core::envelope::is_timestamp`, this
        // project's own code, as if it were the specification. It was not: §01 §2.3 said nothing,
        // and the Python implementation refused `:60` throughout. Folding it into the following
        // minute gave one instant two spellings, and gave a foreign emitter a string the kernel
        // would append and a verifier would reject. See ADR-0020.
        assert!(parse_timestamp("2016-12-31T23:59:60.000Z").is_err());
        let before = parse_timestamp("2016-12-31T23:59:59.000Z").unwrap();
        let after = parse_timestamp("2017-01-01T00:00:00.000Z").unwrap();
        assert!(before < after);
    }

    #[test]
    fn retention_ceiling_arithmetic() {
        assert_eq!(
            add_duration("2026-07-26T00:00:00.000Z", "P365D").unwrap(),
            "2027-07-26T00:00:00.000Z"
        );
        assert_eq!(
            add_duration("2026-07-26T00:00:00.000Z", "P0D").unwrap(),
            "2026-07-26T00:00:00.000Z"
        );
        assert_eq!(
            add_duration("2026-02-27T00:00:00.000Z", "P2D").unwrap(),
            "2026-03-01T00:00:00.000Z"
        );
        // 2028 is a leap year, so the same shift lands on a day 2026 does not have.
        assert_eq!(
            add_duration("2028-02-27T00:00:00.000Z", "P2D").unwrap(),
            "2028-02-29T00:00:00.000Z"
        );
        assert_eq!(
            shift("2026-07-26T00:00:00.000Z", -1).unwrap(),
            "2026-07-25T23:59:59.000Z"
        );
        // A shift past the representable form is refused rather than silently widened.
        assert_eq!(
            shift("2026-07-26T00:00:00.000Z", i64::MAX)
                .unwrap_err()
                .code(),
            "encoding-bad-timestamp"
        );
    }

    #[test]
    fn a_fixed_clock_stands_still_and_moves_on_request() {
        let clock = FixedClock::new("2026-07-26T09:00:00.000Z").unwrap();
        assert_eq!(clock.now(), "2026-07-26T09:00:00.000Z");
        assert_eq!(clock.now(), "2026-07-26T09:00:00.000Z");
        clock.advance_seconds(3_600);
        assert_eq!(clock.now(), "2026-07-26T10:00:00.000Z");
        clock.advance_seconds(-3_600);
        assert_eq!(clock.now(), "2026-07-26T09:00:00.000Z");
    }

    #[test]
    fn the_system_clock_produces_a_parseable_instant() {
        let now = SystemClock.now();
        assert_eq!(format_millis(parse_timestamp(&now).unwrap()), now);
    }

    fn advance(duration: &str) -> Result<ClockAdvance> {
        Ok(ClockAdvance {
            seconds: parse_duration_seconds(duration)?,
            duration: duration.to_owned(),
        })
    }

    #[test]
    fn an_advanced_clock_reads_ahead_of_the_one_it_wraps() {
        let base = Arc::new(FixedClock::new("2026-07-26T09:00:00.000Z").unwrap());
        let clock = AdvancedClock::new(Arc::clone(&base) as SharedClock, advance("P400D").unwrap())
            .unwrap();
        assert_eq!(clock.base_now(), "2026-07-26T09:00:00.000Z");
        assert_eq!(clock.now(), "2027-08-30T09:00:00.000Z");
        // It tracks the clock underneath rather than standing still at a computed instant.
        base.advance_seconds(3_600);
        assert_eq!(clock.now(), "2027-08-30T10:00:00.000Z");
        assert!(clock.banner().contains("P400D"));
    }

    #[test]
    fn the_clock_advance_has_no_way_to_point_backwards() {
        // The whole safety argument is this direction, so it is asserted at both layers that could
        // produce a negative: the duration grammar, which has no sign, and the constructor, which
        // refuses one anyway for callers who build a `ClockAdvance` by hand.
        for spelling in ["-P400D", "-PT1H", "P-400D", "PT-1H"] {
            assert_eq!(
                parse_duration_seconds(spelling).unwrap_err().code(),
                "encoding-bad-duration",
                "{spelling:?} must not parse as a duration"
            );
        }
        let base: SharedClock = Arc::new(FixedClock::new("2026-07-26T09:00:00.000Z").unwrap());
        for seconds in [-1, -86_400, i64::MIN] {
            let hostile = ClockAdvance {
                seconds,
                duration: "forged".to_owned(),
            };
            assert_eq!(
                AdvancedClock::new(Arc::clone(&base), hostile)
                    .unwrap_err()
                    .code(),
                CLOCK_ADVANCE_REFUSED,
                "an advance of {seconds}s was accepted"
            );
        }
    }

    #[test]
    fn an_advance_is_bounded_and_never_zero() {
        let base: SharedClock = Arc::new(FixedClock::new("2026-07-26T09:00:00.000Z").unwrap());
        for refused in ["PT0S", "P0D"] {
            assert_eq!(
                AdvancedClock::new(Arc::clone(&base), advance(refused).unwrap())
                    .unwrap_err()
                    .code(),
                CLOCK_ADVANCE_REFUSED,
                "a zero advance was accepted as {refused:?}"
            );
        }
        assert_eq!(
            AdvancedClock::new(Arc::clone(&base), advance("P3651D").unwrap())
                .unwrap_err()
                .code(),
            CLOCK_ADVANCE_REFUSED
        );
        assert!(AdvancedClock::new(Arc::clone(&base), advance("P3650D").unwrap()).is_ok());
    }

    #[test]
    fn an_advance_saturates_rather_than_reading_behind_the_host() {
        // Unreachable with a real host clock, and asserted because the failure mode if it were
        // reachable is the one thing this type must never do: report a time earlier than reality.
        let base: SharedClock = Arc::new(FixedClock::new("9999-01-01T00:00:00.000Z").unwrap());
        let clock = AdvancedClock::new(Arc::clone(&base), advance("P3650D").unwrap()).unwrap();
        assert_eq!(clock.now(), LAST_REPRESENTABLE_INSTANT);
        assert!(clock.now() > clock.base_now());
    }
}

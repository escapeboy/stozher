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

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err(bad());
    }
    if hour > 23 || minute > 59 || second > 60 {
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
    if !(-62_167_219_200_000..=253_402_300_799_999).contains(&shifted) {
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

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
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
    fn leap_seconds_are_accepted_and_ordered_monotonically() {
        // The specification's own validator accepts `:60`; treating it as the following instant
        // keeps comparison and arithmetic monotone.
        let before = parse_timestamp("2016-12-31T23:59:59.000Z").unwrap();
        let leap = parse_timestamp("2016-12-31T23:59:60.000Z").unwrap();
        let after = parse_timestamp("2017-01-01T00:00:00.000Z").unwrap();
        assert!(before < leap);
        assert_eq!(leap, after);
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
}

//! Time: the one fixed timestamp form, ISO 8601 duration arithmetic, and an injectable clock.
//!
//! Timestamps are the single RFC 3339 UTC form of spec §01 §2.3 — exactly three fractional digits,
//! literal `Z` — and are compared as strings everywhere else in this crate. Real date arithmetic is
//! needed in exactly three places: the future-emission bound (§09 §5), the retention ceiling
//! (§05 §4), and the checkpoint interval (§04 §4.6). It lives here so nothing else has to know
//! about calendars.
//!
//! The clock is a trait because the ingest freshness check is otherwise untestable: the vectors
//! deliberately exclude anything relative to *now* and hand those cases to S1 with an injected
//! clock (`spec/vectors/README.md` §7).

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use stozher_core::error::{Error, Result};
use time::OffsetDateTime;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;

/// The one serialization of an instant this system accepts (§01 §2.3).
const TIMESTAMP: &[BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

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
        format_timestamp(OffsetDateTime::now_utc())
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
        Ok(Self(AtomicI64::new(
            parse_timestamp(at)?.unix_timestamp_nanos() as i64 / 1_000_000,
        )))
    }

    /// Move the clock by a whole number of seconds, which may be negative.
    pub fn advance_seconds(&self, seconds: i64) {
        self.0.fetch_add(seconds * 1000, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> String {
        let millis = self.0.load(Ordering::SeqCst);
        let instant = OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        format_timestamp(instant)
    }
}

/// A shared clock handle.
pub type SharedClock = Arc<dyn Clock>;

/// Render an instant in the fixed form.
#[must_use]
pub fn format_timestamp(instant: OffsetDateTime) -> String {
    instant
        .to_offset(time::UtcOffset::UTC)
        .format(&TIMESTAMP)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".to_owned())
}

/// Parse a timestamp in the fixed form. Any other shape is a rejection, not a repair.
///
/// # Errors
///
/// `encoding-bad-timestamp`.
pub fn parse_timestamp(text: &str) -> Result<OffsetDateTime> {
    time::PrimitiveDateTime::parse(text, &TIMESTAMP)
        .map(|naive| naive.assume_utc())
        .map_err(|_| Error::new("encoding-bad-timestamp", format!("{text:?}")))
}

/// Shift a timestamp by whole seconds, staying in the fixed form.
///
/// # Errors
///
/// `encoding-bad-timestamp` if the input is malformed or the result leaves the representable range.
pub fn shift(text: &str, seconds: i64) -> Result<String> {
    let instant = parse_timestamp(text)?
        .checked_add(time::Duration::seconds(seconds))
        .ok_or_else(|| {
            Error::new(
                "encoding-bad-timestamp",
                format!("{text:?} shifted by {seconds}s leaves the representable range"),
            )
        })?;
    Ok(format_timestamp(instant))
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
    let rest = text.strip_prefix('P').ok_or_else(bad)?;
    if rest.is_empty() {
        return Err(bad());
    }
    let (date_part, time_part) = match rest.split_once('T') {
        Some((date, time)) => {
            if time.is_empty() {
                return Err(bad());
            }
            (date, Some(time))
        }
        None => (rest, None),
    };

    let mut total: i64 = 0;
    let mut digits = String::new();
    let mut saw_component = false;

    let consume = |unit: char, digits: &mut String, total: &mut i64| -> Result<()> {
        if digits.is_empty() {
            return Err(Error::new(
                "encoding-bad-duration",
                format!("{text:?}: unit {unit} has no value"),
            ));
        }
        let value: i64 = digits.parse().map_err(|_| {
            Error::new(
                "encoding-bad-duration",
                format!("{text:?}: {digits} is not an integer"),
            )
        })?;
        digits.clear();
        let seconds = match unit {
            'D' => value.checked_mul(86_400),
            'H' => value.checked_mul(3_600),
            'M' => value.checked_mul(60),
            'S' => Some(value),
            _ => None,
        }
        .ok_or_else(|| Error::new("encoding-bad-duration", format!("{text:?} overflows")))?;
        *total = total.checked_add(seconds).ok_or_else(|| {
            Error::new("encoding-bad-duration", format!("{text:?} overflows"))
        })?;
        Ok(())
    };

    for ch in date_part.chars() {
        match ch {
            '0'..='9' => digits.push(ch),
            'D' => {
                consume('D', &mut digits, &mut total)?;
                saw_component = true;
            }
            // Y and M in the date position are years and months: forbidden outright.
            _ => return Err(bad()),
        }
    }
    if !digits.is_empty() {
        return Err(bad());
    }
    if let Some(time_part) = time_part {
        for ch in time_part.chars() {
            match ch {
                '0'..='9' => digits.push(ch),
                'H' | 'M' | 'S' => {
                    consume(ch, &mut digits, &mut total)?;
                    saw_component = true;
                }
                _ => return Err(bad()),
            }
        }
        if !digits.is_empty() {
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
        for bad in ["P1Y", "P1M", "P1YT1H", "30D", "P", "PT", "P1", "PT1X", ""] {
            assert_eq!(
                parse_duration_seconds(bad).unwrap_err().code(),
                "encoding-bad-duration",
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn timestamps_round_trip_in_exactly_one_form() {
        let at = "2026-07-26T09:15:01.300Z";
        assert_eq!(format_timestamp(parse_timestamp(at).unwrap()), at);
        for bad in [
            "2026-07-26T09:15:01Z",
            "2026-07-26T09:15:01.3Z",
            "2026-07-26T11:15:01.300+02:00",
            "2026-07-26t09:15:01.300z",
        ] {
            assert_eq!(
                parse_timestamp(bad).unwrap_err().code(),
                "encoding-bad-timestamp"
            );
        }
    }

    #[test]
    fn retention_ceiling_arithmetic() {
        assert_eq!(
            add_duration("2026-07-26T00:00:00.000Z", "P365D").unwrap(),
            "2027-07-26T00:00:00.000Z"
        );
    }

    #[test]
    fn a_fixed_clock_stands_still_and_moves_on_request() {
        let clock = FixedClock::new("2026-07-26T09:00:00.000Z").unwrap();
        assert_eq!(clock.now(), "2026-07-26T09:00:00.000Z");
        assert_eq!(clock.now(), "2026-07-26T09:00:00.000Z");
        clock.advance_seconds(3_600);
        assert_eq!(clock.now(), "2026-07-26T10:00:00.000Z");
    }
}

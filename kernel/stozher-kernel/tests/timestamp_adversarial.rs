//! Adversarial input to the hand-written timestamp parser — `spec/01 §2.3`.
//!
//! `SECURITY.md` names `clock.rs` the highest-value target in the codebase, and says why: it is
//! round-tripped exhaustively over every date from 1900 to 2200, and **exhaustive round-tripping
//! over valid dates proves nothing about the rejection of malformed input.** This is the other half.
//!
//! It exists because the parser was adopted deliberately, to drop a dependency carrying a
//! stack-exhaustion advisory on a path that parses attacker-controlled input. Trading a reviewed
//! dependency for hand-written code is only the better trade if the hand-written code is attacked.

use stozher_kernel::clock::{format_millis, parse_timestamp, shift};

/// Every byte position of a valid timestamp, corrupted with every ASCII byte.
///
/// The parser indexes fixed positions after a length check, so a byte that slips past the separator
/// and digit checks would be read as a digit it is not. 24 positions × 128 bytes is small enough to
/// be exhaustive rather than sampled.
#[test]
fn no_single_byte_corruption_is_accepted_unless_it_is_still_a_real_instant() {
    let valid = "2026-07-26T09:00:00.000Z";
    let mut accepted_variants = 0;
    for position in 0..valid.len() {
        for byte in 0u8..128 {
            let mut bytes = valid.as_bytes().to_vec();
            if bytes[position] == byte {
                continue;
            }
            bytes[position] = byte;
            let Ok(text) = std::str::from_utf8(&bytes) else {
                continue;
            };
            if let Ok(millis) = parse_timestamp(text) {
                // Whatever it accepted must round-trip to itself: an accepted string that renders
                // differently is one the signature covers and the system will later disagree about.
                assert_eq!(
                    format_millis(millis),
                    text,
                    "accepted {text:?} but renders it as {:?}",
                    format_millis(millis)
                );
                accepted_variants += 1;
            }
        }
    }
    // The digit positions do produce other valid instants; a run that accepted nothing would mean
    // the loop was testing nothing.
    assert!(
        accepted_variants > 50,
        "only {accepted_variants} corruptions were accepted, so this test is not exercising the \
         digit positions"
    );
}

#[test]
fn nothing_of_any_length_or_content_panics_the_parser() {
    // The parser is reached with attacker-controlled bytes on the ingest path. A panic there is an
    // availability failure with no envelope to show for it, which is worse than a refusal.
    let mut probes: Vec<String> = vec![
        String::new(),
        "Z".to_owned(),
        "\u{0}".repeat(24),
        "2026-07-26T09:00:00.000".to_owned(),
        "2026-07-26T09:00:00.000ZZ".to_owned(),
        "＋2026-07-26T09:00:00.00Z".to_owned(),
        "2026-07-26T09:00:00.00\u{0}Z".to_owned(),
        "999999999999999999999999".to_owned(),
        "-999999999999999999999999".to_owned(),
    ];
    // Multi-byte characters that make the *byte* length 24 while the character length is not.
    probes.push("é".repeat(12));
    probes.push("日本語".repeat(8));
    for length in 0..40usize {
        probes.push("9".repeat(length));
    }
    for probe in probes {
        // The assertion is that this returns rather than unwinding.
        let _ = parse_timestamp(&probe);
        let _ = shift(&probe, 1);
    }
}

#[test]
fn the_representable_range_is_closed_at_both_ends() {
    // `shift` bounds the result to four-digit years because the fixed form cannot express anything
    // else, and silently widening it would produce a string nothing else in the system accepts.
    assert!(shift("9999-12-31T23:59:59.999Z", 1).is_err());
    assert!(shift("0001-01-01T00:00:00.000Z", -1).is_err());
    assert!(shift("2026-07-26T09:00:00.000Z", i64::MAX).is_err());
    assert!(shift("2026-07-26T09:00:00.000Z", i64::MIN).is_err());
    // And the ends themselves are representable, or the bound is off by one.
    assert!(shift("9999-12-31T23:59:59.998Z", 0).is_ok());
    assert!(parse_timestamp("9999-12-31T23:59:59.999Z").is_ok());
}

#[test]
fn a_leap_second_is_refused_because_the_other_implementation_refuses_it() {
    // §01 §2.3 fixes one timestamp form and says it denotes a real instant. `:60` is a real second
    // in UTC and not a real value of this form: it has no distinct millisecond representation, so
    // `format_millis` renders it as the following minute and the string no longer round-trips.
    //
    // This is a parity fix rather than a preference. The Python implementation validates through
    // `datetime.strptime`, which refuses `:60`; this parser accepted it. An envelope stamped
    // `...:60.000Z` was therefore appendable to the kernel and unverifiable by the gateway — a chain
    // that verifies for one party and not the other, which is the one thing an audit may not be.
    for text in [
        "2026-07-26T09:00:60.000Z",
        "2026-07-26T23:59:60.000Z",
        "2026-12-31T23:59:60.999Z",
    ] {
        assert!(
            parse_timestamp(text).is_err(),
            "{text} was accepted; the gateway refuses it"
        );
    }
}

#[test]
fn year_zero_is_refused_at_both_implementations() {
    // The proleptic Gregorian calendar has a year 0; `strptime` does not, and refuses it. The same
    // reasoning as the leap second: a string one implementation can express and the other cannot is
    // a disagreement waiting for an envelope to carry it.
    assert!(parse_timestamp("0000-01-01T00:00:00.000Z").is_err());
    assert!(parse_timestamp("0000-12-31T23:59:59.999Z").is_err());
    assert!(parse_timestamp("0001-01-01T00:00:00.000Z").is_ok());
}

#[test]
fn the_calendar_is_the_gregorian_one_including_its_century_rule() {
    assert!(parse_timestamp("2024-02-29T00:00:00.000Z").is_ok(), "2024 is a leap year");
    assert!(parse_timestamp("2000-02-29T00:00:00.000Z").is_ok(), "2000 is a leap year");
    assert!(parse_timestamp("2100-02-29T00:00:00.000Z").is_err(), "2100 is not");
    assert!(parse_timestamp("1900-02-29T00:00:00.000Z").is_err(), "1900 is not");
    assert!(parse_timestamp("2026-02-29T00:00:00.000Z").is_err());
    assert!(parse_timestamp("2026-04-31T00:00:00.000Z").is_err());
    assert!(parse_timestamp("2026-06-31T00:00:00.000Z").is_err());
}

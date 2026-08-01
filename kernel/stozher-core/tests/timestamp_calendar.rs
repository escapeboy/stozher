//! One binary, one calendar — `spec/01-primitives.md` §2.3.
//!
//! `envelope::is_timestamp` and `clock::parse_timestamp` both decide whether a string is a §01 §2.3
//! timestamp, and they disagreed: the first range-checked the day at `1..=31` and so accepted
//! `2026-02-31`, while the second rejected it with a leap-year-aware `days_in_month`. Which answer
//! an input got depended on which one happened to be called.
//!
//! That is not a cosmetic inconsistency. `gate.rs` reaches for the lenient one before comparing
//! approval windows, so a date that does not exist could bound an approval — and because the format
//! is fixed-width, `"2026-02-31T00:00:00.000Z"` compares greater than every real day in February.
//! An approval "expiring" on a day that never arrives is an approval that does not expire.

use stozher_core::envelope::is_timestamp;

#[test]
fn a_day_that_does_not_exist_is_not_a_timestamp() {
    for impossible in [
        "2026-02-31T00:00:00.000Z",
        "2026-02-30T00:00:00.000Z",
        "2026-02-29T00:00:00.000Z", // 2026 is not a leap year
        "2026-04-31T00:00:00.000Z",
        "2026-06-31T00:00:00.000Z",
        "2026-09-31T00:00:00.000Z",
        "2026-11-31T00:00:00.000Z",
        "2026-01-00T00:00:00.000Z",
    ] {
        assert!(
            !is_timestamp(impossible),
            "{impossible} is not a day that exists"
        );
    }
}

#[test]
fn the_leap_year_rule_is_the_gregorian_one() {
    // Divisible by 4 is a leap year, except centuries, except centuries divisible by 400. Getting
    // the exceptions wrong is the classic way to write a calendar that is right for a lifetime and
    // wrong at the boundary.
    assert!(
        is_timestamp("2024-02-29T00:00:00.000Z"),
        "2024 is a leap year"
    );
    assert!(is_timestamp("2000-02-29T00:00:00.000Z"), "2000: /400, leap");
    assert!(!is_timestamp("1900-02-29T00:00:00.000Z"), "1900: /100, not");
    assert!(!is_timestamp("2100-02-29T00:00:00.000Z"), "2100: /100, not");
}

#[test]
fn every_real_day_of_every_month_is_still_accepted() {
    // The companion the refusals need: a tightened check that also refuses valid days would break
    // every emitter, and would be found in production rather than here.
    let lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (index, length) in lengths.iter().enumerate() {
        let month = index + 1;
        for day in 1..=*length {
            let stamp = format!("2026-{month:02}-{day:02}T09:15:01.300Z");
            assert!(is_timestamp(&stamp), "{stamp} is a real day");
        }
    }
}

#[test]
fn the_rest_of_the_fixed_form_is_unchanged() {
    // §01 §2.3 is fixed-width so that lexicographic order is chronological order; nothing about the
    // calendar fix may loosen the shape that guarantee rests on.
    assert!(is_timestamp("2026-07-26T09:15:01.300Z"));
    assert!(
        !is_timestamp("2026-07-26T09:15:01Z"),
        "no fractional digits"
    );
    assert!(!is_timestamp("2026-07-26T11:15:01.300+02:00"), "not UTC");
    assert!(!is_timestamp("2026-13-26T09:15:01.300Z"), "month 13");
    assert!(!is_timestamp("2026-07-26t09:15:01.300z"), "lowercase");
    // A leap second is a real UTC second and not a value of this form: it renders back as the
    // following minute, so accepting it would give one instant two spellings (ADR-0020).
    assert!(!is_timestamp("2026-07-26T23:59:60.000Z"), "leap second");
    assert!(!is_timestamp("0000-01-01T00:00:00.000Z"), "year zero");
}

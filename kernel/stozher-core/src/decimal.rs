//! Exact comparison of monetary values — `spec/01 §2.5`, `spec/03 §4.3`.
//!
//! # Why this module exists at all
//!
//! `spec/01 §2.5` puts monetary quantities permanently out of the reach of binary64 by requiring
//! them to be decimal **strings**. Both implementations then compared those strings by parsing them
//! back into a `f64` — Rust with `s.parse::<f64>()`, Python with `float(s)` — which reintroduces the
//! representation the specification removed, at the one place it is load-bearing: deciding whether a
//! delegated budget exceeds its parent's.
//!
//! That is not theoretical. `9007199254740993` and `9007199254740992` are one apart and the same
//! binary64, so a child budget one unit over its parent's compares **equal** and the grant is
//! accepted. The two parsers also disagree with each other about what a number even is — Python's
//! `float()` strips surrounding whitespace and Rust's `parse` does not — so `" 25 "` was a value one
//! implementation accepted and the other rejected, which is precisely the class of divergence the
//! `parity` vectors exist to catch.
//!
//! # The grammar is deliberately narrow
//!
//! `digits [ "." digits ]`, and nothing else. No sign, no exponent, no leading `+`, no bare `.5` or
//! `5.`, no whitespace, no separators. Every one of those is a form two implementations can disagree
//! about; none of them is needed to write an amount of money. A budget is a cap on spend, so a
//! negative one is not a narrower budget but a nonsensical one, and it is refused rather than given a
//! meaning.
//!
//! Length is bounded for the same reason `counts.by-action` is: an unbounded string is an unbounded
//! amount of work for every consumer that compares it, and no real monetary cap needs thirty-two
//! characters.

use std::cmp::Ordering;

use crate::error::{Error, Result};

/// The longest monetary string this implementation will compare.
///
/// Thirty-two characters is more than a decillion euros to eighteen decimal places. The bound is
/// here so that a hostile grant cannot make every downstream verifier do unbounded work, not because
/// any legitimate amount comes close.
pub const MAX_LEN: usize = 32;

/// Split a monetary string into its integer and fractional digits.
///
/// # Errors
///
/// `schema-type-mismatch` if `value` is not of the form `digits [ "." digits ]`, or is longer than
/// [`MAX_LEN`].
fn parts(value: &str) -> Result<(&str, &str)> {
    if value.is_empty() || value.len() > MAX_LEN {
        return Err(Error::new(
            "schema-type-mismatch",
            format!(
                "a monetary value must be 1 to {MAX_LEN} characters, not {}",
                value.len()
            ),
        ));
    }
    let (integer, fraction) = match value.split_once('.') {
        // `split_once` finds the first `.`; a second one lands in `fraction` and fails the digit
        // check below, so "1.2.3" is refused rather than read as "1.2".
        Some((integer, fraction)) => (integer, fraction),
        None => (value, ""),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if !digits(integer) || (value.contains('.') && !digits(fraction)) {
        return Err(Error::new(
            "schema-type-mismatch",
            format!(
                "{value:?} is not a decimal string: the form is digits, optionally a point and \
                 more digits — no sign, no exponent, no whitespace"
            ),
        ));
    }
    Ok((integer, fraction))
}

/// Compare two monetary values exactly.
///
/// `"25"`, `"25.0"` and `"25.00"` are equal; `"025.00"` equals all three. Scale carries no meaning
/// here — two ways of writing one amount must not compare as two amounts.
///
/// # Errors
///
/// `schema-type-mismatch` if either value is not a decimal string per [`parts`].
pub fn compare(left: &str, right: &str) -> Result<Ordering> {
    let (left_int, left_frac) = parts(left)?;
    let (right_int, right_frac) = parts(right)?;

    // Integer parts: strip leading zeros, then longer wins, then compare digit by digit. Comparing
    // the strings directly would make "9" > "10", which is the bug lexical comparison always is.
    fn trim(s: &str) -> &str {
        let trimmed = s.trim_start_matches('0');
        if trimmed.is_empty() { "0" } else { trimmed }
    }
    let (left_int, right_int) = (trim(left_int), trim(right_int));
    let integer = left_int
        .len()
        .cmp(&right_int.len())
        .then_with(|| left_int.cmp(right_int));
    if integer != Ordering::Equal {
        return Ok(integer);
    }

    // Fractional parts: compare position by position, treating a missing digit as zero. This is the
    // right-padding a `f64` round-trip was standing in for, done exactly.
    let mut left_digits = left_frac.bytes();
    let mut right_digits = right_frac.bytes();
    loop {
        match (left_digits.next(), right_digits.next()) {
            (None, None) => return Ok(Ordering::Equal),
            (a, b) => {
                let order = a.unwrap_or(b'0').cmp(&b.unwrap_or(b'0'));
                if order != Ordering::Equal {
                    return Ok(order);
                }
            }
        }
    }
}

/// Whether `left` is at most `right`.
///
/// # Errors
///
/// `schema-type-mismatch` if either value is not a decimal string.
pub fn at_most(left: &str, right: &str) -> Result<bool> {
    Ok(compare(left, right)? != Ordering::Greater)
}

/// Add two monetary values exactly.
///
/// Accrued spend is a running total, so this is the operation a budget projection performs on every
/// append. Doing it in binary64 would make the total drift from the sum of the records it was folded
/// from — and the whole claim of a projection is that it is a fold of the log and nothing else.
///
/// Addition is by digit with a carry, at the wider of the two scales, so `"0.1" + "0.2"` is `"0.3"`
/// and not `0.30000000000000004`.
///
/// # Errors
///
/// `schema-type-mismatch` if either value is not a decimal string, or if the sum would be longer
/// than [`MAX_LEN`]. The bound is not decoration: a total that outgrew the type would otherwise be
/// truncated or wrapped, and a spend figure that silently got smaller is the one direction a budget
/// must never be wrong in.
pub fn add(left: &str, right: &str) -> Result<String> {
    let (left_int, left_frac) = parts(left)?;
    let (right_int, right_frac) = parts(right)?;
    let scale = left_frac.len().max(right_frac.len());

    // Right-pad both fractions to the common scale, then add the whole thing as one digit string.
    let pad = |int: &str, frac: &str| {
        let mut digits: Vec<u8> = int.bytes().chain(frac.bytes()).collect();
        digits.extend(std::iter::repeat_n(b'0', scale - frac.len()));
        digits
    };
    let a = pad(left_int, left_frac);
    let b = pad(right_int, right_frac);

    let mut sum: Vec<u8> = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u8;
    for index in 0..a.len().max(b.len()) {
        let digit = |side: &[u8]| -> u8 {
            side.len()
                .checked_sub(index + 1)
                .map_or(0, |position| side[position] - b'0')
        };
        let total = digit(&a) + digit(&b) + carry;
        sum.push(b'0' + total % 10);
        carry = total / 10;
    }
    if carry > 0 {
        sum.push(b'0' + carry);
    }
    sum.reverse();

    let digits =
        String::from_utf8(sum).map_err(|e| Error::new("schema-type-mismatch", e.to_string()))?;
    let (integer, fraction) = digits.split_at(digits.len() - scale);
    let integer = {
        let trimmed = integer.trim_start_matches('0');
        if trimmed.is_empty() { "0" } else { trimmed }
    };
    let total = if scale == 0 {
        integer.to_owned()
    } else {
        format!("{integer}.{fraction}")
    };
    if total.len() > MAX_LEN {
        return Err(Error::new(
            "schema-type-mismatch",
            format!("the sum of {left} and {right} exceeds {MAX_LEN} characters"),
        ));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::{MAX_LEN, add, at_most, compare};

    #[test]
    fn addition_is_exact_where_binary64_is_not() {
        // The canonical demonstration: in binary64 this is 0.30000000000000004.
        assert_eq!(add("0.1", "0.2").expect("both are decimal strings"), "0.3");
        // The result keeps the wider input scale rather than a canonical one, so `add` is asserted
        // by value too — a projection that stored "1.50" where a later read expected "1.5" would
        // otherwise be a difference nothing here would catch.
        assert_eq!(add("1.50", "0").expect("decimal strings"), "1.50");
        assert_eq!(
            compare(&add("1.50", "0").unwrap(), "1.5").unwrap(),
            Ordering::Equal
        );
    }

    #[test]
    fn addition_carries_and_aligns_scales() {
        for (left, right, sum) in [
            ("0", "0", "0"),
            ("1", "1", "2"),
            ("9", "1", "10"),
            ("99", "1", "100"),
            ("0.99", "0.01", "1.00"),
            ("25", "0.5", "25.5"),
            ("1.5", "2.25", "3.75"),
            ("0.001", "0.999", "1.000"),
            ("9007199254740992", "1", "9007199254740993"),
        ] {
            assert_eq!(
                add(left, right).expect("both are decimal strings"),
                sum,
                "{left} + {right}"
            );
            assert_eq!(
                add(right, left).expect("both are decimal strings"),
                sum,
                "addition is commutative: {right} + {left}"
            );
        }
    }

    #[test]
    fn a_running_total_stays_exact_over_many_additions() {
        // A spend projection is a fold, so the value that matters is the one after N appends. Ten
        // additions of 0.1 is the case a float total gets visibly wrong.
        let mut total = "0".to_owned();
        for _ in 0..10 {
            total = add(&total, "0.1").expect("decimal strings");
        }
        assert_eq!(
            compare(&total, "1").expect("decimal strings"),
            Ordering::Equal
        );
    }

    #[test]
    fn a_sum_that_would_outgrow_the_type_is_refused_rather_than_truncated() {
        // A spend figure that silently got smaller is the one direction a budget must never be
        // wrong in, so the bound refuses rather than wrapping.
        let big = "9".repeat(MAX_LEN);
        assert!(add(&big, "1").is_err());
        assert!(add(&big, "0").is_ok());
    }

    #[test]
    fn addition_refuses_what_comparison_refuses() {
        for rejected in ["", " 1", "1e5", "-1", ".5", "1.2.3"] {
            assert!(add(rejected, "1").is_err(), "{rejected:?} was added");
            assert!(add("1", rejected).is_err(), "{rejected:?} was added");
        }
    }

    #[test]
    fn scale_carries_no_meaning() {
        for (left, right) in [
            ("25", "25.00"),
            ("25.0", "25.000"),
            ("025.00", "25"),
            ("0", "0.0"),
            ("0.10", "0.1"),
        ] {
            assert_eq!(
                compare(left, right).expect("both are decimal strings"),
                Ordering::Equal,
                "{left} and {right} are one amount written two ways"
            );
        }
    }

    #[test]
    fn ordering_is_by_value_and_not_by_text() {
        for (left, right) in [
            ("9", "10"),     // lexical comparison gets this backwards
            ("0.9", "1"),    //
            ("1.1", "1.2"),  //
            ("1.09", "1.1"), // and this one, by comparing "09" with "1"
            ("0.0001", "0.001"),
        ] {
            assert_eq!(
                compare(left, right).expect("both are decimal strings"),
                Ordering::Less,
                "{left} should be less than {right}"
            );
            assert_eq!(
                compare(right, left).expect("both are decimal strings"),
                Ordering::Greater
            );
        }
    }

    #[test]
    fn values_one_apart_beyond_binary64_are_not_equal() {
        // The defect this module was written for: 2^53 and 2^53 + 1 are the same `f64`, so a child
        // budget one unit over its parent's compared equal and the grant was accepted.
        let parent = "9007199254740992";
        let child = "9007199254740993";
        assert_eq!(
            compare(child, parent).expect("both are decimal strings"),
            Ordering::Greater
        );
        assert!(!at_most(child, parent).expect("both are decimal strings"));
        assert!(at_most(parent, parent).expect("both are decimal strings"));
    }

    #[test]
    fn every_form_two_implementations_could_disagree_about_is_refused() {
        // Each of these is accepted by at least one of `f64::from_str` and Python's `float()`, and
        // none of them is a way anybody writes an amount of money.
        for rejected in [
            "", " 25", "25 ", "+25", "-25", "1e5", "1E5", "inf", "infinity", "NaN", "nan", ".5",
            "5.", "1_000", "1,000", "1.2.3", "0x19",
            "２５", // full-width digits: `char::is_numeric`, but not ASCII
            "25\n",
        ] {
            assert_eq!(
                compare(rejected, "1")
                    .expect_err(&format!("{rejected:?} was accepted as a monetary value"))
                    .code(),
                "schema-type-mismatch"
            );
        }
    }

    #[test]
    fn the_length_bound_is_enforced_on_both_sides() {
        let long = "1".repeat(MAX_LEN + 1);
        assert!(compare(&long, "1").is_err());
        assert!(compare("1", &long).is_err());
        assert!(compare(&"1".repeat(MAX_LEN), "1").is_ok());
    }
}

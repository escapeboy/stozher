//! `spec/02 §2` and §2.1 against the code that enforces them.
//!
//! # Why this test exists
//!
//! The product's v0.9 gate is *an independent implementation, written from `spec/` alone by someone
//! who has not read our code, passes the vector corpus.* Nothing else in the repository can fail
//! when the prose and the code disagree: both reference implementations read the same rules out of
//! `envelope.rs` and `envelope.py`, and neither reads the specification. A corpus green on both
//! sides therefore says nothing at all about whether the document they were written from describes
//! them — which is precisely the property the gate grades.
//!
//! One divergence was sitting in the tables when this was written: `mandate-ref` is **required** on
//! `cognition` here, while §1 made it required for "effect kinds" — which §2 defines as `effect`,
//! `policy-change` and `aggregate`, not `cognition` — and §2's `cognition` row did not list it
//! either. A reader following the prose builds a cognition envelope this kernel refuses, and
//! refuses `envelope-shape.json`'s own `valid-cognition` vector.
//!
//! # What it does not check
//!
//! Types, value constraints and the sub-object shapes of §3–§8. This is the member *sets* only:
//! which members each kind must carry and which it may. That is the part expressed as two tables a
//! human maintains by hand, and hand-maintained tables in two places are what drift.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use stozher_core::envelope::{KINDS, members_of};

fn spec_text() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/02-envelope.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The section between two headings, so a table is never read out of the wrong one.
fn section<'a>(document: &'a str, from: &str, to: &str) -> &'a str {
    let start = document
        .find(from)
        .unwrap_or_else(|| panic!("the specification has no heading {from:?}"));
    let rest = &document[start + from.len()..];
    let end = rest
        .find(to)
        .unwrap_or_else(|| panic!("the specification has no heading {to:?} after {from:?}"));
    &rest[..end]
}

/// The backticked names in a table cell, ignoring anything in parentheses.
///
/// The parenthetical is where a cell qualifies itself — `revocation`'s row carries
/// "(`reason` OPTIONAL)", and reading `reason` as required is exactly the kind of near-miss this
/// test is here to catch rather than commit.
fn names(cell: &str) -> Vec<String> {
    let cell = cell.split('(').next().unwrap_or(cell);
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Rows of a pipe table whose first cell is a backticked kind, as `(kind, remaining cells)`.
fn rows(section: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    for line in section.lines() {
        let line = line.trim();
        if !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_owned())
            .collect();
        let kind = names(&cells[0]);
        if kind.len() == 1 && KINDS.contains(&kind[0].as_str()) {
            found.push((kind[0].clone(), cells[1..].to_vec()));
        }
    }
    found
}

/// The eight members §2.1 says every kind carries.
const COMMON: [&str; 8] = [
    "v",
    "kind",
    "emitted-at",
    "stream",
    "seq",
    "prev-hash",
    "identity",
    "sig",
];

/// A cell in the `classification` or `execution` column that means the member is required.
fn column_requires(cell: &str) -> bool {
    cell.starts_with("MUST") && !cell.starts_with("MUST NOT")
}

#[test]
fn every_kind_the_code_models_appears_in_both_specification_tables() {
    let document = spec_text();
    let kinds_table = section(&document, "## 2. Envelope kinds", "### 2.1");
    let members_table = section(&document, "### 2.1", "## 3.");

    let in_kinds: BTreeSet<String> = rows(kinds_table).into_iter().map(|(k, _)| k).collect();
    let in_members: BTreeSet<String> = rows(members_table).into_iter().map(|(k, _)| k).collect();
    let modelled: BTreeSet<String> = KINDS.iter().map(|k| (*k).to_owned()).collect();

    assert_eq!(in_kinds, modelled, "§2 and `KINDS` list different kinds");
    assert_eq!(
        in_members, modelled,
        "§2.1 and `KINDS` list different kinds"
    );
}

#[test]
fn the_required_members_of_every_kind_are_the_ones_section_2_names() {
    let document = spec_text();
    let table = section(&document, "## 2. Envelope kinds", "### 2.1");

    for (kind, cells) in rows(table) {
        // Meaning | classification | execution | extra required
        let (classification, execution, extra) = (&cells[1], &cells[2], &cells[3]);
        let mut from_spec: BTreeSet<String> = COMMON.iter().map(|m| (*m).to_owned()).collect();
        if column_requires(classification) {
            from_spec.insert("classification".to_owned());
        }
        if column_requires(execution) {
            from_spec.insert("execution".to_owned());
        }
        from_spec.extend(names(extra));

        let (required, _) = members_of(&kind).expect("a modelled kind");
        let from_code: BTreeSet<String> = required.into_iter().map(str::to_owned).collect();

        assert_eq!(
            from_spec, from_code,
            "§2's row for `{kind}` and this implementation require different members"
        );
    }
}

#[test]
fn the_optional_members_of_every_kind_are_the_ones_section_2_1_names() {
    let document = spec_text();
    let table = section(&document, "### 2.1", "## 3.");

    // The two that are optional on every kind are stated in §2.1's prose rather than repeated in
    // nine rows. Asserting the prose still names them is what stops this test from quietly reading
    // a specification that dropped them and calling the rows a match.
    for member in ["memory-ref", "correlation-ref"] {
        assert!(
            table.contains(&format!("`{member}`")),
            "§2.1's prose no longer names `{member}` as optional on every kind"
        );
    }

    for (kind, cells) in rows(table) {
        let mut from_spec: BTreeSet<String> = names(&cells[0]).into_iter().collect();
        from_spec.insert("memory-ref".to_owned());
        from_spec.insert("correlation-ref".to_owned());

        let (_, optional) = members_of(&kind).expect("a modelled kind");
        let from_code: BTreeSet<String> = optional.into_iter().map(str::to_owned).collect();

        assert_eq!(
            from_spec, from_code,
            "§2.1's row for `{kind}` and this implementation permit different members"
        );
    }
}

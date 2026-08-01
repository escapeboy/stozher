//! Which optional members each envelope kind may carry — `spec/02 §2.1`.
//!
//! # Why this file exists
//!
//! `spec/02 §1` listed every member in one flat table and closed it with "members not listed above
//! MUST be rejected". Read literally that permits `trigger` on a checkpoint and `cost` on a mandate;
//! read as §9.1 words it — "a member not defined for **this kind**" — it says nothing at all about
//! which members belong to which kind. Both implementations therefore invented an answer, and they
//! invented different ones.
//!
//! The divergences were real and none of the 208 vectors touched them, because no vector asked. That
//! is the shape of defect the `parity` kind was added for in v0.2: not a bug either side could see
//! alone, but a question the specification never put to them.
//!
//! §02 §2.1 now states the matrix. This asserts this implementation against it, member by member,
//! and `spec/vectors/envelope-shape.json` asks the same questions of any other.

use serde_json::{Value, json};
use stozher_core::envelope::validate;

/// A structurally valid envelope of `kind`, with nothing optional on it.
fn minimal(kind: &str) -> Value {
    let mut envelope = json!({
        "v": "stozher/0.1",
        "kind": kind,
        "emitted-at": "2026-07-26T09:00:00.000Z",
        "stream": "gw:dev:0001",
        "seq": 0,
        "prev-hash": Value::Null,
        "identity": {
            "subject": "agent:a",
            "key": format!("ed25519:{}", "a".repeat(64)),
            "component": "gateway"
        },
        "sig": {
            "alg": "ed25519",
            "key": format!("ed25519:{}", "a".repeat(64)),
            "value": "b".repeat(128)
        }
    });
    let extra = match kind {
        "effect" => json!({
            "mandate-ref": "a".repeat(64),
            "policy-version": "2026.07.1",
            "classification": "read",
            "execution": {
                "action": "github.get_file", "target": "repo:acme/backend",
                "args-hash": "c".repeat(64), "outcome": "applied",
                "started-at": "2026-07-26T09:00:00.000Z",
                "finished-at": "2026-07-26T09:00:00.000Z"
            }
        }),
        "cognition" => json!({
            "mandate-ref": "a".repeat(64),
            "resource": { "kind": "model", "name": "claude" },
            "cost": { "tokens-in": 1, "tokens-out": 1 }
        }),
        "aggregate" => json!({
            "mandate-ref": "a".repeat(64),
            "policy-version": "2026.07.1",
            "classification": "read",
            "window": { "from": "2026-07-26T08:55:00.000Z", "to": "2026-07-26T09:00:00.000Z" },
            "counts": { "total": 2, "by-action": { "github.get_file": 2 } },
            "sample-hashes": ["d".repeat(64)]
        }),
        "mandate" => json!({ "mandate": { "kind": "mandate" } }),
        "revocation" => {
            json!({ "revokes": "a".repeat(64), "revoked-at": "2026-07-26T09:00:00.000Z" })
        }
        "gate-decision" => json!({ "decision-of": "a".repeat(64) }),
        "signal" => json!({ "signal": {
            "source": "github", "received-at": "2026-07-26T09:00:00.000Z",
            "media-type": "application/json", "payload-hash": "e".repeat(64),
            "sender-verified": true, "retain-until": "2026-08-26T09:00:00.000Z"
        }}),
        "checkpoint" => json!({ "checkpoint": {
            "stream": "gw:dev:0001", "from-seq": 0, "to-seq": 1, "head-hash": "f".repeat(64)
        }}),
        other => panic!("{other} is not one of spec/02 section 2's kinds"),
    };
    let object = envelope.as_object_mut().expect("an object");
    for (member, value) in extra.as_object().expect("an object") {
        object.insert(member.clone(), value.clone());
    }
    envelope
}

/// A sample value for each member whose placement is under test.
fn sample(member: &str) -> Value {
    match member {
        "trigger" => json!({
            "signal-ref": "a".repeat(64), "standing-mandate-ref": "b".repeat(64)
        }),
        "memory-ref" => json!("svod://note/abc"),
        "correlation-ref" => json!("trace-1"),
        "policy-version" => json!("2026.07.1"),
        "commitment-ref" => json!({
            "object-type": "github.ticket", "object-id": "42", "transition": "opened"
        }),
        "evidence" => json!({
            "schema": "github.get_file.v1", "media-type": "application/json",
            "payload-hash": "a".repeat(64), "retain-until": "2026-08-26T09:00:00.000Z"
        }),
        other => panic!("no sample for {other}"),
    }
}

/// `spec/02 §2.1` — the members each kind MAY carry, beyond the common eight and its own required
/// set. Anything absent here is `schema-unknown-member` on that kind.
const MATRIX: [(&str, &[&str]); 9] = [
    (
        "effect",
        &[
            "evidence",
            "authorization",
            "trigger",
            "memory-ref",
            "commitment-ref",
            "correlation-ref",
        ],
    ),
    (
        "policy-change",
        &["evidence", "memory-ref", "correlation-ref"],
    ),
    ("aggregate", &["memory-ref", "correlation-ref"]),
    ("cognition", &["memory-ref", "correlation-ref"]),
    ("signal", &["memory-ref", "correlation-ref"]),
    ("mandate", &["memory-ref", "correlation-ref"]),
    ("revocation", &["reason", "memory-ref", "correlation-ref"]),
    (
        "gate-decision",
        &["decision", "memory-ref", "correlation-ref"],
    ),
    ("checkpoint", &["memory-ref", "correlation-ref"]),
];

/// The members whose placement the matrix decides, and which this file therefore probes.
const PROBED: [&str; 5] = [
    "trigger",
    "memory-ref",
    "correlation-ref",
    "policy-version",
    "commitment-ref",
];

#[test]
fn every_kind_accepts_exactly_the_optional_members_the_matrix_grants_it() {
    let mut mismatches: Vec<String> = Vec::new();
    for (kind, permitted) in MATRIX {
        // `policy-change` needs an authorization to be minimal at all; it is covered by the
        // envelope-shape vectors and its optional set is asserted through the others.
        if kind == "policy-change" {
            continue;
        }
        validate(&minimal(kind))
            .unwrap_or_else(|e| panic!("the minimal {kind} does not validate: {e}"));

        for member in PROBED {
            let mut envelope = minimal(kind);
            // A member the kind already requires is not an optional-placement question.
            if envelope.get(member).is_some() {
                continue;
            }
            envelope[member] = sample(member);
            let accepted = validate(&envelope).is_ok();
            let expected = permitted.contains(&member);
            if accepted != expected {
                // Collected rather than asserted one at a time: the first time this ran it produced
                // a list, and a list is what a reader needs to see whether the specification or the
                // implementation is the thing that is wrong.
                mismatches.push(format!(
                    "{kind} + {member}: this build {}, §02 §2.1 says it {}",
                    if accepted { "accepts" } else { "rejects" },
                    if expected { "may" } else { "may not" }
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "this implementation disagrees with §02 §2.1 on {} placements:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
}

#[test]
fn correlation_ref_is_the_one_member_every_kind_carries() {
    // §02 §10 makes it "stored and indexed, never interpreted" — a label for joining an audit to a
    // trace, with no meaning to the kernel. A member with no semantics has no reason to be refused
    // on any kind, and an operator correlating a mandate grant to the ticket that prompted it is
    // exactly the use it exists for.
    for (kind, permitted) in MATRIX {
        assert!(
            permitted.contains(&"correlation-ref"),
            "{kind} may not carry correlation-ref"
        );
    }
}

#[test]
fn trigger_is_confined_to_the_kind_it_can_mean_anything_on() {
    // §07 §4: `trigger` "links an effect to the signal that triggered it". A mandate grant, a
    // checkpoint or a cognition record has no effect to link, so the member would be decoration —
    // and a decorative member on a signed, chained record is a place to hide something.
    for (kind, permitted) in MATRIX {
        assert_eq!(
            permitted.contains(&"trigger"),
            kind == "effect",
            "{kind} disagrees with §02 §2.1 about trigger"
        );
    }
}

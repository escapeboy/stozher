//! `stozher-kernel policy export-bundle` — the object a component bootstraps from.
//!
//! Asserted against the real binary, for the same reason `revoke_cli.rs` is: the members and the
//! canonical encoding are what a *second* implementation reads. Here that second implementation is
//! the Python gateway (`stozher_gateway/bundle.py`), which refuses a bundle missing any member of
//! the signed body — so a command that dropped one, renamed one, or wrote `anchor: null` where the
//! reader expects the member to be absent would still produce a perfectly valid signed object and
//! would still satisfy every test written on this side of the wire.
//!
//! The refusals matter as much as the success. A bundle path that signs whatever it is handed is
//! worse than no bundle path: it moves the discovery of a broken policy from the operator's terminal
//! to a container nobody is watching.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, process};

use serde_json::{Value, json};

/// The signed body's members. Written down here because this is the wire contract with a reader in
/// another language, and a contract that is only ever derived from the writer is not a contract.
const MEMBERS: [&str; 8] = [
    "anchor",
    "bundle-version",
    "exported-at",
    "kind",
    "max-age",
    "policy",
    "revocations",
    "sig",
    // `v` is the ninth and is asserted separately, below, so this list stays sorted by eye.
];

struct Fixture {
    dir: PathBuf,
    seed: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("stozher-bundle-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch directory");
        let seed = dir.join("root.seed");
        let status = Command::new(env!("CARGO_BIN_EXE_stozher-kernel"))
            .args(["keygen", "--out"])
            .arg(&seed)
            .status()
            .expect("running keygen");
        assert!(status.success(), "keygen failed");
        Self { dir, seed }
    }

    fn write(&self, name: &str, document: &Value) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, serde_json::to_string(document).expect("JSON")).expect("writing");
        path
    }

    /// A policy signed by this fixture's seed at the organization policy role.
    fn signed_policy(&self) -> Value {
        let key = stozher_kernel::keys::Seed::load(&self.seed)
            .expect("the seed")
            .derive(stozher_kernel::keys::ROLE_ORG_POLICY, 0)
            .expect("the policy key");
        key.sign(&json!({
            "v": "stozher/0.1",
            "kind": "policy",
            "policy-version": "2026.07.1",
            "issued-at": "2026-07-01T00:00:00.000Z",
            "classification": {"default-unknown": "consequential", "by-action": {}},
            "gate-rules": [{"classes": ["read", "benign"], "decision": "allow"}],
            "offline": {"read": "allow", "benign": "allow", "consequential": "block"},
            "evidence-ttl": {"read": "P0D"},
        }))
        .expect("signing the policy")
    }

    fn export(&self, extra: &[&str]) -> (bool, String, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_stozher-kernel"))
            .args(["policy", "export-bundle", "--key"])
            .arg(&self.seed)
            .args(["--role", "0", "--index", "0"])
            .args(extra)
            .output()
            .expect("running the kernel binary");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn read(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("the bundle")).expect("valid JSON")
}

#[test]
fn the_bundle_carries_the_members_the_reader_requires_and_verifies_as_one_object() {
    let fixture = Fixture::new("members");
    let policy = fixture.write("policy.json", &fixture.signed_policy());
    let anchor = fixture.write("anchor.json", &json!({"heads": []}));
    let out = fixture.dir.join("bundle.json");

    let (ok, stdout, stderr) = fixture.export(&[
        "--policy",
        policy.to_str().unwrap(),
        "--anchor",
        anchor.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--max-age",
        "P2D",
    ]);
    assert!(ok, "export failed:\n{stdout}{stderr}");

    let bundle = read(&out);
    let members: BTreeSet<&str> = bundle
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected: BTreeSet<&str> = MEMBERS.into_iter().collect();
    expected.insert("v");
    assert_eq!(
        members, expected,
        "the bundle's members are the wire contract"
    );

    assert_eq!(bundle["v"], "stozher/0.1");
    assert_eq!(bundle["kind"], "policy-bundle");
    assert_eq!(bundle["bundle-version"], 1);
    assert_eq!(bundle["max-age"], "P2D");
    assert_eq!(bundle["policy"]["policy-version"], "2026.07.1");
    assert_eq!(bundle["revocations"], json!([]));
    assert_eq!(bundle["anchor"], json!({"heads": []}));

    // One signature over the whole body, so tampering with any part of it is one failure. This is
    // the same check the gateway runs before it trusts a byte of the bundle.
    let signer = stozher_core::signed::verify_signed_object(&bundle).expect("the signature");
    assert_eq!(
        signer.as_str(),
        bundle["sig"]["key"].as_str().expect("a signing key")
    );
    // The file is the artefact; stdout stays empty so the command can be run from a script that is
    // watching for output, and everything a human reads is on stderr.
    assert!(stdout.is_empty(), "stdout carried {stdout:?}");
    assert!(stderr.contains("enforceable until"), "{stderr}");
}

#[test]
fn an_unexported_anchor_is_an_explicit_null_and_not_an_absent_member() {
    // "We anchored nothing" and "this bundle predates anchors" must not read the same at the
    // component: the reader refuses a bundle with no `anchor` member at all, so writing one is what
    // makes the empty case a statement a root signed rather than an omission.
    let fixture = Fixture::new("no-anchor");
    let policy = fixture.write("policy.json", &fixture.signed_policy());
    let out = fixture.dir.join("bundle.json");

    let (ok, stdout, stderr) = fixture.export(&[
        "--policy",
        policy.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "export failed:\n{stdout}{stderr}");

    let bundle = read(&out);
    assert!(bundle.get("anchor").is_some(), "the member must be present");
    assert_eq!(bundle["anchor"], Value::Null);
    // The default lifetime, stated in the document rather than left to the reader to assume.
    assert_eq!(bundle["max-age"], "P7D");
}

#[test]
fn a_policy_that_does_not_verify_is_refused_before_it_is_signed_into_anything() {
    // The likeliest operator mistake by far: exporting the draft `policy-draft` stripped instead of
    // the document `policy-sign` produced. Discovering it here costs one line on a terminal;
    // discovering it at the component costs a container that will not start and a person who has
    // forgotten which file they used.
    let fixture = Fixture::new("unsigned");
    let mut unsigned = fixture.signed_policy();
    unsigned["policy-version"] = json!("2026.07.2"); // edited after signing
    let policy = fixture.write("policy.json", &unsigned);
    let out = fixture.dir.join("bundle.json");

    let (ok, _, stderr) = fixture.export(&[
        "--policy",
        policy.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!ok, "a tampered policy was exported anyway");
    assert!(stderr.contains("does not verify"), "{stderr}");
    assert!(!out.exists(), "a refused export still wrote {out:?}");
}

#[test]
fn a_max_age_this_build_cannot_evaluate_is_refused_rather_than_defaulted() {
    // Months and years are not representable (§01 §2.4), and a bundle whose lifetime cannot be
    // computed is not a bundle with no lifetime.
    let fixture = Fixture::new("max-age");
    let policy = fixture.write("policy.json", &fixture.signed_policy());
    let out = fixture.dir.join("bundle.json");

    for (bad, why) in [
        ("P1M", "months are not a duration"),
        ("PT0S", "expires on export"),
    ] {
        let (ok, _, stderr) = fixture.export(&[
            "--policy",
            policy.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--max-age",
            bad,
        ]);
        assert!(!ok, "{bad} was accepted ({why})");
        assert!(stderr.contains("max-age"), "{stderr}");
        assert!(!out.exists(), "a refused export still wrote {out:?}");
    }
}

#[test]
fn a_revocation_set_that_does_not_verify_is_refused() {
    // The component refuses the *whole* bundle over one bad entry, unlike the live feed which drops
    // one and keeps going. That asymmetry is why the check belongs here too: the set is what a root
    // is vouching for, and this is the last moment a human can be told.
    let fixture = Fixture::new("revocations");
    let policy = fixture.write("policy.json", &fixture.signed_policy());
    let out = fixture.dir.join("bundle.json");
    let revocations = fixture.write(
        "revocations.json",
        &json!([{"v": "stozher/0.1", "kind": "revocation", "revokes": "a".repeat(64),
                 "revoked-at": "2026-07-02T00:00:00.000Z"}]),
    );

    let (ok, _, stderr) = fixture.export(&[
        "--policy",
        policy.to_str().unwrap(),
        "--revocations",
        revocations.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!ok, "an unsigned revocation was exported anyway");
    assert!(stderr.contains("does not verify"), "{stderr}");
    assert!(!out.exists(), "a refused export still wrote {out:?}");
}

//! `stozher-kernel verify` on a store with nothing in it.
//!
//! This is asserted against the real binary rather than a library seam because the thing at risk is
//! the **exit code**, and the exit code is what `deploy/bin/stozher-restore` branches on: it runs
//! `verify` on the restored store and walks the restore back if it fails. A restore that produced an
//! empty store therefore has to fail here, or the script concludes it succeeded and leaves the
//! operator with a green line over nothing.
//!
//! An empty store cannot be told apart from a wiped one by anything the box holds. A deployment that
//! has ever run has at least the two genesis envelopes of §05 §5.2, so "no streams" on a box that is
//! supposed to hold an audit trail is a data-loss incident, and the honest answer is a refusal.
//! `verify` reporting SUCCESS for it was the one failure mode the command exists to catch.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::json;

/// A minimal valid configuration pointing at `database`, written into a scratch directory.
fn config_for(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("stozher-verify-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch directory");
    let database = dir.join("stozher.db");
    let config = dir.join("kernel-config.json");
    let document = json!({
        "bind": "127.0.0.1:0",
        "database": database,
        "kernel-seed": dir.join("kernel.seed"),
        "policy-key": "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
        "kernel-core-stream": "kernel:core",
        "checkpoint-stream": "kernel:checkpoints",
        "rejection-stream": "kernel:rejections",
        "max-future-skew-seconds": 300,
        "roots": [{
            "subject": "human:ivan",
            "key": "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
            "enrolled-at": "2026-07-26T08:00:00.000Z"
        }],
        "callers": [{
            "subject": "agent:gateway",
            "token-sha256": "2222222222222222222222222222222222222222222222222222222222222222"
        }],
        "console-base-url": "https://stozher.acme.internal",
        "notifications": []
    });
    fs::write(
        &config,
        serde_json::to_string_pretty(&document).expect("config json"),
    )
    .expect("writing the config");

    // The kernel refuses a seed file that is not mode 0600, so the ceremony's own posture is not
    // weakened just because this is a test.
    fs::write(dir.join("kernel.seed"), "0".repeat(64)).expect("writing the seed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("kernel.seed"), fs::Permissions::from_mode(0o600))
            .expect("seed permissions");
    }
    (config, dir)
}

#[test]
fn verify_refuses_an_empty_store_rather_than_reporting_it_verified() {
    let (config, dir) = config_for("empty");

    let output = Command::new(env!("CARGO_BIN_EXE_stozher-kernel"))
        .args(["verify", "--config"])
        .arg(&config)
        .output()
        .expect("running the kernel binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        !output.status.success(),
        "verify reported success over an empty store:\n{combined}"
    );
    // The operator has to be able to tell this apart from a chain that failed verification: one is
    // "your records are wrong", the other is "you have no records". Naming it is the difference
    // between re-running a restore and hunting a tamper that never happened.
    assert!(
        combined.contains("no streams"),
        "the refusal must say the store is empty, not merely fail:\n{combined}"
    );

    let _ = fs::remove_dir_all(dir);
}

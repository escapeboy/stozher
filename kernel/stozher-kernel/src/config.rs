//! Kernel configuration.
//!
//! JSON rather than TOML on purpose: everything else in this system is JSON with one canonical form,
//! and a second document language is a second parser to reason about. The file holds **no secrets** —
//! caller credentials appear only as SHA-256 hashes of their bearer tokens, and the only key material
//! referenced is a path to a file the kernel refuses to read unless it is owner-only ([`crate::keys`]).

use std::path::{Path, PathBuf};

use serde_json::Value;
use stozher_core::crypto::is_digest_hex;
use stozher_core::error::{Error, Result};
use stozher_core::signed::KeyId;

/// A human root the deployment trusts.
///
/// The bootstrap ceremony that turns these into `kernel.enroll_root` envelopes is S5. Until then the
/// root set enters through configuration, which is the honest place for it: operator-controlled and
/// visible. It grants no approval — an enrolled root can *sign* approvals; it cannot make a gated
/// envelope appendable without one.
#[derive(Debug, Clone)]
pub struct ConfiguredRoot {
    /// The root's key.
    pub key: KeyId,
    /// Its named human subject, of the form `human:<name>`.
    pub subject: String,
    /// When the ceremony enrolled it.
    pub enrolled_at: String,
}

/// A component permitted to talk to the kernel (§05 §2.2, §10 §1.1).
#[derive(Debug, Clone)]
pub struct ConfiguredCaller {
    /// The subject a successful credential resolves to. Recorded on rejections (§04 §7).
    pub subject: String,
    /// SHA-256 of the bearer token, lowercase hex. The token itself is never stored.
    pub token_sha256: String,
}

/// The kernel's configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to serve on.
    pub bind: String,
    /// SQLite database path.
    pub database: PathBuf,
    /// Path to the kernel's seed file, from which the checkpoint key at role `3'` is derived.
    pub kernel_seed: PathBuf,
    /// The organization's policy key at role `4'`.
    pub policy_key: KeyId,
    /// The kernel's own stream (§04 §1).
    pub kernel_core_stream: String,
    /// The stream checkpoints live in (§04 §4.5).
    pub checkpoint_stream: String,
    /// The stream rejection records live in (§04 §7).
    pub rejection_stream: String,
    /// How far into the future an `emitted-at` may be (§09 §5).
    pub max_future_skew_seconds: i64,
    /// The enrolled human roots.
    pub roots: Vec<ConfiguredRoot>,
    /// Permitted callers.
    pub callers: Vec<ConfiguredCaller>,
}

const MEMBERS: [&str; 10] = [
    "bind",
    "database",
    "kernel-seed",
    "policy-key",
    "kernel-core-stream",
    "checkpoint-stream",
    "rejection-stream",
    "max-future-skew-seconds",
    "roots",
    "callers",
];

impl Config {
    /// Read and validate a configuration file.
    ///
    /// # Errors
    ///
    /// `config-unreadable`, `config-malformed`, or a `key-id-malformed` from a bad key identifier.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::new("config-unreadable", format!("{}: {e}", path.display())))?;
        let document: Value = serde_json::from_str(&text)
            .map_err(|e| Error::new("config-malformed", format!("{}: {e}", path.display())))?;
        Self::parse(&document)
    }

    /// Validate an already-parsed configuration document.
    ///
    /// # Errors
    ///
    /// `config-malformed`, or `key-id-malformed`.
    pub fn parse(document: &Value) -> Result<Self> {
        let map = document
            .as_object()
            .ok_or_else(|| Error::new("config-malformed", "configuration must be an object"))?;
        for key in map.keys() {
            if !MEMBERS.contains(&key.as_str()) {
                return Err(Error::new(
                    "config-malformed",
                    format!("unknown configuration member {key:?}"),
                ));
            }
        }
        let text = |name: &str, default: &str| -> String {
            map.get(name)
                .and_then(Value::as_str)
                .unwrap_or(default)
                .to_owned()
        };
        let required = |name: &str| -> Result<&str> {
            map.get(name).and_then(Value::as_str).ok_or_else(|| {
                Error::new("config-malformed", format!("{name} is required"))
            })
        };

        let policy_key = KeyId::parse(required("policy-key")?)?;

        let mut roots = Vec::new();
        for entry in map.get("roots").and_then(Value::as_array).into_iter().flatten() {
            let key = KeyId::parse(entry["key"].as_str().ok_or_else(|| {
                Error::new("config-malformed", "roots[].key is required")
            })?)?;
            let subject = entry["subject"]
                .as_str()
                .filter(|s| s.starts_with("human:") && s.len() > "human:".len())
                .ok_or_else(|| {
                    // A root is a named human. "the team" cannot be nudged (maxim 3).
                    Error::new(
                        "config-malformed",
                        "roots[].subject must be a named human, of the form human:<name>",
                    )
                })?
                .to_owned();
            let enrolled_at = entry["enrolled-at"]
                .as_str()
                .ok_or_else(|| Error::new("config-malformed", "roots[].enrolled-at is required"))?;
            crate::clock::parse_timestamp(enrolled_at)?;
            roots.push(ConfiguredRoot {
                key,
                subject,
                enrolled_at: enrolled_at.to_owned(),
            });
        }

        let mut callers = Vec::new();
        for entry in map.get("callers").and_then(Value::as_array).into_iter().flatten() {
            let subject = entry["subject"]
                .as_str()
                .ok_or_else(|| Error::new("config-malformed", "callers[].subject is required"))?
                .to_owned();
            let token_sha256 = entry["token-sha256"]
                .as_str()
                .filter(|h| is_digest_hex(h))
                .ok_or_else(|| {
                    Error::new(
                        "config-malformed",
                        "callers[].token-sha256 must be 64 lowercase hex digits — configuration \
                         never holds a token in the clear",
                    )
                })?
                .to_owned();
            callers.push(ConfiguredCaller {
                subject,
                token_sha256,
            });
        }

        Ok(Self {
            bind: text("bind", "127.0.0.1:8787"),
            database: PathBuf::from(text("database", "var/stozher.db")),
            kernel_seed: PathBuf::from(text("kernel-seed", "keys/kernel.seed")),
            policy_key,
            kernel_core_stream: text("kernel-core-stream", "kernel:core"),
            checkpoint_stream: text("checkpoint-stream", "kernel:checkpoints"),
            rejection_stream: text("rejection-stream", "kernel:rejections"),
            max_future_skew_seconds: map
                .get("max-future-skew-seconds")
                .and_then(Value::as_i64)
                .unwrap_or(300),
            roots,
            callers,
        })
    }

    /// Resolve a bearer token to its caller subject, in constant time with respect to the token.
    ///
    /// # Errors
    ///
    /// [`crate::codes::CALLER_UNAUTHENTICATED`] when no configured caller matches.
    pub fn authenticate(&self, token: &str) -> Result<&str> {
        let presented = stozher_core::crypto::sha256_hex(token.as_bytes());
        let mut found: Option<&str> = None;
        for caller in &self.callers {
            // Compare every candidate and keep going: an early return would leak, through timing,
            // how many configured callers share a prefix with the presented token.
            if constant_time_eq(caller.token_sha256.as_bytes(), presented.as_bytes()) {
                found = Some(&caller.subject);
            }
        }
        found.ok_or_else(|| {
            Error::new(
                crate::codes::CALLER_UNAUTHENTICATED,
                "the presented credential does not resolve to a configured caller",
            )
        })
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        format!("ed25519:{}", hex::encode([byte; 32]))
    }

    fn document() -> Value {
        serde_json::json!({
            "policy-key": key(1),
            "roots": [ { "subject": "human:ivan", "key": key(2), "enrolled-at": "2026-07-26T08:00:00.000Z" } ],
            "callers": [ { "subject": "agent:gateway", "token-sha256": stozher_core::crypto::sha256_hex(b"secret") } ]
        })
    }

    #[test]
    fn a_configured_token_resolves_to_its_subject() {
        let config = Config::parse(&document()).unwrap();
        assert_eq!(config.authenticate("secret").unwrap(), "agent:gateway");
        assert_eq!(
            config.authenticate("wrong").unwrap_err().code(),
            crate::codes::CALLER_UNAUTHENTICATED
        );
    }

    #[test]
    fn configuration_never_holds_a_token_in_the_clear() {
        let mut document = document();
        document["callers"][0] = serde_json::json!({
            "subject": "agent:gateway",
            "token-sha256": "secret"
        });
        assert_eq!(Config::parse(&document).unwrap_err().code(), "config-malformed");
    }

    #[test]
    fn a_root_must_be_a_named_human() {
        let mut document = document();
        document["roots"][0]["subject"] = Value::from("the-team");
        assert_eq!(Config::parse(&document).unwrap_err().code(), "config-malformed");
        document["roots"][0]["subject"] = Value::from("human:");
        assert_eq!(Config::parse(&document).unwrap_err().code(), "config-malformed");
    }

    #[test]
    fn unknown_members_are_refused_rather_than_ignored() {
        let mut document = document();
        document["gate-bypass"] = Value::from(true);
        assert_eq!(Config::parse(&document).unwrap_err().code(), "config-malformed");
    }
}

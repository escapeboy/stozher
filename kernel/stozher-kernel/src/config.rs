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
    /// The approver-ping channels (ADR-0002: Slack, SMTP, generic webhook, and nothing else).
    pub notifications: Vec<ConfiguredChannel>,
    /// Where this deployment's console answers, for the link inside an approver ping.
    pub console_base_url: Option<String>,
    /// The approver-flood bound of §09 §7.
    pub gate_rate_limit: RateLimit,
    /// How often the kernel runs payload decay, in seconds (`decay-interval`).
    ///
    /// It lives here rather than in policy for ADR-0010's reason: `spec/05 §1`'s member set is
    /// closed and every member is required, so a new policy member is a breaking wire change that
    /// invalidates every existing document and every vector at once. A sweep frequency also
    /// authorizes nothing and changes nobody's rights — *what* may be deleted and *when* is already
    /// policy's `retention` ceiling, and this only decides how often the kernel gets round to acting
    /// on what policy already decided.
    ///
    /// There is deliberately no way to switch it off. Turning the timer off would not retain
    /// anything longer — retention is policy's — it would only stop the product doing what it
    /// advertises, which is the failure `deploy/README.md` §5 was written about.
    pub decay_interval_seconds: i64,
}

/// How many gate requests one subject may park in one window (§09 §7).
///
/// > "Approval fatigue is an availability attack: an adversary that generates many gate-worthy
/// > actions can train an approver to click through."
///
/// There is no way to switch this off. §09 §7 states it as a MUST, and a cap an operator can set to
/// zero on a busy afternoon is a cap that is off in every deployment that ever had a busy
/// afternoon. Raising it is a number in a file that a reviewer can see; removing it is not offered.
#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    /// Requests one subject may park per window.
    pub per_subject: u32,
    /// The window, in seconds.
    pub window_seconds: i64,
}

impl Default for RateLimit {
    fn default() -> Self {
        // Thirty parked requests from one subject in five minutes is already a queue no human reads
        // carefully, which is the failure §09 §7 describes. Ordinary work does not come close: a
        // gated action is one a human is about to be asked about, not one an agent performs in a
        // loop.
        Self {
            per_subject: 30,
            window_seconds: 300,
        }
    }
}

/// One configured notification channel. Credentials appear only as the **names** of environment
/// variables (`*-env`), never as values: a configuration file is copied, diffed and pasted into
/// tickets, and a webhook URL with a token in it is a secret in all three places.
#[derive(Debug, Clone)]
pub enum ConfiguredChannel {
    /// Slack incoming webhook. The URL is the credential.
    Slack {
        /// Environment variable holding the webhook URL.
        url_env: String,
    },
    /// A generic webhook receiving the ping as JSON.
    Webhook {
        /// Environment variable holding the URL.
        url_env: String,
        /// Environment variable holding a bearer token, if the endpoint wants one.
        token_env: Option<String>,
    },
    /// Email through an SMTP relay.
    Smtp {
        /// Relay host.
        host: String,
        /// Relay port.
        port: u16,
        /// Envelope sender.
        from: String,
        /// Recipients. A rotation MAY decide whom to notify; the *signature* is always one
        /// person's (§06 §5), so a list here says nothing about who may approve.
        to: Vec<String>,
        /// SMTP username, when the relay wants one.
        username: Option<String>,
        /// Environment variable holding the password.
        password_env: Option<String>,
    },
}

const MEMBERS: [&str; 14] = [
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
    "notifications",
    "console-base-url",
    "gate-rate-limit",
    "decay-interval",
];

/// Once a day. Retention deadlines in this system are expressed in days (§05 §6), so a sweep an
/// order of magnitude finer than the thing it enforces buys nothing, and one coarser than a day
/// would let a payload outlive its `retain-until` by longer than the shortest retention a policy can
/// express.
const DEFAULT_DECAY_INTERVAL_SECONDS: i64 = 86_400;

/// Members of a `notifications[]` entry, per channel. Closed, so a misspelled key is a startup
/// failure rather than a channel that silently never fires.
const CHANNEL_MEMBERS: [(&str, &[&str]); 3] = [
    ("slack", &["channel", "webhook-url-env"]),
    ("webhook", &["channel", "url-env", "token-env"]),
    (
        "smtp",
        &[
            "channel",
            "host",
            "port",
            "from",
            "to",
            "username",
            "password-env",
        ],
    ),
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
            map.get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| Error::new("config-malformed", format!("{name} is required")))
        };

        let policy_key = KeyId::parse(required("policy-key")?)?;

        let mut roots = Vec::new();
        for entry in map
            .get("roots")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let key = KeyId::parse(
                entry["key"]
                    .as_str()
                    .ok_or_else(|| Error::new("config-malformed", "roots[].key is required"))?,
            )?;
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
        for entry in map
            .get("callers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
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

        let mut notifications = Vec::new();
        for entry in map
            .get("notifications")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            notifications.push(parse_channel(entry)?);
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
            notifications,
            console_base_url: map
                .get("console-base-url")
                .and_then(Value::as_str)
                .map(str::to_owned),
            gate_rate_limit: parse_rate_limit(map.get("gate-rate-limit"))?,
            decay_interval_seconds: parse_decay_interval(map.get("decay-interval"))?,
        })
    }

    /// Build the approver-ping adapter this configuration describes.
    ///
    /// Zero channels is a legitimate deployment — a single operator watching the console — and the
    /// pending page says so in words rather than rendering an empty notification column that reads
    /// like "delivered".
    #[must_use]
    pub fn notifier(&self) -> crate::notify::Notifier {
        let channels = self
            .notifications
            .iter()
            .map(|configured| -> Box<dyn crate::notify::Channel> {
                match configured.clone() {
                    ConfiguredChannel::Slack { url_env } => {
                        Box::new(crate::notify::SlackWebhook::new(url_env))
                    }
                    ConfiguredChannel::Webhook { url_env, token_env } => {
                        Box::new(crate::notify::Webhook::new(url_env, token_env))
                    }
                    ConfiguredChannel::Smtp {
                        host,
                        port,
                        from,
                        to,
                        username,
                        password_env,
                    } => Box::new(crate::notify::Smtp::new(
                        host,
                        port,
                        from,
                        to,
                        username,
                        password_env,
                    )),
                }
            })
            .collect();
        crate::notify::Notifier::new(channels)
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

/// Parse `gate-rate-limit`, which is closed and bounded in both directions.
///
/// A cap of zero would refuse every request and turn the flood defence into an outage; a window of
/// zero would make the cap unenforceable. Both are refused at startup rather than discovered when
/// the first genuine gate never reaches an approver.
fn parse_rate_limit(entry: Option<&Value>) -> Result<RateLimit> {
    let Some(entry) = entry else {
        return Ok(RateLimit::default());
    };
    let map = entry
        .as_object()
        .ok_or_else(|| Error::new("config-malformed", "gate-rate-limit must be an object"))?;
    for key in map.keys() {
        if !["per-subject", "window"].contains(&key.as_str()) {
            return Err(Error::new(
                "config-malformed",
                format!("gate-rate-limit has no member {key:?}"),
            ));
        }
    }
    let default = RateLimit::default();
    let per_subject = match map.get("per-subject") {
        None => default.per_subject,
        Some(value) => {
            let count = value
                .as_u64()
                .and_then(|c| u32::try_from(c).ok())
                .ok_or_else(|| {
                    Error::new(
                        "config-malformed",
                        "gate-rate-limit.per-subject must be a positive integer",
                    )
                })?;
            if count == 0 {
                return Err(Error::new(
                    "config-malformed",
                    "gate-rate-limit.per-subject must be at least 1 — spec 09 section 7 requires a \
                     cap, and a cap of zero refuses every gate rather than bounding a flood",
                ));
            }
            count
        }
    };
    let window_seconds = match map.get("window") {
        None => default.window_seconds,
        Some(value) => {
            let duration = value.as_str().ok_or_else(|| {
                Error::new(
                    "config-malformed",
                    "gate-rate-limit.window must be an ISO 8601 duration",
                )
            })?;
            let seconds = crate::clock::parse_duration_seconds(duration)?;
            if seconds <= 0 {
                return Err(Error::new(
                    "config-malformed",
                    "gate-rate-limit.window must be a positive duration",
                ));
            }
            seconds
        }
    };
    Ok(RateLimit {
        per_subject,
        window_seconds,
    })
}

/// Parse `decay-interval`, an ISO 8601 duration.
///
/// A non-positive interval is refused at startup rather than becoming a loop that spins, and the
/// absence of the member is the default rather than "no timer": a deployment that says nothing about
/// decay gets decay, because the alternative — silence meaning "never" — is exactly the defect this
/// timer exists to close.
fn parse_decay_interval(entry: Option<&Value>) -> Result<i64> {
    let Some(entry) = entry else {
        return Ok(DEFAULT_DECAY_INTERVAL_SECONDS);
    };
    let duration = entry.as_str().ok_or_else(|| {
        Error::new(
            "config-malformed",
            "decay-interval must be an ISO 8601 duration",
        )
    })?;
    let seconds = crate::clock::parse_duration_seconds(duration)?;
    if seconds <= 0 {
        return Err(Error::new(
            "config-malformed",
            "decay-interval must be a positive duration. There is no way to switch decay off: \
             retention is policy's to decide, and a kernel that never sweeps does not extend it, \
             it only stops enforcing it",
        ));
    }
    Ok(seconds)
}

/// Parse one `notifications[]` entry.
///
/// A member ending in `-env` names an environment variable. A member that *looked* like a secret —
/// `webhook-url`, `password` — is not in any channel's member list, so writing one is a startup
/// failure with the misspelling named, not a secret quietly living in a file.
fn parse_channel(entry: &Value) -> Result<ConfiguredChannel> {
    let map = entry.as_object().ok_or_else(|| {
        Error::new(
            "config-malformed",
            "notifications[] entries must be objects",
        )
    })?;
    let channel = map
        .get("channel")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("config-malformed", "notifications[].channel is required"))?;
    let allowed = CHANNEL_MEMBERS
        .iter()
        .find(|(name, _)| *name == channel)
        .map(|(_, members)| *members)
        .ok_or_else(|| {
            // ADR-0002 fixes the set at three. A fourth is a product decision that has to argue
            // with the inclusion test, not a configuration key someone fills in.
            Error::new(
                "config-malformed",
                format!(
                    "notifications[].channel {channel:?} is not one of slack, smtp, webhook — \
                     Stozher owns exactly one outbound and exactly these three channels"
                ),
            )
        })?;
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(Error::new(
                "config-malformed",
                format!("notifications[] {channel} channel has no member {key:?}"),
            ));
        }
    }
    let required = |name: &str| -> Result<String> {
        map.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                Error::new(
                    "config-malformed",
                    format!("notifications[] {channel} channel requires {name}"),
                )
            })
    };
    let optional = |name: &str| map.get(name).and_then(Value::as_str).map(str::to_owned);

    match channel {
        "slack" => Ok(ConfiguredChannel::Slack {
            url_env: required("webhook-url-env")?,
        }),
        "webhook" => Ok(ConfiguredChannel::Webhook {
            url_env: required("url-env")?,
            token_env: optional("token-env"),
        }),
        _ => {
            let to: Vec<String> = map
                .get("to")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            if to.is_empty() {
                return Err(Error::new(
                    "config-malformed",
                    "notifications[] smtp channel requires at least one recipient in to",
                ));
            }
            let port = map.get("port").and_then(Value::as_u64).unwrap_or(25);
            Ok(ConfiguredChannel::Smtp {
                host: required("host")?,
                port: u16::try_from(port).map_err(|_| {
                    Error::new("config-malformed", format!("notifications[] port {port}"))
                })?,
                from: required("from")?,
                to,
                username: optional("username"),
                password_env: optional("password-env"),
            })
        }
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
    fn a_deployment_that_says_nothing_about_decay_still_gets_it() {
        // The defect this closes was a property nobody had switched on. Silence must therefore mean
        // "sweep daily", not "never sweep" — the reading that produced the original defect.
        assert_eq!(
            Config::parse(&document()).unwrap().decay_interval_seconds,
            DEFAULT_DECAY_INTERVAL_SECONDS
        );
    }

    #[test]
    fn a_decay_interval_is_a_duration_and_must_be_positive() {
        let mut document = document();
        document["decay-interval"] = Value::from("PT6H");
        assert_eq!(
            Config::parse(&document).unwrap().decay_interval_seconds,
            6 * 60 * 60
        );

        // The two ways to ask for a timer that never fires, both refused at startup rather than
        // becoming a loop that spins or one that never runs. They refuse under different codes and
        // that is not an inconsistency: a negative duration is not a duration at all and never
        // reaches this member's own rule, so §01 §2.4's parser turns it away first — the same split
        // `gate-rate-limit.window` already has.
        document["decay-interval"] = Value::from("-PT1H");
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "encoding-bad-duration",
            "a negative decay interval was accepted"
        );
        document["decay-interval"] = Value::from("PT0S");
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "config-malformed",
            "a zero decay interval was accepted"
        );
        document["decay-interval"] = Value::from(3600);
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "config-malformed",
            "a bare number was accepted where an ISO 8601 duration is required"
        );
    }

    #[test]
    fn configuration_never_holds_a_token_in_the_clear() {
        let mut document = document();
        document["callers"][0] = serde_json::json!({
            "subject": "agent:gateway",
            "token-sha256": "secret"
        });
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "config-malformed"
        );
    }

    #[test]
    fn a_root_must_be_a_named_human() {
        let mut document = document();
        document["roots"][0]["subject"] = Value::from("the-team");
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "config-malformed"
        );
        document["roots"][0]["subject"] = Value::from("human:");
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "config-malformed"
        );
    }

    #[test]
    fn a_notification_channel_names_the_variable_holding_its_secret_not_the_secret() {
        let mut document = document();
        document["notifications"] = serde_json::json!([
            { "channel": "slack", "webhook-url-env": "STOZHER_SLACK_WEBHOOK" },
            { "channel": "webhook", "url-env": "STOZHER_WEBHOOK_URL", "token-env": "STOZHER_WEBHOOK_TOKEN" },
            { "channel": "smtp", "host": "127.0.0.1", "port": 25, "from": "stozher@acme.internal",
              "to": ["ivan@acme.internal"] }
        ]);
        let config = Config::parse(&document).unwrap();
        assert_eq!(config.notifications.len(), 3);
        assert_eq!(config.notifier().channel_count(), 3);

        // The literal spelling is not a member of any channel, so a secret in the file is a
        // startup failure rather than a secret in the file.
        document["notifications"] = serde_json::json!([
            { "channel": "slack", "webhook-url": "https://hooks.slack.com/services/T/B/xoxb-secret" }
        ]);
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "config-malformed"
        );
    }

    #[test]
    fn a_fourth_notification_channel_is_refused() {
        // ADR-0002 fixes the set at three: "the only outbound Stozher owns … 2-3 channels max".
        let mut document = document();
        document["notifications"] =
            serde_json::json!([ { "channel": "sms", "url-env": "STOZHER_SMS" } ]);
        let error = Config::parse(&document).unwrap_err();
        assert_eq!(error.code(), "config-malformed");
        assert!(error.detail().contains("slack, smtp, webhook"));
    }

    #[test]
    fn unknown_members_are_refused_rather_than_ignored() {
        let mut document = document();
        document["gate-bypass"] = Value::from(true);
        assert_eq!(
            Config::parse(&document).unwrap_err().code(),
            "config-malformed"
        );
    }
}

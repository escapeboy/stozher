//! The approver ping — the only outbound Stozher owns (ADR-0002, `docs/design/console.md`).
//!
//! > *"Sending a message is a governed consequential effect (client's own tools via gateway), not
//! > infrastructure we provide. Stozher owns exactly one outbound: the approver ping (minimal
//! > notification adapter, Slack/email/webhook) — console dependency, nothing more."*
//!
//! So: three channels, a trait, and a hard stop. Adding a fourth is a product decision that has to
//! argue with ADR-0002's inclusion test, not a configuration key someone fills in.
//!
//! # Three rules this module holds
//!
//! **No plaintext secrets.** Every credential is named by the environment variable that holds it
//! (`*_env`, the convention `docs/gateway-integration-constraints.md` §1 harvested from
//! Harbormaster's own config). A configuration file that carried a webhook URL with its token in it
//! would be a secret in a file operators copy, diff and paste into tickets.
//!
//! **A failure to notify is a record, never a dropped park.** Every attempt writes a
//! `gate_notifications` row with its outcome, and the console renders "nobody was told" differently
//! from "an approver was told" — the same distinction the fleet triage holds between `[unknown]`
//! and `[clean]`. The park itself is durable *before* any channel is touched, so a channel that is
//! down costs an approver a notification, never the queue a request.
//!
//! **The ping says nothing the refusal would not.** It carries the request hash, who asked, what
//! for, and where to answer. Never arguments, never other pending requests, never policy content,
//! never key material (§10 §6).

use std::time::Duration;

use serde_json::{Value, json};
use stozher_core::error::{Error, Result};

/// What an approver is told. Deliberately the same facts the structured refusal carries (§06 §4.1)
/// and no more: `args-hash` names the arguments, the arguments themselves stay in the evidence
/// payload where retention policy governs them.
#[derive(Debug, Clone)]
pub struct Ping {
    /// `object-hash` of the action request — the handle for answering it.
    pub request_hash: String,
    /// The subject that asked.
    pub subject: String,
    /// The component it acted through.
    pub component: String,
    /// The action it wants to perform.
    pub action: String,
    /// What it would act upon.
    pub target: String,
    /// The weight class policy computed.
    pub classification: String,
    /// When the request stops being answerable.
    pub not_after: String,
    /// Where a human answers it, when the deployment knows its own console URL.
    pub console_url: Option<String>,
}

impl Ping {
    /// One line, for a chat channel or a subject header.
    #[must_use]
    pub fn headline(&self) -> String {
        format!(
            "{} wants to {} on {} ({}) — expires {}",
            self.subject, self.action, self.target, self.classification, self.not_after
        )
    }

    /// The machine-readable form a generic webhook receives.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "stozher": stozher_core::VERSION,
            "event": "gate-parked",
            "request-hash": self.request_hash,
            "subject": self.subject,
            "component": self.component,
            "action": self.action,
            "target": self.target,
            "classification": self.classification,
            "not-after": self.not_after,
            "console-url": self.console_url
        })
    }

    /// The full text a human reads.
    #[must_use]
    pub fn body(&self) -> String {
        let mut text = format!(
            "A consequential action is parked awaiting a named human's signature.\n\n\
             subject:        {}\n\
             component:      {}\n\
             action:         {}\n\
             target:         {}\n\
             classification: {}\n\
             request-hash:   {}\n\
             expires:        {}\n",
            self.subject,
            self.component,
            self.action,
            self.target,
            self.classification,
            self.request_hash,
            self.not_after
        );
        if let Some(url) = &self.console_url {
            text.push_str(&format!("\nAnswer it at {url}/console/pending\n"));
        }
        // Never a workaround, an alternative action, or a way to proceed without approval
        // (§06 §4.1) — the ping is an invitation to decide, not a negotiation.
        text
    }
}

/// One outbound channel.
///
/// Trait-based because the *set* is fixed but the *transport* is the part a deployment varies, and
/// because a test must be able to capture a ping without a network. There is deliberately no
/// `enabled` flag and no "dry run" mode: a channel that is configured delivers, and one that is not
/// configured does not exist.
pub trait Channel: Send + Sync + std::fmt::Debug {
    /// The channel's name, as it appears in `gate_notifications.channel` and in the console.
    fn name(&self) -> &str;

    /// Deliver one ping, or say why it could not be delivered.
    ///
    /// # Errors
    ///
    /// `notify-failed` with a detail an operator can act on. The detail is written to the
    /// notification record, so it must never contain a credential.
    fn deliver(&self, ping: &Ping) -> Result<()>;
}

/// The failure code every channel reports. Not normative: `spec/06 §4.3` requires the notification
/// and says nothing about how a failed one is named.
pub const NOTIFY_FAILED: &str = "notify-failed";

fn failed(detail: impl std::fmt::Display) -> Error {
    Error::new(NOTIFY_FAILED, detail.to_string())
}

/// How long any one channel may take before the attempt is abandoned. A slow webhook must not hold
/// a notification worker; the park is already recorded either way.
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

/// Read a secret from the environment variable a configuration names.
///
/// # Errors
///
/// `notify-failed` when the variable is unset or empty — which is an operator error worth a loud
/// record rather than a channel that silently sends nothing.
fn secret(variable: &str) -> Result<String> {
    match std::env::var(variable) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        _ => Err(failed(format!("{variable} is unset"))),
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(CHANNEL_TIMEOUT))
        .build()
        .into()
}

/// Slack incoming webhook. The URL *is* the credential, so it is never in configuration.
#[derive(Debug, Clone)]
pub struct SlackWebhook {
    url_env: String,
}

impl SlackWebhook {
    /// Build from the name of the environment variable holding the webhook URL.
    #[must_use]
    pub fn new(url_env: String) -> Self {
        Self { url_env }
    }
}

impl Channel for SlackWebhook {
    fn name(&self) -> &str {
        "slack"
    }

    fn deliver(&self, ping: &Ping) -> Result<()> {
        let url = secret(&self.url_env)?;
        let body = json!({ "text": format!("*Stozher — approval needed*\n{}\n```{}```", ping.headline(), ping.body()) });
        let payload = serde_json::to_string(&body).map_err(failed)?;
        let response = agent()
            .post(&url)
            .header("content-type", "application/json")
            // The URL is the secret, so it must not reach the error path that becomes a stored
            // record. Every failure below reports the status, never the target.
            .send(payload)
            .map_err(|e| failed(format!("slack webhook: {e}")))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(failed(format!("slack webhook answered {status}")));
        }
        Ok(())
    }
}

/// A generic webhook: the ping as JSON, optionally behind a bearer credential.
#[derive(Debug, Clone)]
pub struct Webhook {
    url_env: String,
    token_env: Option<String>,
}

impl Webhook {
    /// Build from the environment variables holding the URL and, optionally, a bearer token.
    #[must_use]
    pub fn new(url_env: String, token_env: Option<String>) -> Self {
        Self { url_env, token_env }
    }
}

impl Channel for Webhook {
    fn name(&self) -> &str {
        "webhook"
    }

    fn deliver(&self, ping: &Ping) -> Result<()> {
        let url = secret(&self.url_env)?;
        let payload = serde_json::to_string(&ping.to_json()).map_err(failed)?;
        let mut request = agent()
            .post(&url)
            .header("content-type", "application/json");
        if let Some(variable) = &self.token_env {
            request = request.header("authorization", format!("Bearer {}", secret(variable)?));
        }
        let response = request
            .send(payload)
            .map_err(|e| failed(format!("webhook: {e}")))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(failed(format!("webhook answered {status}")));
        }
        Ok(())
    }
}

/// Email through an SMTP relay.
///
/// # Why this speaks plain SMTP to a relay, and refuses to authenticate over one that is not local
///
/// The kernel is the binary an auditor pen-tests, and a second TLS stack inside it is surface the
/// product's own pitch argues against (ADR-0003). The single-tenant on-premise shape this product
/// deploys into already has a relay — a local `postfix`, or the organization's own smarthost — and
/// pointing at it needs **no credential at all**, which is the strongest form of "no plaintext
/// secrets in config".
///
/// Where a credential *is* configured, this channel sends `AUTH PLAIN` **only** to a loopback
/// address, and otherwise refuses (`notify-failed`) rather than putting a password on the wire in
/// the clear. Refusing loudly is the honest failure; silently downgrading is the dishonest one.
#[derive(Debug, Clone)]
pub struct Smtp {
    host: String,
    port: u16,
    from: String,
    to: Vec<String>,
    username: Option<String>,
    password_env: Option<String>,
}

impl Smtp {
    /// Build an SMTP channel.
    #[must_use]
    pub fn new(
        host: String,
        port: u16,
        from: String,
        to: Vec<String>,
        username: Option<String>,
        password_env: Option<String>,
    ) -> Self {
        Self {
            host,
            port,
            from,
            to,
            username,
            password_env,
        }
    }

    fn is_loopback(&self) -> bool {
        use std::net::{Ipv4Addr, Ipv6Addr};

        self.host == "localhost"
            || self
                .host
                .parse::<Ipv4Addr>()
                .is_ok_and(|address| address.is_loopback())
            || self
                .host
                .parse::<Ipv6Addr>()
                .is_ok_and(|address| address.is_loopback())
    }

    fn message(&self, ping: &Ping) -> String {
        format!(
            "From: {}\r\nTo: {}\r\nSubject: [Stozher] approval needed: {}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\n{}",
            self.from,
            self.to.join(", "),
            ping.action,
            ping.body().replace("\r\n", "\n").replace('\n', "\r\n")
        )
    }
}

impl Channel for Smtp {
    fn name(&self) -> &str {
        "smtp"
    }

    fn deliver(&self, ping: &Ping) -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpStream;

        let credential = match (&self.username, &self.password_env) {
            (Some(user), Some(variable)) => {
                if !self.is_loopback() {
                    return Err(failed(format!(
                        "refusing AUTH PLAIN to {}: SMTP credentials are sent only to a loopback \
                         relay; point this channel at a local relay or drop the credential",
                        self.host
                    )));
                }
                Some((user.clone(), secret(variable)?))
            }
            (None, None) => None,
            _ => return Err(failed("smtp username and password-env are set together")),
        };

        let stream = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|e| failed(format!("smtp connect {}:{}: {e}", self.host, self.port)))?;
        stream.set_read_timeout(Some(CHANNEL_TIMEOUT)).ok();
        stream.set_write_timeout(Some(CHANNEL_TIMEOUT)).ok();
        let mut reader = BufReader::new(stream.try_clone().map_err(failed)?);
        let mut writer = stream;

        let expect = |reader: &mut BufReader<TcpStream>, wanted: u8| -> Result<()> {
            // SMTP multiline replies repeat the code with `-` until the last line, which uses a
            // space. Read until that last line so the next command is not answered by a leftover.
            loop {
                let mut line = String::new();
                let read = reader
                    .read_line(&mut line)
                    .map_err(|e| failed(format!("smtp read: {e}")))?;
                if read == 0 {
                    return Err(failed("smtp closed the connection"));
                }
                let code = line.as_bytes().first().copied().unwrap_or(b'0');
                if code != wanted {
                    return Err(failed(format!("smtp said {}", line.trim_end())));
                }
                if line.as_bytes().get(3).copied() != Some(b'-') {
                    return Ok(());
                }
            }
        };
        let say = |writer: &mut TcpStream, line: &str| -> Result<()> {
            writer
                .write_all(format!("{line}\r\n").as_bytes())
                .map_err(|e| failed(format!("smtp write: {e}")))
        };

        expect(&mut reader, b'2')?;
        say(&mut writer, "EHLO stozher")?;
        expect(&mut reader, b'2')?;
        if let Some((user, password)) = credential {
            // AUTH PLAIN is base64(\0user\0password); the password never appears in any error
            // detail below, only the reply code does.
            say(
                &mut writer,
                &format!("AUTH PLAIN {}", base64(&format!("\0{user}\0{password}"))),
            )?;
            expect(&mut reader, b'2')?;
        }
        say(&mut writer, &format!("MAIL FROM:<{}>", self.from))?;
        expect(&mut reader, b'2')?;
        for recipient in &self.to {
            say(&mut writer, &format!("RCPT TO:<{recipient}>"))?;
            expect(&mut reader, b'2')?;
        }
        say(&mut writer, "DATA")?;
        expect(&mut reader, b'3')?;
        writer
            .write_all(self.message(ping).as_bytes())
            .and_then(|()| writer.write_all(b"\r\n.\r\n"))
            .map_err(|e| failed(format!("smtp write: {e}")))?;
        expect(&mut reader, b'2')?;
        say(&mut writer, "QUIT")?;
        Ok(())
    }
}

/// Standard base64, for `AUTH PLAIN`. Twenty lines rather than a dependency in the binary an
/// auditor reads.
fn base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let octets = text.as_bytes();
    let mut out = String::with_capacity(octets.len().div_ceil(3) * 4);
    for chunk in octets.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let packed = u32::from(buffer[0]) << 16 | u32::from(buffer[1]) << 8 | u32::from(buffer[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - index * 6;
                out.push(ALPHABET[((packed >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The adapter: every configured channel, tried in turn.
#[derive(Debug, Default)]
pub struct Notifier {
    channels: Vec<Box<dyn Channel>>,
}

/// What one channel did with one ping.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// Which channel.
    pub channel: String,
    /// Whether it got there.
    pub delivered: bool,
    /// The failure, when it did not. Never contains a credential.
    pub detail: Option<String>,
}

impl Notifier {
    /// Build an adapter over a fixed set of channels.
    #[must_use]
    pub fn new(channels: Vec<Box<dyn Channel>>) -> Self {
        Self { channels }
    }

    /// How many channels this deployment configured. Zero is a fact the console states rather than
    /// a state it renders as silence.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Ping every channel and report what each one did.
    ///
    /// Never returns an error: a park is already recorded when this runs, and a channel outage is
    /// something to record, not something that can undo a park.
    #[must_use]
    pub fn notify(&self, ping: &Ping) -> Vec<Attempt> {
        self.channels
            .iter()
            .map(|channel| match channel.deliver(ping) {
                Ok(()) => Attempt {
                    channel: channel.name().to_owned(),
                    delivered: true,
                    detail: None,
                },
                Err(e) => {
                    tracing::error!(
                        channel = channel.name(),
                        request_hash = ping.request_hash,
                        error = %e.detail(),
                        "an approver ping could not be delivered; the park stands and is queued"
                    );
                    Attempt {
                        channel: channel.name().to_owned(),
                        delivered: false,
                        detail: Some(e.detail().to_owned()),
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Default)]
    struct Capturing {
        seen: Mutex<Vec<String>>,
        fails: bool,
    }

    impl Channel for Capturing {
        fn name(&self) -> &str {
            "capturing"
        }

        fn deliver(&self, ping: &Ping) -> Result<()> {
            self.seen
                .lock()
                .expect("the capture lock")
                .push(ping.request_hash.clone());
            if self.fails {
                return Err(failed("the channel is down"));
            }
            Ok(())
        }
    }

    fn ping() -> Ping {
        Ping {
            request_hash: "ab".repeat(32),
            subject: "agent:claude-code/ivan-mbp".to_owned(),
            component: "gateway".to_owned(),
            action: "github.create_issue".to_owned(),
            target: "repo:acme/backend".to_owned(),
            classification: "consequential".to_owned(),
            not_after: "2026-07-26T10:00:00.000Z".to_owned(),
            console_url: Some("https://stozher.acme.internal".to_owned()),
        }
    }

    #[test]
    fn a_channel_that_fails_is_reported_rather_than_swallowed() {
        let notifier = Notifier::new(vec![
            Box::new(Capturing::default()),
            Box::new(Capturing {
                seen: Mutex::default(),
                fails: true,
            }),
        ]);
        let attempts = notifier.notify(&ping());
        assert_eq!(attempts.len(), 2);
        assert!(attempts[0].delivered);
        assert!(!attempts[1].delivered);
        assert_eq!(attempts[1].detail.as_deref(), Some("the channel is down"));
    }

    #[test]
    fn the_ping_carries_no_arguments_and_no_key_material() {
        let rendered = format!("{}{}", ping().body(), ping().to_json());
        for forbidden in ["args", "ed25519:", "password", "token"] {
            assert!(
                !rendered.contains(forbidden),
                "the ping leaked {forbidden:?}: {rendered}"
            );
        }
    }

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        assert_eq!(base64(""), "");
        assert_eq!(base64("f"), "Zg==");
        assert_eq!(base64("fo"), "Zm8=");
        assert_eq!(base64("foo"), "Zm9v");
        assert_eq!(base64("foob"), "Zm9vYg==");
        assert_eq!(base64("fooba"), "Zm9vYmE=");
        assert_eq!(base64("foobar"), "Zm9vYmFy");
    }

    #[test]
    fn smtp_refuses_to_authenticate_to_a_relay_it_cannot_reach_privately() {
        let channel = Smtp::new(
            "smtp.example.com".to_owned(),
            25,
            "stozher@acme.internal".to_owned(),
            vec!["ivan@acme.internal".to_owned()],
            Some("stozher".to_owned()),
            Some("STOZHER_TEST_SMTP_PASSWORD".to_owned()),
        );
        let error = channel.deliver(&ping()).unwrap_err();
        assert_eq!(error.code(), NOTIFY_FAILED);
        assert!(error.detail().contains("loopback"), "{}", error.detail());
    }
}

//! Talking to the component under test — `spec/08 §4.8`.
//!
//! # Why the component drives itself
//!
//! §08 §4.4 requires eight refusals of envelopes **the component signed**. The harness cannot build
//! seven of them, and the reason is the point of the product rather than an inconvenience: it would
//! need the component's signing key, and a harness holding that key could emit envelopes
//! indistinguishable from the component's own. Certification would then be performed by something
//! able to forge the thing it certifies.
//!
//! So the component attempts them itself, through the action its manifest already declares at
//! `conformance.self-test` — a MUST member since §08 §1.1, and one [`crate::manifest`] has always
//! required. Implementing this protocol adds nothing to the component contract; it makes a contract
//! that already existed reachable. ADR-0016 records the decision and the alternative it refused.
//!
//! # Why a subprocess and a line of JSON
//!
//! §08 §4 requires a run to be deterministic and re-runnable "with no component-side state". A fresh
//! process per run makes that structural: there is no session to resume, no file to leave behind and
//! nothing to clear between runs. Line-delimited JSON over stdin/stdout is the smallest transport
//! that carries the protocol, needs no port, no certificate and no service to be already running,
//! and can be driven from a shell by an operator who wants to see what the harness sees.
//!
//! # Why every request is timed
//!
//! A component that never answers would hang the harness rather than fail it, and a hung
//! certification run reports nothing at all — the worst of the three outcomes, because an operator
//! waiting on a spinner has not learned that the component is broken. Silence is therefore a failure
//! with a deadline attached.

use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use stozher_core::error::{Error, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use crate::codes;

/// How long one request may take before the component is treated as unresponsive.
///
/// Generous, because a `vectors` request asks a component to compute a few hundred digests and a
/// cold interpreter may take a moment to start. It is a deadlock detector, not a performance budget.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Something the harness can ask the component under test to do.
///
/// One method, because the protocol is one request shape. The trait exists so the check groups can
/// be driven by a test double as well as by a real component: a group that could only run against a
/// live subprocess could not be tested against a *non-conformant* one, and a harness never exercised
/// against a component built to fail is a harness nobody has evidence works.
pub trait ComponentDriver {
    /// Send one request and read the component's answer.
    ///
    /// # Errors
    ///
    /// [`codes::CONFORMANCE_DRIVER_FAILED`] when the component could not be reached, did not answer
    /// in time, or answered something that is not one JSON object on one line. Each of those is a
    /// conformance failure rather than a harness bug, and the caller records it as one — but they
    /// are reported here as errors so that a group cannot mistake "no answer" for an empty answer.
    fn ask(&self, request: Value) -> impl Future<Output = Result<Value>> + Send;
}

/// A component driven as a subprocess over line-delimited JSON (§08 §4.8).
#[derive(Debug)]
pub struct StdioDriver {
    child: Mutex<Session>,
    /// What was spawned, so a failure names the component rather than "the driver".
    description: String,
}

#[derive(Debug)]
struct Session {
    process: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl StdioDriver {
    /// Start the component's self-test.
    ///
    /// `program` and `arguments` are the command an operator would type. Nothing about the component
    /// is assumed beyond its willingness to speak §08 §4.8 on stdin and stdout, which is what lets a
    /// component written in any language be certified by this harness.
    ///
    /// # Errors
    ///
    /// [`codes::CONFORMANCE_DRIVER_FAILED`] if the process cannot be started. That is an operator
    /// error — a wrong path, a missing interpreter — and it happens before any group runs, so it is
    /// reported to the operator rather than recorded against the component.
    pub fn spawn(program: &str, arguments: &[String]) -> Result<Self> {
        let mut process = tokio::process::Command::new(program)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr is left attached to the harness's own, so a component's diagnostics reach the
            // operator running the certification. §08 §4.8 forbids parsing it, and nothing here does.
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                Error::new(
                    codes::CONFORMANCE_DRIVER_FAILED,
                    format!("could not start {program}: {e}"),
                )
            })?;
        // Both pipes were requested above, so their absence would be a bug in this function rather
        // than a condition the component can cause.
        let stdin = process.stdin.take().expect("stdin was piped");
        let stdout = process.stdout.take().expect("stdout was piped");
        Ok(Self {
            child: Mutex::new(Session {
                process,
                stdin,
                stdout: BufReader::new(stdout),
            }),
            description: if arguments.is_empty() {
                program.to_owned()
            } else {
                format!("{program} {}", arguments.join(" "))
            },
        })
    }

    /// Stop the component.
    ///
    /// Called when the run finishes. `kill_on_drop` covers the panicking path; this covers the
    /// ordinary one, where leaving a child process behind after a certification run would be a
    /// harness that litters the operator's machine once per component they evaluate.
    pub async fn shutdown(&self) {
        let mut session = self.child.lock().await;
        // The component is expected to exit when its stdin closes. Killing outright is the
        // fallback, and it is safe: a self-test process holds nothing worth a graceful exit.
        let _ = session.process.start_kill();
    }
}

impl ComponentDriver for StdioDriver {
    async fn ask(&self, request: Value) -> Result<Value> {
        let mut session = self.child.lock().await;
        let failed = |detail: String| Error::new(codes::CONFORMANCE_DRIVER_FAILED, detail);

        let mut line = serde_json::to_string(&request)
            .map_err(|e| failed(format!("the request would not serialize: {e}")))?;
        line.push('\n');

        let exchange = async {
            session
                .stdin
                .write_all(line.as_bytes())
                .await
                .map_err(|e| failed(format!("writing to {}: {e}", self.description)))?;
            session
                .stdin
                .flush()
                .await
                .map_err(|e| failed(format!("flushing to {}: {e}", self.description)))?;
            let mut answer = String::new();
            let read = session
                .stdout
                .read_line(&mut answer)
                .await
                .map_err(|e| failed(format!("reading from {}: {e}", self.description)))?;
            if read == 0 {
                // The component closed its output. Distinguished from a malformed answer because it
                // usually means the process died, and an operator reading "it exited" goes looking
                // in a different place than one reading "it answered nonsense".
                return Err(failed(format!(
                    "{} closed its output without answering",
                    self.description
                )));
            }
            serde_json::from_str::<Value>(answer.trim()).map_err(|e| {
                failed(format!(
                    "{} answered something that is not one JSON object: {e}",
                    self.description
                ))
            })
        };

        match tokio::time::timeout(REQUEST_TIMEOUT, exchange).await {
            Ok(answer) => answer,
            Err(_) => Err(failed(format!(
                "{} did not answer within {} seconds",
                self.description,
                REQUEST_TIMEOUT.as_secs()
            ))),
        }
    }
}

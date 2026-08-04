//! Ingest — the one way anything enters the store.
//!
//! # Order of operations
//!
//! §02 §9.2 fixes it, and the order is the security property:
//!
//! ```text
//! parse strictly → verify signature over the received bytes → validate schema
//!                → validate mandate → validate authorization → append
//! ```
//!
//! "A schema check that runs before signature verification lets an attacker probe schemas with
//! unsigned objects; a schema check that runs after append lets junk into the chain."
//!
//! Policy evaluation is then §05 §3's order and only that order: classification → prohibition →
//! mandate → gate rule → budget.
//!
//! # There is no second way in
//!
//! [`Ingest::submit`] is the only public function in this crate that can cause an envelope to be
//! appended. [`crate::store::Store::append`] is crate-private, so no HTTP handler, no maintenance
//! task and no test outside this crate can reach it. There is no parameter, header, environment
//! variable, trusted-component list or state binding anywhere in this module that turns a required
//! approval into an optional one: `requires_gate` is computed from the policy document and the
//! envelope's own reported outcome, and the only value that satisfies it is a verified signature
//! (§06 §2). The negative case is tested by attempting it — see `tests/no_ambient_approval.rs`.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{Map, Value};
use stozher_core::error::{Error, Result};
use stozher_core::gate::Approver;
use stozher_core::mandate::{
    GrantParams, MandateRequest, VerifyParams, verify_grant, verify_mandate_chain,
    verify_revocation,
};
use stozher_core::signed::{KeyId, verify_signed_object};
use stozher_core::{chain, crypto, envelope, gate, jcs, payload, signed};

use crate::clock::{self, SharedClock};
use crate::codes;
use crate::keys::SigningKey;
use crate::manifest::Manifest;
use crate::policy::{ClassifyInput, Decision, Policy, class_weight};
use crate::store::{
    AppendPlan, Appended, CheckpointRow, GateDecisionRow, GateUse, PayloadRow, Projections,
    RejectionInput, RejectionRecord, STREAM_KIND_EFFECT, STREAM_KIND_SIGNAL, Store, StreamResume,
};

/// Envelope kinds that carry authority and therefore a mandate (§02 §2).
const EFFECT_KINDS: [&str; 3] = ["effect", "policy-change", "aggregate"];

/// The kernel actions whose authorization MUST be signed by an enrolled human root, whatever the
/// org's `gate-rules` say: policy publication (§05 §5.2), component registration (§08 §3.1) and
/// changes to the root set itself (§03 §6). Policy cannot lower the bar on the mechanism that
/// enforces policy.
///
/// `kernel.conformance_run` is here for the same reason rather than a different one. §08 §3.3 makes
/// registration conditional on a green run, and the kernel verifies that condition by finding an
/// applied envelope claiming one — so the root who approves the *registration* is approving on the
/// strength of a claim whose only property was that it existed. Whoever could emit the run decided
/// what the root was agreeing to. The claim now costs what the thing it unlocks costs.
/// `kernel.resume_stream` is here because it is the exit from a wedge (§04 §7.2), and an exit
/// without a signature is not a gate. It is also the only act in this system that changes what
/// [`crate::store::Store::append`] will accept at a chain position, which puts it in the same class
/// as publishing policy: an organization may classify it higher, never lower.
const ROOT_APPROVED_ACTIONS: [&str; 6] = [
    "kernel.publish_policy",
    "kernel.register_component",
    "kernel.enroll_root",
    "kernel.retire_root",
    "kernel.conformance_run",
    "kernel.resume_stream",
];

/// The result of a submission.
#[derive(Debug)]
pub enum Outcome {
    /// The envelope is in the chain, or was already.
    Accepted(Appended),
    /// The envelope was refused, and the refusal is itself a record.
    Rejected {
        /// The normative reason code.
        reason: String,
        /// Human-readable detail. Not contractual.
        detail: String,
        /// The chained rejection record, absent only if recording it also failed.
        record: Option<RejectionRecord>,
    },
    /// The kernel could not answer. Not a rejection, and deliberately not recorded as one.
    Unavailable(String),
}

/// Deployment facts ingest needs that are not in the policy document.
#[derive(Debug, Clone)]
pub struct IngestConfig {
    /// The organization's policy key at SLIP-0010 role `4'` (§01 §6).
    pub policy_key: KeyId,
    /// How far into the future an `emitted-at` may be before it is refused (§09 §5: `PT5M`).
    pub max_future_skew_seconds: i64,
    /// The kernel's own stream, which carries root enrollment, policy publication and gate
    /// decisions (§04 §1). The two genesis envelopes must land here, at `seq` 0 and 1.
    pub kernel_core_stream: String,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            // A deployment must configure this; the placeholder is a key that cannot verify
            // anything, so an unconfigured kernel refuses every policy rather than accepting any.
            policy_key: KeyId::parse(&format!("ed25519:{}", "0".repeat(64)))
                .expect("the all-zero key identifier is well formed"),
            max_future_skew_seconds: 300,
            kernel_core_stream: "kernel:core".to_owned(),
        }
    }
}

/// The ingest pipeline.
#[derive(Debug, Clone)]
pub struct Ingest {
    store: Store,
    clock: SharedClock,
    kernel_key: Arc<SigningKey>,
    config: IngestConfig,
}

/// Everything derived while validating, before anything is written.
struct Validated {
    plan: AppendPlan,
    claims: Claims,
}

/// What a submitted object said about itself. Best effort by definition — if it is being rejected,
/// nothing in it is trusted; these are investigation aids on a rejection record, not facts.
#[derive(Debug, Clone, Default)]
struct Claims {
    stream: Option<String>,
    seq: Option<u64>,
    kind: Option<String>,
}

impl Ingest {
    /// Build the pipeline.
    #[must_use]
    pub fn new(
        store: Store,
        clock: SharedClock,
        kernel_key: Arc<SigningKey>,
        config: IngestConfig,
    ) -> Self {
        Self {
            store,
            clock,
            kernel_key,
            config,
        }
    }

    /// The store, for read-only query handlers.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The clock.
    #[must_use]
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// The kernel's signing key — used for rejection records and checkpoints.
    #[must_use]
    pub fn kernel_key(&self) -> &SigningKey {
        &self.kernel_key
    }

    /// The organization's policy key, which every policy document is verified against.
    #[must_use]
    pub fn policy_key(&self) -> &KeyId {
        &self.config.policy_key
    }

    /// Build, sign and submit an envelope the kernel itself emits, on its own core stream.
    ///
    /// The kernel signs an envelope in exactly the situations where **somebody else signed the
    /// object**: a gate decision (§06 §1.3), a revocation (§03 §7). Those objects are produced
    /// offline, on a machine that holds a seed and does not hold the chain, so their signer cannot
    /// cover `stream`, `seq` and `prev-hash` — values known only at the moment of append. The
    /// kernel's signature attests receipt and chain position and no authority whatever; the
    /// authority is the nested object, and [`Self::validate`] re-verifies it independently of who
    /// wrapped it. A kernel-signed envelope around a forged object is refused by the same code path
    /// that would refuse it from anyone else.
    ///
    /// The core stream has several writers — genesis, root changes, policy publication, decisions,
    /// revocations — so the chain position is taken under contention and retried a bounded number of
    /// times. A retry re-signs, because `seq` and `prev-hash` are inside the signed bytes.
    ///
    /// # Errors
    ///
    /// The `(reason-code, detail)` of a refusal, or [`codes::STORE_UNAVAILABLE`] when every attempt
    /// lost the race. Reporting the last chain code instead would tell the caller their object was
    /// permanently rejected, when in fact nothing was recorded and retrying is exactly right.
    pub async fn append_as_kernel(
        &self,
        kind: &str,
        members: Map<String, Value>,
        what: &str,
    ) -> std::result::Result<String, (String, String)> {
        const ATTEMPTS: usize = 8;
        let unavailable = |e: Error| (e.code().to_owned(), e.detail().to_owned());
        let stream = self.config.kernel_core_stream.clone();
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            // Eight immediate re-reads of the same head is eight writers colliding at the same
            // instant. A short escalating pause between them is what turns a burst into a queue.
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(2 << attempt.min(6))).await;
            }
            let head = self.store.stream_head(&stream).await.map_err(unavailable)?;
            let (seq, prev) = match head {
                Some((head_seq, head_id)) => (head_seq + 1, Some(head_id)),
                None => (0, None),
            };
            let key = self.kernel_key();
            let mut body = serde_json::json!({
                "v": stozher_core::VERSION,
                "kind": kind,
                "emitted-at": self.clock.now(),
                "stream": stream,
                "seq": seq,
                "prev-hash": prev,
                "identity": {
                    "subject": "agent:kernel",
                    "key": key.id().as_str(),
                    "component": "kernel"
                }
            });
            body.as_object_mut()
                .expect("the literal above is a JSON object")
                .extend(members.clone());
            let envelope = key.sign(&body).map_err(unavailable)?;
            let request = serde_json::json!({ "envelope": envelope, "payloads": [] });
            let raw = jcs::canonicalize(&request).map_err(unavailable)?;
            match self.submit(raw.as_bytes(), Some("agent:kernel")).await {
                Outcome::Accepted(appended) => return Ok(appended.id),
                Outcome::Rejected { reason, detail, .. }
                    if reason == "chain-seq-duplicate" || reason == "chain-prev-hash-mismatch" =>
                {
                    last = Some((reason, detail));
                }
                Outcome::Rejected { reason, detail, .. } => return Err((reason, detail)),
                Outcome::Unavailable(detail) => {
                    return Err((codes::STORE_UNAVAILABLE.to_owned(), detail));
                }
            }
        }
        let detail = last.map_or_else(
            || format!("the kernel's core stream is too contended to record {what}"),
            |(code, detail)| {
                format!(
                    "the kernel's core stream is too contended to record {what}: \
                     {ATTEMPTS} attempts, last {code} ({detail})"
                )
            },
        );
        Err((codes::STORE_UNAVAILABLE.to_owned(), detail))
    }

    /// Submit an ingest request: `{ "envelope": …, "payloads": [ … ] }`.
    ///
    /// A refusal is recorded in the kernel's rejection stream before this returns, with the reason
    /// code, the hash of the rejected bytes, the submitting subject and the timestamp (§04 §7).
    /// Infrastructure failures are not recorded: a rejection means the object was invalid, and the
    /// kernel's own outages are not emitter misbehaviour.
    pub async fn submit(&self, raw: &[u8], submitted_by: Option<&str>) -> Outcome {
        let received_at = self.clock.now();
        match self.validate(raw, &received_at).await {
            Ok(Either::Idempotent(appended)) => Outcome::Accepted(appended),
            Ok(Either::Fresh(validated)) => match self.store.append(&validated.plan).await {
                Ok(appended) => Outcome::Accepted(appended),
                Err(e) if e.code() == codes::STORE_UNAVAILABLE => {
                    Outcome::Unavailable(e.detail().to_owned())
                }
                Err(e) => {
                    self.reject(raw, &e, submitted_by, &received_at, &validated.claims)
                        .await
                }
            },
            Err(e) if e.code() == codes::STORE_UNAVAILABLE => {
                Outcome::Unavailable(e.detail().to_owned())
            }
            Err(e) => {
                self.reject(raw, &e, submitted_by, &received_at, &claims(raw))
                    .await
            }
        }
    }

    async fn reject(
        &self,
        raw: &[u8],
        error: &Error,
        submitted_by: Option<&str>,
        received_at: &str,
        claims: &Claims,
    ) -> Outcome {
        let input = RejectionInput {
            reason: error.code().to_owned(),
            detail: truncate(error.detail(), 1024),
            object_hash: rejected_bytes_hash(raw),
            submitted_by: submitted_by.map(str::to_owned),
            received_at: received_at.to_owned(),
            claimed_stream: claims.stream.clone(),
            claimed_seq: claims.seq,
            claimed_kind: claims.kind.clone(),
        };
        let record = self
            .store
            .record_rejection(&self.kernel_key, &input)
            .await
            .inspect_err(|e| {
                // If the rejection cannot be recorded the refusal still stands — the envelope is
                // not in the chain — but the audit has lost a record, which is worth saying loudly.
                tracing::error!(
                    reason = %input.reason,
                    error = %e,
                    "a rejection could not be recorded"
                );
            })
            .ok();
        Outcome::Rejected {
            reason: error.code().to_owned(),
            detail: error.detail().to_owned(),
            record,
        }
    }

    async fn validate(&self, raw: &[u8], received_at: &str) -> Result<Either> {
        // (1) Parse strictly. `jcs::parse` refuses duplicate member names, lone surrogates and
        // numeric literals with no canonical form, so a malformed object never reaches a signature
        // check that might otherwise be fed ambiguous bytes.
        let text = std::str::from_utf8(raw)
            .map_err(|e| Error::new("jcs-malformed-json", format!("body is not UTF-8: {e}")))?;
        let request = jcs::parse(text)?;
        let request_map = request.as_object().ok_or_else(|| {
            Error::new(
                "schema-type-mismatch",
                "an ingest request must be an object",
            )
        })?;
        for key in request_map.keys() {
            if !["envelope", "payloads"].contains(&key.as_str()) {
                return Err(Error::new("schema-unknown-member", key.clone()));
            }
        }
        let env = request_map
            .get("envelope")
            .ok_or_else(|| Error::new("schema-missing-member", "envelope"))?;
        let payloads: Vec<Value> = match request_map.get("payloads") {
            None => Vec::new(),
            Some(Value::Array(list)) => list.clone(),
            Some(_) => {
                return Err(Error::new(
                    "schema-type-mismatch",
                    "payloads must be an array",
                ));
            }
        };

        let id = signed::object_id(env)?;
        let canonical_json = jcs::canonicalize(env)?;

        // Idempotency by `id()` comes before the replay check so that re-submitting a byte-identical
        // envelope — a retry after a lost response — succeeds instead of being read as an approval
        // being used twice (§04 §3, §06 §3).
        if let Some(existing) = self.store.envelope_by_id(&id).await? {
            return Ok(Either::Idempotent(Appended {
                id,
                stream: existing.stream,
                seq: existing.seq,
                idempotent: true,
            }));
        }

        // (2) Signature over the bytes as received, before any schema opinion is formed.
        let subject_key = verify_signed_object(env)?;

        // (3) Schema.
        envelope::validate(env)?;

        let kind = env["kind"].as_str().unwrap_or_default().to_owned();
        let stream = env["stream"].as_str().unwrap_or_default().to_owned();
        let seq = env["seq"].as_u64().unwrap_or_default();
        let emitted_at = env["emitted-at"].as_str().unwrap_or_default().to_owned();
        let component = env["identity"]["component"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let subject = env["identity"]["subject"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        // (4) Freshness. An emitter controls its own `emitted-at` and mandate validity is evaluated
        // at that instant, so a compromised emitter could otherwise backdate an effect into a window
        // when a mandate was valid. The bound makes the drift visible rather than unbounded (§09 §5).
        let horizon = clock::shift(received_at, self.config.max_future_skew_seconds)?;
        if emitted_at > horizon {
            return Err(Error::new(
                "envelope-emitted-in-future",
                format!("emitted-at {emitted_at} is beyond the accepted horizon {horizon}"),
            ));
        }

        // (5) Payload binding. Verified before storage so the payload store is reachable only
        // through an envelope that commits to what it holds (§04 §5.2).
        let ingest_ok = payload::verify_ingest(env, &payloads)?;

        // (6) Policy. A kernel with no published policy enforces nothing and therefore accepts
        // nothing: failing closed here means refusing, not guessing (§05 §1). The sole exception is
        // the ceremony's own two envelopes — see `validate_genesis`.
        let policy = match self.store.current_policy().await? {
            Some(document) => Some(Policy::parse(&document, &self.config.policy_key)?),
            None => None,
        };

        let roots: Vec<KeyId> = self
            .store
            .roots_at(&emitted_at)
            .await?
            .into_iter()
            .map(|(key, _)| key)
            .collect();

        let mut plan = AppendPlan {
            envelope: env.clone(),
            id: id.clone(),
            canonical_json,
            stream_kind: if kind == "signal" {
                STREAM_KIND_SIGNAL
            } else {
                STREAM_KIND_EFFECT
            },
            received_at: received_at.to_owned(),
            human_root: None,
            effective_class: None,
            policy_violation: None,
            payloads: Vec::new(),
            gate_use: None,
            projections: Projections::default(),
            spend: None,
        };

        // (7)-(11) Kind-specific validation, in §05 §3's order for the kinds that carry authority.
        let Some(policy) = policy else {
            self.validate_genesis(env, &roots, &subject_key, &mut plan, &payloads)
                .await?;
            return Ok(Either::Fresh(Box::new(Validated {
                claims: Claims {
                    stream: Some(stream),
                    seq: Some(seq),
                    kind: Some(kind),
                },
                plan,
            })));
        };
        if EFFECT_KINDS.contains(&kind.as_str()) {
            self.validate_effect_kind(env, &policy, &roots, &subject_key, &mut plan, &payloads)
                .await?;
        } else {
            match kind.as_str() {
                "cognition" => {
                    // A cognition envelope has no `component`, `action` or `classification`, so
                    // three of §03 §4.2's four dimensions cannot be matched — but it does carry
                    // `resource` (§02 §6), and that one is enforced. The scope check used to be
                    // skipped whole because of the three that are missing, which meant a mandate
                    // could not bound what an agent spends cognition on at all: `resources`
                    // constrained every effect and no cognition. §03 §5 now says so.
                    // `kind:name`, the same spelling `execution.target` uses for every other record
                    // (`mcp:notes`, `repo:acme/backend`), so one `resources` pattern in a scope
                    // means the same thing wherever it is written. §03 §5 states the mapping.
                    let (Some(kind), Some(name)) = (
                        env.pointer("/resource/kind").and_then(Value::as_str),
                        env.pointer("/resource/name").and_then(Value::as_str),
                    ) else {
                        return Err(Error::new(
                            "schema-missing-member",
                            "resource.kind and resource.name are required to check scope",
                        ));
                    };
                    let resource = format!("{kind}:{name}");
                    let chain_ok = self
                        .walk_mandate_for_resource(
                            env,
                            &roots,
                            &subject_key,
                            &emitted_at,
                            &policy,
                            &resource,
                        )
                        .await?;
                    plan.human_root = Some(chain_ok);
                    // Cognition is where money is spent, so this is the path a monetary cap is
                    // actually reached through (§02 §6, §03 §4.3).
                    self.accrue_budget(env, &mut plan).await?;
                }
                "signal" => {
                    // Signal streams are separate from effect streams so a flood of inbound traffic
                    // cannot advance an effect stream's `seq` (§07 §2.5). The signature attests
                    // receipt by this component and nothing about the content's truth (§07 §2.2).
                    self.collect_payloads(env, &payloads, &policy, None, &mut plan)?;
                }
                "mandate" => {
                    self.validate_mandate_grant(env, &policy, &roots, &mut plan)
                        .await?
                }
                "revocation" => self.validate_revocation(env, &roots, &mut plan).await?,
                "gate-decision" => {
                    self.validate_gate_decision(env, &roots, &policy, &emitted_at, &mut plan)
                        .await?
                }
                "checkpoint" => self.validate_checkpoint(env, &mut plan).await?,
                other => {
                    return Err(Error::new(
                        "envelope-unknown-kind",
                        format!("kind {other:?} has no ingest rule"),
                    ));
                }
            }
        }

        // An `authorization` that is *present* is always fully verified, even when policy did not
        // demand one: an envelope must not be able to carry an unverified authorization-shaped
        // object that a later reader might trust (§06 §2, closing note).
        if plan.gate_use.is_none()
            && env.get("authorization").is_some()
            && !EFFECT_KINDS.contains(&kind.as_str())
        {
            return Err(Error::new(
                "schema-unknown-member",
                format!("a {kind} envelope must not carry authorization"),
            ));
        }

        let _ = (ingest_ok, component, subject);
        Ok(Either::Fresh(Box::new(Validated {
            claims: Claims {
                stream: Some(stream),
                seq: Some(seq),
                kind: Some(kind),
            },
            plan,
        })))
    }

    /// The ceremony, and nothing else, before a policy exists.
    ///
    /// §05 §5.2 states the carve-out and its bounds: "there is no bootstrap exception except the
    /// ceremony's first policy, which MUST be `seq` 1 of `kernel:core`, signed by the first root, and
    /// MUST be recorded as such." Taken literally that is circular — the first `policy-change` is a
    /// gated effect, a gated effect needs a mandate, and both need a policy in force to be evaluated
    /// against. This resolves the circle with **exactly two** envelopes, both fully validated:
    ///
    /// | `seq` | kind | what it is |
    /// |---|---|---|
    /// | 0 | `mandate` | an enrolled root grants an *interactive* mandate to the bootstrap subject |
    /// | 1 | `policy-change` | that subject publishes the first policy, approved by the root |
    ///
    /// Why this is not a bypass:
    ///
    /// * it accepts two `kind` values and refuses every other envelope with `policy-not-published`,
    ///   so no effect can be applied before a policy governs it;
    /// * both positions are pinned, so it can fire at most twice per deployment, ever, and never
    ///   again once `seq` 1 of the core stream is occupied;
    /// * the mandate must be `interactive` — the kind that "dies with the session" — so the ceremony
    ///   cannot mint standing autonomy that outlives it, and the standing-lifetime ceiling it could
    ///   not yet be checked against never applies;
    /// * the policy change is verified through the *same* §06 §2 algorithm as every other gated
    ///   effect, with `requires_gate` forced true and the approver set forced to the enrolled roots.
    ///   The first policy is approved by a named human's signature over its exact document hash, or
    ///   it does not exist.
    async fn validate_genesis(
        &self,
        env: &Value,
        roots: &[KeyId],
        subject_key: &KeyId,
        plan: &mut AppendPlan,
        payloads: &[Value],
    ) -> Result<()> {
        let kind = env["kind"].as_str().unwrap_or_default();
        let on_core = env["stream"].as_str() == Some(self.config.kernel_core_stream.as_str());
        let seq = env["seq"].as_u64().unwrap_or(u64::MAX);
        let refuse = || {
            Error::new(
                "policy-not-published",
                format!(
                    "no policy version is in force; before one exists this kernel accepts only \
                     an interactive root mandate at ({}, 0) and the first policy change at ({}, 1)",
                    self.config.kernel_core_stream, self.config.kernel_core_stream
                ),
            )
        };
        if !on_core {
            return Err(refuse());
        }
        match (kind, seq) {
            ("mandate", 0) => {
                let mandate = env
                    .get("mandate")
                    .ok_or_else(|| Error::new("schema-missing-member", "mandate"))?;
                if mandate["mandate-kind"].as_str() != Some("interactive") {
                    return Err(refuse());
                }
                verify_grant(
                    mandate,
                    None,
                    &GrantParams {
                        roots,
                        // Only `standing` has a lifetime ceiling, and this branch permits only
                        // `interactive`; there is nothing to compare against and nothing skipped.
                        max_standing_not_after: None,
                    },
                )?;
                plan.projections.mandate = Some((signed::object_id(mandate)?, mandate.clone()));
                Ok(())
            }
            ("policy-change", 1) => {
                let emitted_at = env["emitted-at"].as_str().unwrap_or_default();
                let declared_class = env["classification"].as_str().unwrap_or_default();
                if declared_class != "consequential" {
                    // §02 §2 and §05 §5.2: a policy change is `consequential`, always.
                    return Err(Error::new(
                        "policy-component-override-attempt",
                        format!("a policy change is consequential, not {declared_class}"),
                    ));
                }
                self.validate_policy_change(env, payloads, plan).await?;
                let request = MandateRequest {
                    component: env["identity"]["component"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    action: env["execution"]["action"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    classification: declared_class.to_owned(),
                    resource: env["execution"]["target"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                };
                plan.human_root = Some(
                    self.walk_mandate_with_depth(env, roots, subject_key, emitted_at, 3, &request)
                        .await?,
                );
                plan.effective_class = Some(declared_class.to_owned());
                let root_approvers = self.root_approvers(emitted_at).await?;
                let ok = gate::verify_authorization(env, true, &root_approvers, &HashSet::new())?
                    .ok_or_else(|| {
                    Error::new(
                        "gate-authorization-missing",
                        "the first policy must carry a root's approval signature",
                    )
                })?;
                plan.gate_use = Some(GateUse {
                    request_hash: ok.request_hash,
                    decided_by: ok.decided_by.as_str().to_owned(),
                    single_use: ok.single_use,
                    not_after: env["authorization"]["decision"]["not-after"]
                        .as_str()
                        .unwrap_or(emitted_at)
                        .to_owned(),
                });
                Ok(())
            }
            _ => Err(refuse()),
        }
    }

    async fn validate_effect_kind(
        &self,
        env: &Value,
        policy: &Policy,
        roots: &[KeyId],
        subject_key: &KeyId,
        plan: &mut AppendPlan,
        payloads: &[Value],
    ) -> Result<()> {
        let kind = env["kind"].as_str().unwrap_or_default();
        let emitted_at = env["emitted-at"].as_str().unwrap_or_default();
        let component = env["identity"]["component"].as_str().unwrap_or_default();
        let subject = env["identity"]["subject"].as_str().unwrap_or_default();
        let declared_class = env["classification"].as_str().unwrap_or_default();

        // The requests this envelope must be authorized for. An `aggregate` folds many calls, so
        // every action in the window is checked, each at class `read`.
        let requests = self.effect_requests(env)?;
        let manifest = self.store.latest_manifest(component).await?;
        let manifest = manifest.as_ref().map(Manifest::parse).transpose()?;

        // §05 §3 step 1 — classification. The strongest class over the folded window wins, so an
        // aggregate cannot dilute a reclassified action by burying it among ordinary reads.
        let mut effective = String::new();
        for (action, resource) in &requests {
            let class = policy.classify(&ClassifyInput {
                subject,
                action,
                resource,
                manifest_class: manifest.as_ref().and_then(|m| m.proposed_class(action)),
            });
            if effective.is_empty() || class_weight(&class) > class_weight(&effective) {
                effective = class;
            }
        }
        // A component MUST NOT apply a class weaker than the effective policy's (§08 §1.2). The
        // manifest is a proposal; the classification is the organization's.
        if class_weight(declared_class) < class_weight(&effective) {
            return Err(Error::new(
                "policy-component-override-attempt",
                format!(
                    "envelope claims {declared_class}, policy computes {effective} for {}",
                    requests
                        .iter()
                        .map(|(a, _)| a.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        plan.effective_class = Some(effective.clone());

        let outcome = env["execution"]["outcome"].as_str().unwrap_or("applied");
        // `aggregate` carries no `execution`; a folded window of reads is by definition applied.
        let applied = matches!(outcome, "applied" | "failed") || kind == "aggregate";

        // §05 §3 step 2 — prohibition. Nothing permits a `prohibited` action: not a mandate, not an
        // approval, not a gate decision. An envelope reporting one as *applied* is a component
        // confessing a violation. It is appended and flagged rather than refused: refusing would
        // delete the only record that the violation happened, which is the opposite of an audit.
        if effective == "prohibited" && applied {
            plan.policy_violation = Some("prohibited-applied".to_owned());
        }

        // §05 §3 step 3 — mandate. Every request is checked against the *same* chain: `mandate-ref`
        // is one top-level member, so an aggregate cites one mandate for the whole window and every
        // request necessarily terminates at the same human root. What differs per request is only
        // the scope match (§03 §4.2), so the chain is fetched once and each request is matched
        // against it — an aggregate folding a thousand actions is one ancestry query, not a
        // thousand identical ones.
        let mandate_ref = env["mandate-ref"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "mandate-ref"))?;
        let max_depth = policy.max_delegation_depth();
        let mandates = self.store.mandate_ancestry(mandate_ref, max_depth).await?;
        let ids: Vec<String> = mandates.keys().cloned().collect();
        let revocations = self.store.revocations_targeting(&ids).await?;
        let params = VerifyParams {
            roots,
            revocations: &revocations,
            at: emitted_at,
            subject_key,
            max_delegation_depth: max_depth,
        };
        let mut human_root = None;
        for (action, resource) in &requests {
            let request = MandateRequest {
                component: component.to_owned(),
                action: action.clone(),
                classification: if kind == "aggregate" {
                    "read".to_owned()
                } else {
                    declared_class.to_owned()
                },
                resource: resource.clone(),
            };
            human_root =
                Some(verify_mandate_chain(&mandates, mandate_ref, &request, &params)?.human_root);
        }
        plan.human_root = human_root;

        // §05 §3 step 5 — budget. Shared with the cognition path below rather than written here:
        // `cost` lives on cognition envelopes (§02 §6), and a budget step that only ran for effects
        // would never once compare a monetary cap to anything.
        self.accrue_budget(env, plan).await?;

        // A triggered effect cites the standing rule that authorized it (§07 §4).
        self.validate_trigger(env).await?;

        if kind == "aggregate" {
            validate_aggregate_window(env, policy)?;
        }
        if kind == "policy-change" {
            self.validate_policy_change(env, payloads, plan).await?;
        }
        match env["execution"]["action"].as_str() {
            Some("kernel.register_component") => {
                self.validate_registration(env, payloads, plan).await?;
            }
            Some("kernel.enroll_root" | "kernel.retire_root") => {
                self.validate_root_change(env, payloads, roots, subject_key, plan)?;
            }
            Some("kernel.resume_stream") => {
                // The position it names must be one this store actually refused; that check needs
                // the transaction and lives in `write_projections`, so what is decided here is the
                // document's shape and its binding to the signature.
                plan.projections.stream_resume = Some(stream_resume(env, payloads)?);
            }
            _ => {}
        }
        self.validate_commitment(env, manifest.as_ref(), subject)
            .await?;

        // §05 §3 step 4 — the gate rule.
        let decision = policy.decision_for(&effective);
        let action = env["execution"]["action"].as_str().unwrap_or_default();
        let root_approved = ROOT_APPROVED_ACTIONS.contains(&action) || kind == "policy-change";
        let requires_gate = match &decision {
            // A gated action that was never applied — parked, denied, timed out — legitimately has
            // no approval to carry (§06 §6). Requiring one would make it impossible to record that
            // a human said no.
            Decision::Gate { .. } => applied,
            Decision::Allow => root_approved && applied,
            Decision::Deny => {
                if applied {
                    plan.policy_violation
                        .get_or_insert_with(|| "policy-denied-applied".to_owned());
                }
                root_approved && applied
            }
        };

        let approvers = if root_approved {
            // Policy cannot lower the bar on the mechanism that enforces policy: publishing a
            // policy version, registering a component and changing the root set are approved by an
            // enrolled human root, whatever `gate-rules` says (§05 §5.2, §08 §3.1, §03 §6).
            self.root_approvers(emitted_at).await?
        } else {
            match &decision {
                Decision::Gate { approvers } => {
                    self.approver_keys(approvers, emitted_at, action).await?
                }
                Decision::Allow | Decision::Deny => Vec::new(),
            }
        };

        // §06 §1.1 and §1.2 are shape rules — "All members are REQUIRED. Unknown members MUST be
        // rejected" — and until now they ran only on `POST /v1/gate/requests` and the console's
        // decide route. An `authorization` assembled by a component and carried straight here met
        // neither, so the closed member set, the nonce's entropy and both timestamp formats were
        // enforced only on the path an attacker has no reason to take. `envelope::validate` does not
        // help: its sub-object spec stops at `{request, decision}` and does not descend.
        if let Some(authorization) = env.get("authorization") {
            crate::gatequeue::validate_embedded(authorization)?;
        }

        let seen = match env["authorization"]["decision"]["request-hash"].as_str() {
            Some(hash) if self.store.gate_request_seen(hash).await? => {
                HashSet::from([hash.to_owned()])
            }
            _ => HashSet::new(),
        };

        // §06 §2 — all eleven steps, in the normative order, from the reference implementation.
        match gate::verify_authorization(env, requires_gate, &approvers, &seen) {
            Ok(Some(ok)) => {
                if !applied {
                    // An approval carried by an envelope that reports no effect is not consumed;
                    // marking it used would burn a signature the operator still needs.
                    plan.gate_use = None;
                } else {
                    plan.gate_use = Some(GateUse {
                        request_hash: ok.request_hash,
                        decided_by: ok.decided_by.as_str().to_owned(),
                        single_use: ok.single_use,
                        not_after: env["authorization"]["decision"]["not-after"]
                            .as_str()
                            .unwrap_or(emitted_at)
                            .to_owned(),
                    });
                }
            }
            Ok(None) => {}
            // A signed denial carried by an envelope that applied nothing is a record, not an
            // authorization: §06 §4.5 REQUIRES that envelope to exist, so ingest must accept it.
            // The pairing is what makes this safe — a denial can never accompany an applied effect,
            // because `applied` is exactly the condition under which this arm does not fire.
            Err(e) if e.code() == "gate-denied" && !applied => {}
            Err(e) => return Err(e),
        }

        self.collect_payloads(env, payloads, policy, Some(&effective), plan)?;
        Ok(())
    }

    /// The `(action, resource)` pairs an effect-kind envelope must be authorized for.
    fn effect_requests(&self, env: &Value) -> Result<Vec<(String, String)>> {
        if env["kind"].as_str() == Some("aggregate") {
            let by_action = env["counts"]["by-action"]
                .as_object()
                .ok_or_else(|| Error::new("schema-missing-member", "counts.by-action"))?;
            if by_action.is_empty() {
                return Err(Error::new(
                    "aggregate-count-mismatch",
                    "an aggregation record folds no actions",
                ));
            }
            // An aggregation record carries no resource (§02 §7), so the mandate is checked against
            // the "no target" sentinel of §02 §4. A mandate whose `resources` scope is narrower than
            // `["-"]` or `["*"]` therefore cannot cover aggregated reads — which is the conservative
            // reading, and is recorded as a specification gap rather than papered over.
            return Ok(by_action
                .keys()
                .map(|action| (action.clone(), "-".to_owned()))
                .collect());
        }
        let action = env["execution"]["action"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "execution.action"))?;
        let target = env["execution"]["target"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "execution.target"))?;
        Ok(vec![(action.to_owned(), target.to_owned())])
    }

    /// §03 §4.3 — accrue what this envelope consumed, and flag it if a cap in its chain has no room.
    ///
    /// **Flags and appends; never refuses.** The consumption has already happened, and refusing the
    /// envelope would delete the only record that it happened — the same reasoning `ingest` already
    /// follows for `prohibited-applied` and `policy-denied-applied`. `spec/03 §4.3` puts the
    /// *blocking* on the emitter ("outcome: blocked, envelope still emitted"); what arrives here
    /// past a cap is a component confessing that it acted anyway. `docs/product-completion-design.md`
    /// §4.2 proposed refusing outright, and ADR-0015 records why that was not followed.
    ///
    /// The charge reaches the citing mandate **and every ancestor**, because a budget caps "this
    /// mandate and everything delegated beneath it". Without the ancestry half a delegation chain
    /// would multiply an organisation's limit by its own depth.
    async fn accrue_budget(&self, env: &Value, plan: &mut AppendPlan) -> Result<()> {
        // Only what was actually consumed: `accrual_of` charges an applied effect and a cost-bearing
        // cognition, and nothing else. Charging a blocked or denied effect would turn a working gate
        // into a budget leak — an agent refused a thousand times would exhaust the cap having done
        // nothing at all.
        let adding = crate::budget::accrual_of(env);
        if adding.is_empty() {
            return Ok(());
        }
        let Some(mandate_ref) = env["mandate-ref"].as_str() else {
            return Ok(());
        };
        let line = self.store.mandate_line(mandate_ref).await?;
        for mandate_id in &line {
            let Some(mandate) = self.store.mandate(mandate_id).await? else {
                continue;
            };
            let Some(cap) = mandate.get("budget") else {
                continue;
            };
            let accrued = self.store.spend(mandate_id).await?;
            if !crate::budget::would_exceed(cap, &accrued, &adding).is_empty() {
                plan.policy_violation
                    .get_or_insert_with(|| codes::BUDGET_EXCEEDED_APPLIED.to_owned());
            }
        }
        plan.spend = Some(crate::store::SpendAccrual {
            mandates: line,
            amounts: adding,
        });
        Ok(())
    }

    /// The cognition path: every check of §03 §5, with scope matched on `resources` alone.
    async fn walk_mandate_for_resource(
        &self,
        env: &Value,
        roots: &[KeyId],
        subject_key: &KeyId,
        at: &str,
        policy: &Policy,
        resource: &str,
    ) -> Result<String> {
        let max_depth = policy.max_delegation_depth();
        let mandate_ref = env["mandate-ref"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "mandate-ref"))?;
        let mandates = self.store.mandate_ancestry(mandate_ref, max_depth).await?;
        let ids: Vec<String> = mandates.keys().cloned().collect();
        let revocations = self.store.revocations_targeting(&ids).await?;
        let params = VerifyParams {
            roots,
            revocations: &revocations,
            at,
            subject_key,
            max_delegation_depth: max_depth,
        };
        let ok = stozher_core::mandate::verify_mandate_chain_for_resource(
            &mandates,
            mandate_ref,
            resource,
            &params,
        )?;
        Ok(ok.human_root)
    }

    async fn walk_mandate_with_depth(
        &self,
        env: &Value,
        roots: &[KeyId],
        subject_key: &KeyId,
        at: &str,
        max_depth: u32,
        request: &MandateRequest,
    ) -> Result<String> {
        let mandate_ref = env["mandate-ref"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "mandate-ref"))?;
        let mandates = self.store.mandate_ancestry(mandate_ref, max_depth).await?;
        let ids: Vec<String> = mandates.keys().cloned().collect();
        let revocations = self.store.revocations_targeting(&ids).await?;
        let params = VerifyParams {
            roots,
            revocations: &revocations,
            at,
            subject_key,
            max_delegation_depth: max_depth,
        };
        // No unscoped branch. It existed for `cognition` alone, and §03 §5 now says how a
        // cognition envelope is scoped — on the one dimension it carries. Every record reaching
        // this function supplies a full request tuple; there is no path here that skips the check.
        let ok = verify_mandate_chain(&mandates, mandate_ref, request, &params)?;
        Ok(ok.human_root)
    }

    async fn validate_trigger(&self, env: &Value) -> Result<()> {
        let Some(trigger) = env.get("trigger") else {
            return Ok(());
        };
        // Resolution is this side's — it owns the store; the judgement is `stozher_core::trigger`'s,
        // so §07 §4 is one rule in one place and `spec/vectors/trigger.json` can state it as a
        // table. A lookup that finds nothing is `None`, which the rule reads as unresolved.
        let signal = match trigger["signal-ref"].as_str() {
            Some(reference) => match self.store.envelope_by_id(reference).await? {
                Some(record) => Some(record.envelope()?),
                None => None,
            },
            None => None,
        };
        let mandate = match trigger["standing-mandate-ref"].as_str() {
            Some(reference) => self.store.mandate(reference).await?,
            None => None,
        };
        stozher_core::trigger::check(env, mandate.as_ref(), signal.as_ref())
    }

    async fn validate_policy_change(
        &self,
        env: &Value,
        payloads: &[Value],
        plan: &mut AppendPlan,
    ) -> Result<()> {
        // §05 §5.3: the approval signature binds the exact bytes of the policy that took effect, so
        // the document has to be here and `args-hash` has to be its hash. Approving "a policy
        // change" in the abstract is not representable.
        let args_hash = env["execution"]["args-hash"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "execution.args-hash"))?;
        let document = payloads
            .iter()
            .find(|p| p["payload-hash"].as_str() == Some(args_hash))
            .map(|p| p["payload"].clone())
            .ok_or_else(|| {
                Error::new(
                    codes::POLICY_CHANGE_DOCUMENT_UNBOUND,
                    "the new policy document must be submitted alongside the change, \
                     and args-hash must be its object-hash",
                )
            })?;
        let computed = jcs::object_hash(&document)?;
        if computed != args_hash {
            return Err(Error::new(
                codes::POLICY_CHANGE_DOCUMENT_UNBOUND,
                format!("the submitted policy hashes to {computed}, args-hash is {args_hash}"),
            ));
        }
        let incoming = Policy::parse(&document, &self.config.policy_key)?;
        let expected_target = format!("policy:{}", incoming.version());
        if env["execution"]["target"].as_str() != Some(expected_target.as_str()) {
            return Err(Error::new(
                codes::POLICY_CHANGE_TARGET_MISMATCH,
                format!(
                    "execution.target is {:?}, expected {expected_target:?}",
                    env["execution"]["target"]
                ),
            ));
        }
        if self.store.policy_version_exists(incoming.version()).await? {
            return Err(Error::new(
                "policy-version-reused",
                format!(
                    "policy version {} has already been published",
                    incoming.version()
                ),
            ));
        }
        plan.projections.policy = Some((
            incoming.version().to_owned(),
            document,
            incoming.document_hash().to_owned(),
        ));
        Ok(())
    }

    async fn validate_registration(
        &self,
        env: &Value,
        payloads: &[Value],
        plan: &mut AppendPlan,
    ) -> Result<()> {
        let args_hash = env["execution"]["args-hash"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "execution.args-hash"))?;
        let document = payloads
            .iter()
            .find(|p| p["payload-hash"].as_str() == Some(args_hash))
            .map(|p| p["payload"].clone())
            .ok_or_else(|| {
                Error::new(
                    codes::MANIFEST_MALFORMED,
                    "the manifest must be submitted alongside its registration, \
                     and args-hash must be its object-hash",
                )
            })?;
        let manifest = Manifest::parse(&document)?;
        if manifest.hash() != args_hash {
            return Err(Error::new(
                codes::MANIFEST_MALFORMED,
                "args-hash does not commit to the submitted manifest",
            ));
        }
        // §08 §3.2: a `name` bound to a different key is a different component wearing this one's
        // identity.
        if let Some(bound) = self.store.manifest_component_key(manifest.name()).await? {
            if bound != manifest.component_key().as_str() {
                return Err(Error::new(
                    "manifest-name-key-conflict",
                    format!("{} is already bound to {bound}", manifest.name()),
                ));
            }
        }
        if self
            .store
            .manifest_version_exists(manifest.name(), manifest.version())
            .await?
        {
            return Err(Error::new(
                "manifest-version-retained",
                format!(
                    "{} {} is already registered and versions are retained forever",
                    manifest.name(),
                    manifest.version()
                ),
            ));
        }
        // §08 §3.3: no green conformance run, no registration. The run is itself an audited claim —
        // an accepted `kernel.conformance_run` envelope whose `args-hash` is this manifest's hash.
        if !self.store.conformance_run_is_green(manifest.hash()).await? {
            return Err(Error::new(
                "manifest-conformance-not-green",
                format!(
                    "no applied kernel.conformance_run envelope commits to manifest {}",
                    manifest.hash()
                ),
            ));
        }
        plan.projections.manifest = Some((
            manifest.name().to_owned(),
            manifest.version().to_owned(),
            manifest.hash().to_owned(),
            manifest.component_key().as_str().to_owned(),
            document,
        ));
        Ok(())
    }

    fn validate_root_change(
        &self,
        env: &Value,
        payloads: &[Value],
        roots: &[KeyId],
        subject_key: &KeyId,
        plan: &mut AppendPlan,
    ) -> Result<()> {
        // §03 §6: the root set is changed only by a gated envelope signed by an existing root.
        if !roots.contains(subject_key) {
            return Err(Error::new(
                "mandate-root-not-enrolled",
                format!(
                    "{subject_key} is not an enrolled human root and may not change the root set"
                ),
            ));
        }
        match root_change(env, payloads)? {
            RootChange::Enrol { key, subject } => {
                plan.projections.enroll_root = Some((key.as_str().to_owned(), subject));
            }
            RootChange::Retire { key } => {
                plan.projections.retire_root = Some(key.as_str().to_owned());
            }
        }
        Ok(())
    }

    async fn validate_commitment(
        &self,
        env: &Value,
        manifest: Option<&Manifest>,
        subject: &str,
    ) -> Result<()> {
        let Some(commitment) = env.get("commitment-ref") else {
            return Ok(());
        };
        let object_type = commitment["object-type"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "commitment-ref.object-type"))?;
        let object_id = commitment["object-id"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "commitment-ref.object-id"))?;
        let transition = commitment["transition"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "commitment-ref.transition"))?;
        let manifest = manifest.ok_or_else(|| {
            Error::new(
                "durable-transition-not-permitted",
                format!("no registered manifest declares durable object {object_type:?}"),
            )
        })?;
        // The state is the fold of the object's transition envelopes in chain order — never a
        // "current state" row that could be written directly (§02 §8).
        let history = self
            .store
            .durable_transitions(object_type, object_id)
            .await?;
        let mut folded: Option<String> = None;
        for (past, _) in &history {
            folded =
                Some(manifest.check_transition(object_type, past, "agent", folded.as_deref())?);
        }
        // §08 §2: a `["human"]`-only transition is refused from an agent key regardless of the
        // agent's mandate. The role comes from the subject class, which is the only thing about the
        // signer the envelope states.
        let signer_role = if subject.starts_with("human:") {
            "human"
        } else {
            "agent"
        };
        manifest.check_transition(object_type, transition, signer_role, folded.as_deref())?;
        Ok(())
    }

    async fn validate_mandate_grant(
        &self,
        env: &Value,
        policy: &Policy,
        roots: &[KeyId],
        plan: &mut AppendPlan,
    ) -> Result<()> {
        let mandate = env
            .get("mandate")
            .ok_or_else(|| Error::new("schema-missing-member", "mandate"))?;
        let issued_at = mandate["issued-at"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "mandate.issued-at"))?;
        // Only a delegated grant has a parent to resolve. Resolving unconditionally would report
        // `mandate-unresolved` for a *root* mandate that wrongly carries one, hiding the real defect
        // (`mandate-root-has-parent`) behind a lookup failure.
        let parent = match (mandate["mandate-kind"].as_str(), mandate["parent"].as_str()) {
            (Some("delegated"), Some(parent_ref)) => {
                Some(self.store.mandate(parent_ref).await?.ok_or_else(|| {
                    Error::new("mandate-unresolved", format!("no mandate {parent_ref}"))
                })?)
            }
            _ => None,
        };
        let ceiling = policy.standing_lifetime_ceiling(issued_at)?;
        verify_grant(
            mandate,
            parent.as_ref(),
            &GrantParams {
                roots,
                max_standing_not_after: Some(&ceiling),
            },
        )?;
        plan.projections.mandate = Some((signed::object_id(mandate)?, mandate.clone()));
        Ok(())
    }

    async fn validate_revocation(
        &self,
        env: &Value,
        roots: &[KeyId],
        plan: &mut AppendPlan,
    ) -> Result<()> {
        // §03 §7: the revoker signs the **object** under `revocation`; the envelope's own `sig` is
        // the emitter's and attests receipt and chain position, not authority. The envelope used to
        // *be* the revocation object, which meant the revoker's signature covered `stream`, `seq`
        // and `prev-hash` — values only the kernel knows at append — and so could not be produced
        // offline. A root whose seed exists only on a laptop is the person most likely to need this.
        let object = env
            .get("revocation")
            .ok_or_else(|| Error::new("schema-missing-member", "revocation"))?;
        // The top-level members are a projection of the object, kept so the store can index a
        // revocation without opening it. They may not disagree with it: two spellings of one fact
        // let an emitter choose which reader agrees with it.
        for name in ["revokes", "revoked-at", "reason"] {
            if env.get(name) != object.get(name) {
                return Err(Error::new(
                    "revocation-object-mismatch",
                    format!("the envelope's {name} does not match the signed revocation object"),
                ));
            }
        }
        let target = env["revokes"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "revokes"))?;
        if !crypto::is_digest_hex(target) {
            return Err(Error::new(
                "encoding-not-lowercase-hex",
                "revokes must be a 64-hex mandate id",
            ));
        }
        clock::parse_timestamp(
            env["revoked-at"]
                .as_str()
                .ok_or_else(|| Error::new("schema-missing-member", "revoked-at"))?,
        )?;
        let mut mandates = Map::new();
        // Load the target and its ancestry so "signed by the grantor of any ancestor" is decidable.
        for (id, document) in self.store.mandate_ancestry(target, 16).await? {
            mandates.insert(id, document);
        }
        verify_revocation(&mandates, object, roots)?;
        // The projection stores the *envelope* id, which is what the chain names, and the
        // signed object, which is what carries the authority a later reader must re-check.
        plan.projections.revocation = Some((signed::object_id(env)?, object.clone()));
        Ok(())
    }

    async fn validate_gate_decision(
        &self,
        env: &Value,
        roots: &[KeyId],
        policy: &Policy,
        at: &str,
        plan: &mut AppendPlan,
    ) -> Result<()> {
        let decision_of = env["decision-of"]
            .as_str()
            .ok_or_else(|| Error::new("schema-missing-member", "decision-of"))?;
        if !crypto::is_digest_hex(decision_of) {
            return Err(Error::new(
                "encoding-not-lowercase-hex",
                "decision-of must be a 64-hex request hash",
            ));
        }
        let Some(decision) = env.get("decision") else {
            return Ok(());
        };
        let signer = verify_signed_object(decision)
            .map_err(|e| Error::new("gate-decision-sig-invalid", e.detail().to_owned()))?;
        if decision["request-hash"].as_str() != Some(decision_of) {
            return Err(Error::new(
                "gate-authorization-request-hash-mismatch",
                "decision-of must equal the decision's request-hash",
            ));
        }
        match decision["decision"].as_str() {
            Some("approve") => {}
            Some("deny") => {
                if decision["reason"].as_str().unwrap_or_default().is_empty() {
                    return Err(Error::new(
                        "gate-denial-without-reason",
                        "a denial must state why",
                    ));
                }
            }
            other => {
                return Err(Error::new(
                    "gate-decision-unknown",
                    format!("decision {other:?}"),
                ));
            }
        }
        // An agent that can approve is a system with no gates (§06 §5).
        let permitted = match policy.decision_for("consequential") {
            Decision::Gate { approvers } => self.approver_keys(&approvers, at, "").await?,
            Decision::Allow | Decision::Deny => self.root_approvers(at).await?,
        };
        if !permitted.iter().any(|a| a.key == signer) && !roots.contains(&signer) {
            return Err(Error::new(
                "gate-approver-not-permitted",
                format!("{signer} is not an approver in this deployment"),
            ));
        }
        // When the request is one the kernel queued (§06 §4.3), the decision is bound to it here:
        // request-hash over the stored bytes, self-approval, the closed vocabulary and both expiry
        // windows. A decision over a request this kernel never saw is still a legitimate record —
        // a component enforcing locally may have parked it — so the absence of a row is not a
        // refusal, only the absence of the extra binding.
        if let Some((request, _)) = self.store.gate_request(decision_of).await? {
            let requested_at = request["requested-at"].as_str().unwrap_or(at).to_owned();
            let queued = crate::gatequeue::validate(&request, &requested_at)?;
            let checked = crate::gatequeue::check_decision(decision, &queued)?;
            // §06 §5: the approver subject must not be the requesting subject either — a human who
            // holds two keys is still one human, and "escalation terminates at a named human"
            // (maxim 3) is about the person, not the keypair.
            if self.subject_of(&checked.decided_by, at).await? == Some(queued.subject.clone()) {
                return Err(Error::new(
                    "gate-self-approval",
                    format!("{} decided its own subject's request", queued.subject),
                ));
            }
            plan.projections.gate_decision = Some(GateDecisionRow {
                request_hash: checked.request_hash,
                verdict: checked.verdict,
                reason: checked.reason,
                decided_by: checked.decided_by.as_str().to_owned(),
                decided_at: checked.decided_at,
                decision: checked.decision,
            });
        }
        Ok(())
    }

    /// The named subject a key acts as, if the deployment knows one: an enrolled root, or a human
    /// holding a mandate. Used only to refuse self-approval by a second key of the same human.
    ///
    /// §06 §5 admits both approver kinds — "an enrolled human root, **or** a human holding a mandate
    /// whose scope includes the action" — so resolving through the root set alone would leave the
    /// second kind unresolvable, and an unresolvable subject is one the self-approval check cannot
    /// refuse.
    async fn subject_of(&self, key: &KeyId, at: &str) -> Result<Option<String>> {
        for (root_key, subject) in self.store.roots_at(at).await? {
            if &root_key == key {
                return Ok(Some(subject));
            }
        }
        self.store.mandated_subject_of(key.as_str(), at).await
    }

    /// The enrolled roots at `at`, as approvers whose subject the deployment can name (§06 §5).
    async fn root_approvers(&self, at: &str) -> Result<Vec<Approver>> {
        Ok(self
            .store
            .roots_at(at)
            .await?
            .into_iter()
            .map(|(key, subject)| Approver::named(key, subject))
            .collect())
    }

    async fn validate_checkpoint(&self, env: &Value, plan: &mut AppendPlan) -> Result<()> {
        let body = env
            .get("checkpoint")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::new("schema-missing-member", "checkpoint"))?;
        for key in body.keys() {
            if ![
                "stream",
                "from-seq",
                "to-seq",
                "head-hash",
                "count",
                "observed-at",
            ]
            .contains(&key.as_str())
            {
                return Err(Error::new(
                    "schema-unknown-member",
                    format!("checkpoint.{key}"),
                ));
            }
        }
        // §04 §4.1: a checkpoint signed by any other key is not a checkpoint.
        if env["sig"]["key"].as_str() != Some(self.kernel_key.id().as_str()) {
            return Err(Error::new(
                "checkpoint-signer-not-kernel",
                "a checkpoint must be signed by the kernel's enrolled checkpoint key",
            ));
        }
        let target_stream = body
            .get("stream")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new("schema-missing-member", "checkpoint.stream"))?;
        let from_seq = body
            .get("from-seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::new("schema-missing-member", "checkpoint.from-seq"))?;
        let to_seq = body
            .get("to-seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::new("schema-missing-member", "checkpoint.to-seq"))?;
        let count = body
            .get("count")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::new("schema-missing-member", "checkpoint.count"))?;
        let head_hash = body
            .get("head-hash")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new("schema-missing-member", "checkpoint.head-hash"))?;
        let observed_at = body
            .get("observed-at")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new("schema-missing-member", "checkpoint.observed-at"))?;
        clock::parse_timestamp(observed_at)?;
        if count != to_seq.saturating_sub(from_seq) + 1 {
            return Err(Error::new(
                "checkpoint-count-mismatch",
                format!("count {count} does not match [{from_seq}, {to_seq}]"),
            ));
        }
        if self.store.stream_kind(target_stream).await?.is_none() {
            return Err(Error::new(
                codes::CHECKPOINT_STREAM_UNKNOWN,
                format!("no stream {target_stream} has been written to"),
            ));
        }
        // §04 §4.3: `head-hash` MUST equal `id()` of envelope `to-seq` of the attested stream.
        let attested = self
            .store
            .range(target_stream, to_seq, to_seq)
            .await?
            .first()
            .map(signed::object_id)
            .transpose()?
            .ok_or_else(|| {
                Error::new(
                    "checkpoint-head-mismatch",
                    format!("{target_stream} has no envelope at seq {to_seq}"),
                )
            })?;
        if attested != head_hash {
            return Err(Error::new(
                "checkpoint-head-mismatch",
                format!("head of {target_stream} at {to_seq} is {attested}, attested {head_hash}"),
            ));
        }
        plan.projections.checkpoint = Some(CheckpointRow {
            stream: target_stream.to_owned(),
            from_seq,
            to_seq,
            head_hash: head_hash.to_owned(),
            observed_at: observed_at.to_owned(),
        });
        Ok(())
    }

    /// The keys permitted to approve an action of this class in this deployment (§06 §5).
    ///
    /// Public because the console's decision route has to answer "may this key say yes to *this*"
    /// before recording anything, and it must answer it with the **same** resolution ingest will
    /// apply to the effect afterwards. A console with its own notion of who may approve is a second
    /// policy, and the second one is always the one that is wrong.
    ///
    /// # Errors
    ///
    /// [`codes::STORE_UNAVAILABLE`], or any policy parse failure.
    pub async fn approvers_for(
        &self,
        classification: &str,
        action: &str,
        at: &str,
    ) -> Result<Vec<Approver>> {
        let roots = self.root_approvers(at).await?;
        // Policy cannot lower the bar on the mechanism that enforces policy (§05 §5.2, §08 §3.1,
        // §03 §6): these four are approved by an enrolled root whatever `gate-rules` says.
        if ROOT_APPROVED_ACTIONS.contains(&action) {
            return Ok(roots);
        }
        let Some(document) = self.store.current_policy().await? else {
            return Ok(roots);
        };
        let policy = Policy::parse(&document, &self.config.policy_key)?;
        match policy.decision_for(classification) {
            Decision::Gate { approvers } => self.approver_keys(&approvers, at, action).await,
            Decision::Allow | Decision::Deny => Ok(roots),
        }
    }

    /// Resolve approver *subjects* to the keys permitted to sign (§06 §5).
    ///
    /// An approver is an enrolled human root, or a human holding a mandate whose scope includes the
    /// action being approved. Never a group, a role or a rotation — a rotation may decide whom to
    /// notify, but the signature is always one person's.
    /// Each key is returned with the subject it was resolved *from*, because that is what makes the
    /// subject half of §06 §5's self-approval prohibition checkable at all (see
    /// [`stozher_core::gate::Approver`]).
    async fn approver_keys(
        &self,
        subjects: &[String],
        at: &str,
        action: &str,
    ) -> Result<Vec<Approver>> {
        let mut keys: Vec<Approver> = Vec::new();
        for (key, subject) in self.store.roots_at(at).await? {
            if subjects.iter().any(|s| s == &subject) {
                keys.push(Approver::named(key, subject));
            }
        }
        for subject in subjects {
            if !subject.starts_with("human:") {
                continue;
            }
            for mandate in self.store.mandates_held_by(subject, at).await? {
                let covers_action = action.is_empty()
                    || mandate["scope"]["actions"]
                        .as_array()
                        .is_some_and(|patterns| {
                            patterns.iter().filter_map(Value::as_str).any(|pattern| {
                                pattern == "*"
                                    || pattern == action
                                    || pattern.strip_suffix(".*").is_some_and(|prefix| {
                                        action.len() > prefix.len()
                                            && action.starts_with(prefix)
                                            && action.as_bytes()[prefix.len()] == b'.'
                                    })
                            })
                        });
                if !covers_action {
                    continue;
                }
                if let Some(key) = mandate["grantee"]["key"].as_str() {
                    if let Ok(key) = KeyId::parse(key) {
                        if !keys.iter().any(|a| a.key == key) {
                            keys.push(Approver::named(key, subject.clone()));
                        }
                    }
                }
            }
        }
        Ok(keys)
    }

    /// Clamp retention to the policy ceiling and prepare payloads for storage.
    fn collect_payloads(
        &self,
        env: &Value,
        payloads: &[Value],
        policy: &Policy,
        class: Option<&str>,
        plan: &mut AppendPlan,
    ) -> Result<()> {
        let emitted_at = env["emitted-at"].as_str().unwrap_or_default();
        if let (Some(class), Some(evidence)) = (class, env.get("evidence")) {
            if policy.stores_payloads(class) {
                let claimed = evidence["retain-until"]
                    .as_str()
                    .ok_or_else(|| Error::new("schema-missing-member", "evidence.retain-until"))?;
                let ceiling = policy.retention_ceiling(class, emitted_at)?;
                // An emitter cannot buy itself a longer retention than the org allows (§02 §5).
                if claimed > ceiling.as_str() {
                    return Err(Error::new(
                        "evidence-retention-too-long",
                        format!(
                            "retain-until {claimed} exceeds the policy ceiling {ceiling} for {class}"
                        ),
                    ));
                }
            } else {
                // `P0D` means no payload is stored at all. The kernel discards what was submitted
                // and does **not** treat the submission as an error — the emitter may be running
                // older policy (§05 §4) — so the ceiling comparison, which `P0D` would make
                // unsatisfiable for any future `retain-until`, is not applied here either.
                return Ok(());
            }
        }
        for payload in payloads {
            let payload_hash = payload["payload-hash"]
                .as_str()
                .ok_or_else(|| Error::new("schema-missing-member", "payloads[].payload-hash"))?;
            let media_type = payload["media-type"]
                .as_str()
                .ok_or_else(|| Error::new("schema-missing-member", "payloads[].media-type"))?;
            let body = &payload["payload"];
            let bytes = if media_type == payload::JSON_MEDIA_TYPE {
                jcs::canonicalize(body)?.into_bytes()
            } else {
                hex::decode(body.as_str().unwrap_or_default()).map_err(|e| {
                    Error::new(
                        "encoding-not-lowercase-hex",
                        format!("payloads[].payload: {e}"),
                    )
                })?
            };
            let retain_until =
                retain_until_for(env, payload_hash).unwrap_or_else(|| emitted_at.to_owned());
            plan.payloads.push(PayloadRow {
                payload_hash: payload_hash.to_owned(),
                media_type: media_type.to_owned(),
                bytes,
                retain_until,
            });
        }
        Ok(())
    }
}

/// What a `kernel.enroll_root` / `kernel.retire_root` envelope changes about the root set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootChange {
    /// Add this key, under the name of the human it belongs to.
    Enrol {
        /// The key being enrolled.
        key: KeyId,
        /// The `human:<name>` subject it belongs to.
        subject: String,
    },
    /// Retire this key. Not retroactive (§03 §8).
    Retire {
        /// The key being retired.
        key: KeyId,
    },
}

/// Read a root change out of its envelope — `spec/03 §6`, everything except *who may make it*.
///
/// Split out from [`Ingest::validate_root_change`], which keeps the one check that needs the
/// deployment's current root set, so that the rest is a pure function of the envelope and its
/// payloads. That is what `spec/vectors/root-change.json` can ask of any implementation.
///
/// # Errors
///
/// [`codes::ROOT_ENROLLMENT_MALFORMED`], or `schema-missing-member`.
pub fn root_change(env: &Value, payloads: &[Value]) -> Result<RootChange> {
    let target = env["execution"]["target"].as_str().unwrap_or_default();
    let key = target.strip_prefix("root:").ok_or_else(|| {
        Error::new(
            codes::ROOT_ENROLLMENT_MALFORMED,
            format!("execution.target {target:?} must be root:ed25519:<64 hex>"),
        )
    })?;
    let key = KeyId::parse(key).map_err(|e| {
        Error::new(
            codes::ROOT_ENROLLMENT_MALFORMED,
            format!("execution.target does not name a key: {}", e.detail()),
        )
    })?;
    if env["execution"]["action"].as_str() == Some("kernel.enroll_root") {
        let subject = enrolled_subject(env, payloads, &key)?;
        Ok(RootChange::Enrol { key, subject })
    } else {
        Ok(RootChange::Retire { key })
    }
}

/// Read a stream resume out of its envelope — `spec/04 §7.2`, everything except *who may make it*.
///
/// Split out for the same reason [`root_change`] is: who may resume a stream needs the deployment's
/// root set, and §05 §5.6 answers it the same way it answers a policy change. What is left is a pure
/// function of the envelope and the payload its `args-hash` commits to, which is what
/// `spec/vectors/stream-recovery.json` can ask of any implementation.
///
/// Nothing here validates the refused bytes, and nothing here fills the refused position. A resume
/// is an operator saying *"this stream may continue"*, never *"that envelope was fine after all"*
/// (§04 §7.2 rule 4).
///
/// # Errors
///
/// [`codes::STREAM_RESUME_UNBOUND`], [`codes::STREAM_RESUME_MALFORMED`], or `schema-missing-member`.
pub fn stream_resume(env: &Value, payloads: &[Value]) -> Result<StreamResume> {
    let target = env["execution"]["target"].as_str().unwrap_or_default();
    let named = target.strip_prefix("stream:").ok_or_else(|| {
        Error::new(
            codes::STREAM_RESUME_MALFORMED,
            format!("execution.target {target:?} must be stream:<stream>"),
        )
    })?;
    let args_hash = env["execution"]["args-hash"]
        .as_str()
        .ok_or_else(|| Error::new("schema-missing-member", "execution.args-hash"))?;
    // The document is required, and an absent payload is ordinarily decay: the position being
    // resumed exists nowhere else in the envelope, so there would be nothing to record and nothing
    // to reconstruct. Located by `args-hash` because that is the value the root's signature covers —
    // a resume whose document the approval does not commit to is a signature over nothing.
    let document = payloads
        .iter()
        .find(|p| p["payload-hash"].as_str() == Some(args_hash))
        .map(|p| &p["payload"])
        .ok_or_else(|| {
            Error::new(
                codes::STREAM_RESUME_UNBOUND,
                "a resume must submit the document its args-hash commits to",
            )
        })?;
    let members = document.as_object().ok_or_else(|| {
        Error::new(
            codes::STREAM_RESUME_MALFORMED,
            "the resume document must be a JSON object",
        )
    })?;
    // Closed, for the reason a policy document's member set is closed: a resume an implementation
    // does not fully understand is a resume it MUST NOT act on.
    for key in members.keys() {
        if !matches!(
            key.as_str(),
            "stream" | "resume-seq" | "refused-object-hash" | "reason-code"
        ) {
            return Err(Error::new(
                codes::STREAM_RESUME_MALFORMED,
                format!("unknown member {key:?} in the resume document"),
            ));
        }
    }
    let stream = members
        .get("stream")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(codes::STREAM_RESUME_MALFORMED, "stream"))?;
    if stream != named {
        return Err(Error::new(
            codes::STREAM_RESUME_MALFORMED,
            format!("the document resumes {stream}, execution.target names {named}"),
        ));
    }
    let resume_seq = members
        .get("resume-seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::new(codes::STREAM_RESUME_MALFORMED, "resume-seq"))?;
    let bridge_hash = members
        .get("refused-object-hash")
        .and_then(Value::as_str)
        .filter(|h| {
            h.len() == 64
                && h.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        })
        .ok_or_else(|| {
            Error::new(
                codes::STREAM_RESUME_MALFORMED,
                "refused-object-hash must be 64 lowercase hex characters",
            )
        })?;
    let reason_code = members
        .get("reason-code")
        .and_then(Value::as_str)
        .filter(|r| !r.is_empty())
        .ok_or_else(|| Error::new(codes::STREAM_RESUME_MALFORMED, "reason-code"))?;
    Ok(StreamResume {
        stream: stream.to_owned(),
        resume_seq,
        bridge_hash: bridge_hash.to_owned(),
        reason_code: reason_code.to_owned(),
    })
}

/// The human an enrolment names, read from the evidence the approval committed to (§03 §6).
///
/// # Why the payload is required here and nowhere else
///
/// A referenced payload may legitimately be absent at ingest — that is what a decayed evidence
/// section looks like, and [`payload::verify_ingest`] permits it. Not for this action. The `roots`
/// projection stores `(key, subject)`, and the **subject** is the value §06 §5's self-approval
/// prohibition is evaluated over: *a human holding a second key is still the same human*. If the
/// subject is not in the envelope, there is nothing to record and nothing to reconstruct later.
///
/// This previously fell back to `execution.target` — the string `root:ed25519:<hex>` — which is a
/// name no human has. The mechanism for giving a person a second enrolled key was therefore also
/// the mechanism that stopped the prohibition recognising them as the same person, and nothing
/// contradicted it because roots seeded from `Config` carry their real subjects.
///
/// The payload is bound to `execution.args-hash`, which is what the approver signed over, so the
/// name recorded here is the name a named human approved — not one the emitter chose afterwards.
fn enrolled_subject(env: &Value, payloads: &[Value], enrolled: &KeyId) -> Result<String> {
    let args_hash = env["execution"]["args-hash"]
        .as_str()
        .ok_or_else(|| Error::new("schema-missing-member", "execution.args-hash"))?;
    let evidence = payloads
        .iter()
        .find(|p| p["payload-hash"].as_str() == Some(args_hash))
        .map(|p| &p["payload"])
        .ok_or_else(|| {
            Error::new(
                codes::ROOT_ENROLLMENT_MALFORMED,
                "an enrolment must submit the evidence its args-hash commits to, naming the human",
            )
        })?;
    let subject = evidence["subject"].as_str().unwrap_or_default();
    if !subject.starts_with("human:") || subject.len() <= "human:".len() {
        return Err(Error::new(
            codes::ROOT_ENROLLMENT_MALFORMED,
            format!("the evidence names {subject:?}, which is not a human subject"),
        ));
    }
    // The evidence names a key as well, and it must be the one being enrolled: two spellings of
    // one fact let an emitter approve the enrolment of one key and record another.
    match evidence["key"].as_str() {
        Some(key) if key == enrolled.as_str() => Ok(subject.to_owned()),
        Some(key) => Err(Error::new(
            codes::ROOT_ENROLLMENT_MALFORMED,
            format!("the evidence names key {key}, execution.target names {enrolled}"),
        )),
        None => Err(Error::new(
            codes::ROOT_ENROLLMENT_MALFORMED,
            "the evidence names no key",
        )),
    }
}

/// Which of the two payload-bearing sections committed to this hash, and until when.
fn retain_until_for(env: &Value, payload_hash: &str) -> Option<String> {
    for section in ["evidence", "signal"] {
        let section = env.get(section)?;
        if section["payload-hash"].as_str() == Some(payload_hash) {
            return section["retain-until"].as_str().map(str::to_owned);
        }
    }
    None
}

fn validate_aggregate_window(env: &Value, policy: &Policy) -> Result<()> {
    let from = env["window"]["from"]
        .as_str()
        .ok_or_else(|| Error::new("schema-missing-member", "window.from"))?;
    let to = env["window"]["to"]
        .as_str()
        .ok_or_else(|| Error::new("schema-missing-member", "window.to"))?;
    if to < from {
        return Err(Error::new(
            codes::AGGREGATE_WINDOW_INVERTED,
            format!("window [{from}, {to}] is inverted"),
        ));
    }
    let ceiling = clock::shift(from, policy.aggregate_max_window_seconds())?;
    if to > ceiling.as_str() {
        // "An aggregate that is still open is an effect that is not yet in the audit" (§02 §7.5).
        return Err(Error::new(
            codes::AGGREGATE_WINDOW_TOO_LONG,
            format!("window ends at {to}, later than the policy ceiling {ceiling}"),
        ));
    }
    Ok(())
}

enum Either {
    Idempotent(Appended),
    Fresh(Box<Validated>),
}

/// `object-hash` of the rejected bytes, or their SHA-256 when they are not a JSON value at all
/// (§04 §7). The raw bytes are deliberately **not** retained: a rejected object may carry personal
/// data, and hoarding it forever would contradict §04 §5.
fn rejected_bytes_hash(raw: &[u8]) -> String {
    std::str::from_utf8(raw)
        .ok()
        .and_then(|text| jcs::parse(text).ok())
        .and_then(|value| jcs::object_hash(&value).ok())
        .unwrap_or_else(|| crypto::sha256_hex(raw))
}

/// What the rejected object claimed about itself, for investigation. Best effort by definition: the
/// object is invalid, so nothing in it is trusted.
fn claims(raw: &[u8]) -> Claims {
    let Some(value) = std::str::from_utf8(raw)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
    else {
        return Claims::default();
    };
    let env = value.get("envelope").unwrap_or(&value);
    Claims {
        stream: env["stream"].as_str().map(str::to_owned),
        seq: env["seq"].as_u64(),
        kind: env["kind"].as_str().map(str::to_owned),
    }
}

fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Verify a stored range and return its head hash and whether it was anchored (§04 §2.1).
///
/// Payloads are never consulted. That is the property that makes erasure compatible with integrity,
/// so it is worth stating where the verification is actually invoked.
///
/// # Errors
///
/// Any chain or structural code from [`chain::verify_chain`].
pub fn verify_range(
    envelopes: &[Value],
    stream: &str,
    anchor: Option<&str>,
) -> Result<chain::ChainResult> {
    chain::verify_chain(envelopes, stream, anchor)
}

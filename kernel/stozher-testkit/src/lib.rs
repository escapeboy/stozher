//! Test harness for the Stozher kernel: a real kernel, bootstrapped through the real genesis path.
//!
//! This is a crate rather than an inline `mod support` in each test file so that its helpers are a
//! public API rather than per-binary dead code — otherwise every test binary that happens not to use
//! a fixture would warn, and the only cures are a lint suppression or a lie.
//!
//! Nothing here reaches around the pipeline. The world is built by submitting the same two genesis
//! envelopes an operator would submit, and every later fixture goes through `POST /v1/ingest`'s own
//! entry point. A harness that seeded the store directly would test a store that production never
//! sees, and would quietly hide exactly the bugs these tests exist to catch.

use std::sync::Arc;

use serde_json::{Value, json};
use stozher_core::signed::KeyId;
use stozher_core::{crypto, jcs, signed};
use stozher_kernel::clock::{Clock, FixedClock, SharedClock};
use stozher_kernel::keys::{ROLE_KERNEL_CHECKPOINT, Seed};
use stozher_kernel::{Config, Ingest, Kernel, Outcome, Store};

/// The instant the world is built at. Fixed so every expectation is reproducible.
pub const NOW: &str = "2026-07-26T09:00:00.000Z";
/// The effect stream test fixtures append to.
pub const EFFECT_STREAM: &str = "gw:dev:0001";
/// The signal stream test fixtures append to.
pub const SIGNAL_STREAM: &str = "signals:gateway:0001";
/// The kernel's own stream.
pub const CORE_STREAM: &str = "kernel:core";
/// The bearer token the harness authenticates with.
pub const TOKEN: &str = "test-caller-token";

/// A keypair a test controls.
pub struct TestKey {
    secret: [u8; 32],
    /// The public key identifier.
    pub id: KeyId,
    /// The subject this key acts as.
    pub subject: String,
}

impl TestKey {
    fn new(seed_byte: u8, subject: &str) -> Self {
        let secret = [seed_byte; 32];
        Self {
            secret,
            id: KeyId::from_public_key(&crypto::public_key_of(&secret)),
            subject: subject.to_owned(),
        }
    }

    /// Sign an object per the signed-object pattern.
    pub fn sign(&self, object: &Value) -> Value {
        signed::sign_object(object, &self.secret).expect("signing a JSON object")
    }
}

/// A bootstrapped kernel plus every key the tests need.
pub struct World {
    /// The kernel under test.
    pub kernel: Arc<Kernel>,
    /// The clock the kernel reads, movable by tests.
    pub clock: Arc<FixedClock>,
    /// `human:ivan` — enrolled root and the approver named by the baseline policy.
    pub root: TestKey,
    /// `human:mira` — a second enrolled root, for cases needing two humans.
    pub second_root: TestKey,
    /// The organization's policy key at role `4'`.
    pub policy_key: TestKey,
    /// `agent:gateway/dev` — the subject most fixtures act as.
    pub agent: TestKey,
    /// A key enrolled nowhere, for negative cases.
    pub stranger: TestKey,
    /// The version the bootstrap published.
    pub policy_version: String,
    /// The interactive mandate granted at genesis.
    pub interactive_mandate: String,
    /// A standing mandate wide enough for the fixtures' effects.
    pub standing_mandate: String,
}

/// Build and bootstrap a world.
pub async fn world() -> World {
    let clock = Arc::new(FixedClock::new(NOW).expect("a fixed clock at NOW"));
    let root = TestKey::new(0x11, "human:ivan");
    let second_root = TestKey::new(0x12, "human:mira");
    let policy_key = TestKey::new(0x13, "org:policy");
    let agent = TestKey::new(0x14, "agent:gateway/dev");
    let stranger = TestKey::new(0x15, "agent:nowhere");

    let config = Config::parse(&json!({
        "bind": "127.0.0.1:0",
        "database": ":memory:",
        "kernel-seed": "/nonexistent/kernel.seed",
        "policy-key": policy_key.id.as_str(),
        "kernel-core-stream": CORE_STREAM,
        "checkpoint-stream": "kernel:checkpoints",
        "rejection-stream": "kernel:rejections",
        "roots": [
            { "subject": root.subject, "key": root.id.as_str(), "enrolled-at": "2026-07-01T00:00:00.000Z" },
            { "subject": second_root.subject, "key": second_root.id.as_str(), "enrolled-at": "2026-07-01T00:00:00.000Z" }
        ],
        "callers": [
            { "subject": "agent:test-harness", "token-sha256": crypto::sha256_hex(TOKEN.as_bytes()) }
        ]
    }))
    .expect("a valid configuration");

    let store = Store::open_memory("kernel:rejections")
        .await
        .expect("an in-memory store");
    let kernel_key = Seed::generate()
        .expect("entropy")
        .derive(ROLE_KERNEL_CHECKPOINT, 0)
        .expect("derivation");
    let kernel = Arc::new(
        Kernel::assemble(
            config,
            store,
            kernel_key,
            Arc::clone(&clock) as SharedClock,
        )
        .await
        .expect("assembling the kernel"),
    );

    let mut world = World {
        kernel,
        clock,
        root,
        second_root,
        policy_key,
        agent,
        stranger,
        policy_version: String::new(),
        interactive_mandate: String::new(),
        standing_mandate: String::new(),
    };
    world.bootstrap().await;
    world
}

impl World {
    /// The ingest pipeline.
    pub fn ingest(&self) -> &Ingest {
        &self.kernel.ingest
    }

    /// Submit an envelope with its payloads and return the outcome.
    pub async fn submit(&self, envelope: &Value, payloads: &[Value]) -> Outcome {
        let request = json!({ "envelope": envelope, "payloads": payloads });
        let raw = jcs::canonicalize(&request).expect("canonicalizing an ingest request");
        self.ingest()
            .submit(raw.as_bytes(), Some("agent:test-harness"))
            .await
    }

    /// Submit and require acceptance, reporting the refusal if there is one.
    pub async fn accept(&self, envelope: &Value, payloads: &[Value]) -> String {
        match self.submit(envelope, payloads).await {
            Outcome::Accepted(appended) => appended.id,
            Outcome::Rejected { reason, detail, .. } => {
                panic!("expected acceptance, got {reason}: {detail}")
            }
            Outcome::Unavailable(detail) => panic!("store unavailable: {detail}"),
        }
    }

    /// Submit and require refusal with a specific reason code.
    pub async fn reject(&self, envelope: &Value, payloads: &[Value], expected: &str) {
        match self.submit(envelope, payloads).await {
            Outcome::Rejected { reason, detail, .. } => assert_eq!(
                reason, expected,
                "wrong reason code (detail: {detail})"
            ),
            Outcome::Accepted(appended) => {
                panic!("expected {expected}, but the envelope was accepted as {}", appended.id)
            }
            Outcome::Unavailable(detail) => panic!("store unavailable: {detail}"),
        }
    }

    /// The head hash of a stream, for chaining the next envelope.
    pub async fn head(&self, stream: &str) -> (u64, Option<String>) {
        match self
            .ingest()
            .store()
            .stream_head(stream)
            .await
            .expect("reading a stream head")
        {
            Some((seq, id)) => (seq + 1, Some(id)),
            None => (0, None),
        }
    }

    /// The two genesis envelopes of §05 §5.2, submitted through the real pipeline.
    async fn bootstrap(&mut self) {
        // (0) An enrolled root grants an interactive mandate to the bootstrap subject.
        let mandate = self.root.sign(&json!({
            "v": stozher_core::VERSION,
            "kind": "mandate",
            "mandate-kind": "interactive",
            "grantor": { "subject": self.root.subject, "key": self.root.id.as_str(), "role": "human" },
            "grantee": { "subject": self.agent.subject, "key": self.agent.id.as_str() },
            "issued-at": NOW,
            "not-before": NOW,
            "not-after": "2026-07-26T17:00:00.000Z",
            "parent": Value::Null,
            "max-depth": 2,
            "scope": {
                "components": ["kernel"],
                "actions": ["kernel.*"],
                "classes": ["read", "benign", "consequential"],
                "resources": ["*"]
            },
            "nonce": "00000000000000000000000000000001"
        }));
        self.interactive_mandate = signed::object_id(&mandate).expect("mandate id");
        let envelope = self.agent.sign(&json!({
            "v": stozher_core::VERSION,
            "kind": "mandate",
            "emitted-at": NOW,
            "stream": CORE_STREAM,
            "seq": 0,
            "prev-hash": Value::Null,
            "identity": { "subject": self.agent.subject, "key": self.agent.id.as_str(), "component": "kernel" },
            "mandate": mandate
        }));
        self.accept(&envelope, &[]).await;

        // (1) That subject publishes the first policy, approved by the root.
        let document = self.policy_key.sign(&stozher_kernel::policy::baseline_conservative(
            "2026.07.1",
            NOW,
            &self.root.subject,
        ));
        self.policy_version = "2026.07.1".to_owned();
        self.publish_policy(&document).await;

        // A standing mandate wide enough for ordinary fixtures. Not part of the ceremony — an
        // ordinary `mandate` envelope, appended once policy is in force.
        let standing = self.root.sign(&json!({
            "v": stozher_core::VERSION,
            "kind": "mandate",
            "mandate-kind": "standing",
            "grantor": { "subject": self.root.subject, "key": self.root.id.as_str(), "role": "human" },
            "grantee": { "subject": self.agent.subject, "key": self.agent.id.as_str() },
            "issued-at": NOW,
            "not-before": NOW,
            "not-after": "2026-10-01T00:00:00.000Z",
            "parent": Value::Null,
            "max-depth": 2,
            "scope": {
                "components": ["gateway", "kernel", "boruna"],
                "actions": ["github.*", "slack.*", "fs.*", "kernel.*", "-"],
                "classes": ["read", "benign", "consequential", "prohibited"],
                "resources": ["*"]
            },
            "nonce": "00000000000000000000000000000002"
        }));
        self.standing_mandate = signed::object_id(&standing).expect("mandate id");
        let envelope = self.core_envelope("mandate", json!({ "mandate": standing })).await;
        self.accept(&envelope, &[]).await;
    }

    /// Publish a signed policy document through the full gated path.
    pub async fn publish_policy(&mut self, document: &Value) {
        let version = document["policy-version"].as_str().expect("policy-version").to_owned();
        let document_hash = jcs::object_hash(document).expect("policy hash");
        let target = format!("policy:{version}");
        let outgoing = if self.policy_version.is_empty() {
            version.clone()
        } else {
            self.policy_version.clone()
        };
        let authorization = self.authorize(&Ask {
            requester: &self.agent,
            component: "kernel",
            mandate_ref: &self.interactive_mandate,
            policy_version: &outgoing,
            classification: "consequential",
            action: "kernel.publish_policy",
            target: &target,
            args_hash: &document_hash,
        });
        let body = json!({
            "mandate-ref": self.interactive_mandate,
            "policy-version": outgoing,
            "classification": "consequential",
            "execution": {
                "action": "kernel.publish_policy",
                "target": target,
                "args-hash": document_hash,
                "outcome": "applied",
                "started-at": NOW,
                "finished-at": NOW
            },
            "evidence": {
                "schema": "kernel.publish_policy.v1",
                "media-type": "application/json",
                "payload-hash": document_hash,
                "retain-until": "2027-07-26T00:00:00.000Z"
            },
            "authorization": authorization
        });
        let envelope = self.core_envelope("policy-change", body).await;
        let payload = json!({
            "payload-hash": document_hash,
            "media-type": "application/json",
            "payload": document
        });
        self.accept(&envelope, &[payload]).await;
        self.policy_version = version;
    }

    /// Build and sign an envelope on the kernel's core stream at the next free position.
    pub async fn core_envelope(&self, kind: &str, extra: Value) -> Value {
        let (seq, prev) = self.head(CORE_STREAM).await;
        let mut body = json!({
            "v": stozher_core::VERSION,
            "kind": kind,
            "emitted-at": self.clock.now(),
            "stream": CORE_STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": { "subject": self.agent.subject, "key": self.agent.id.as_str(), "component": "kernel" }
        });
        merge(&mut body, extra);
        self.agent.sign(&body)
    }

    /// An `authorization` object: an action request plus a root's signature over its hash (§06 §1).
    pub fn authorize(&self, ask: &Ask<'_>) -> Value {
        let request = self.action_request(ask);
        let decision = self.decide(&request, "approve", None, &self.root);
        json!({ "request": request, "decision": decision })
    }

    /// An action request object (§06 §1.1).
    pub fn action_request(&self, ask: &Ask<'_>) -> Value {
        json!({
            "v": stozher_core::VERSION,
            "kind": "action-request",
            "requested-at": self.clock.now(),
            "subject": ask.requester.subject,
            "key": ask.requester.id.as_str(),
            "component": ask.component,
            "mandate-ref": ask.mandate_ref,
            "policy-version": ask.policy_version,
            "classification": ask.classification,
            "action": ask.action,
            "target": ask.target,
            "args-hash": ask.args_hash,
            "nonce": crypto::sha256_hex(
                format!("{}|{}|{}|{}", ask.action, ask.target, ask.args_hash, ask.mandate_ref)
                    .as_bytes()
            )[..32]
                .to_owned(),
            "not-after": "2026-07-26T17:00:00.000Z"
        })
    }

    /// A signed gate decision over a request (§06 §1.2).
    pub fn decide(
        &self,
        request: &Value,
        verdict: &str,
        reason: Option<&str>,
        approver: &TestKey,
    ) -> Value {
        approver.sign(&json!({
            "v": stozher_core::VERSION,
            "kind": "gate-decision",
            "request-hash": jcs::object_hash(request).expect("request hash"),
            "decision": verdict,
            "decided-at": self.clock.now(),
            "not-after": "2026-07-26T17:00:00.000Z",
            "single-use": true,
            "reason": reason.map_or(Value::Null, |r| Value::from(r))
        }))
    }

    /// A signed `effect` envelope on [`EFFECT_STREAM`], chained onto its current head.
    ///
    /// `overrides` is merged over the body before signing, so a test can express "the valid case,
    /// but with this one member wrong" without restating twenty members.
    pub async fn effect(&self, action: &str, class: &str, overrides: Value) -> Value {
        let (seq, prev) = self.head(EFFECT_STREAM).await;
        let args_hash = crypto::sha256_hex(format!("args-for-{action}-{seq}").as_bytes());
        let mut body = json!({
            "v": stozher_core::VERSION,
            "kind": "effect",
            "emitted-at": self.clock.now(),
            "stream": EFFECT_STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": { "subject": self.agent.subject, "key": self.agent.id.as_str(), "component": "gateway" },
            "mandate-ref": self.standing_mandate,
            "policy-version": self.policy_version,
            "classification": class,
            "execution": {
                "action": action,
                "target": "repo:acme/backend",
                "args-hash": args_hash,
                "outcome": "applied",
                "started-at": self.clock.now(),
                "finished-at": self.clock.now()
            }
        });
        merge(&mut body, overrides);
        self.agent.sign(&body)
    }

    /// A `consequential` effect carrying a valid approval — the accept case of the gate matrix.
    pub async fn gated_effect(&self, action: &str, overrides: Value) -> Value {
        let draft = self.effect(action, "consequential", json!({})).await;
        let args_hash = draft["execution"]["args-hash"].as_str().expect("args-hash").to_owned();
        let target = draft["execution"]["target"].as_str().expect("target").to_owned();
        let authorization = self.authorize(&Ask {
            requester: &self.agent,
            component: "gateway",
            mandate_ref: &self.standing_mandate,
            policy_version: &self.policy_version,
            classification: "consequential",
            action,
            target: &target,
            args_hash: &args_hash,
        });
        let mut body = draft.as_object().expect("an object").clone();
        body.remove("sig");
        let mut body = Value::Object(body);
        merge(&mut body, json!({ "authorization": authorization }));
        merge(&mut body, overrides);
        self.agent.sign(&body)
    }

    /// A `signal` envelope on [`SIGNAL_STREAM`] (§07 §2).
    pub async fn signal(&self, payload: &Value, overrides: Value) -> Value {
        let (seq, prev) = self.head(SIGNAL_STREAM).await;
        let mut body = json!({
            "v": stozher_core::VERSION,
            "kind": "signal",
            "emitted-at": self.clock.now(),
            "stream": SIGNAL_STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": { "subject": "agent:gateway", "key": self.agent.id.as_str(), "component": "gateway" },
            "signal": {
                "source": "webhook:github",
                "source-ref": "delivery:8f2c",
                "received-at": self.clock.now(),
                "media-type": "application/json",
                "payload-hash": jcs::object_hash(payload).expect("payload hash"),
                "retain-until": "2026-08-25T00:00:00.000Z",
                "sender-verified": true,
                "sender-verification": "hmac-sha256/github-webhook-secret"
            }
        });
        merge(&mut body, overrides);
        self.agent.sign(&body)
    }
}

/// What a subject is asking to be allowed to do, for building an action request (§06 §1.1).
pub struct Ask<'a> {
    /// The key that will sign the effect.
    pub requester: &'a TestKey,
    /// Emitting component.
    pub component: &'a str,
    /// The mandate the effect cites.
    pub mandate_ref: &'a str,
    /// The policy version in force.
    pub policy_version: &'a str,
    /// The weight class.
    pub classification: &'a str,
    /// The action type.
    pub action: &'a str,
    /// The thing acted upon.
    pub target: &'a str,
    /// `object-hash` of the call's arguments.
    pub args_hash: &'a str,
}

/// Deep-merge `overlay` into `base`, so a fixture can override one nested member.
///
/// A `null` in the overlay sets the member to `null` — which is what a fixture testing
/// `prev-hash: null` needs. Removing a member entirely is [`without`].
pub fn merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(existing) if existing.is_object() && value.is_object() => {
                        merge(existing, value);
                    }
                    _ => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

/// Remove a member from an object and re-sign, for "the valid case minus this member" fixtures.
pub fn without(envelope: &Value, member: &str, signer: &TestKey) -> Value {
    let mut map = envelope.as_object().expect("an object").clone();
    map.remove(member);
    map.remove("sig");
    signer.sign(&Value::Object(map))
}

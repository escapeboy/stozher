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
    /// A deterministic keypair. The seed byte is the whole secret, which is fine for a test and
    /// exactly why this crate is `publish = false`.
    #[must_use]
    pub fn new(seed_byte: u8, subject: &str) -> Self {
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
    /// A standing mandate covering `github.get_file` at class `read` and nothing else.
    pub narrow_mandate: String,
    /// A standing mandate carrying a `requests` budget, so a delegated child can exceed it.
    pub budgeted_mandate: String,
    /// A component key, for manifests.
    pub component: TestKey,
    /// `id()` of an appended signal envelope, when the world has one.
    pub signal_id: String,
}

/// Build and bootstrap a world.
pub async fn world() -> World {
    let mut world = world_bare().await;
    world.bootstrap().await;
    world
}

/// Build and bootstrap a world backed by a real database file.
///
/// Tests that need to prove append-only enforcement use this: they open the same file with an
/// ordinary database client and try to rewrite history, which is the only way to show the guarantee
/// lives in the engine rather than in this crate's good manners.
pub async fn world_at(database: &std::path::Path) -> World {
    let mut world = world_bare_at(Some(database)).await;
    world.bootstrap().await;
    world
}

/// Build a world with keys and roots configured but **no policy published** — the state a kernel is
/// in before the ceremony, in which it must refuse every ordinary envelope.
pub async fn world_bare() -> World {
    world_bare_at(None).await
}

async fn world_bare_at(database: Option<&std::path::Path>) -> World {
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

    let store = match database {
        Some(path) => Store::open(path, "kernel:rejections")
            .await
            .expect("a file-backed store"),
        None => Store::open_memory("kernel:rejections")
            .await
            .expect("an in-memory store"),
    };
    let kernel_key = Seed::generate()
        .expect("entropy")
        .derive(ROLE_KERNEL_CHECKPOINT, 0)
        .expect("derivation");
    let kernel = Arc::new(
        Kernel::assemble(config, store, kernel_key, Arc::clone(&clock) as SharedClock)
            .await
            .expect("assembling the kernel"),
    );

    World {
        kernel,
        clock,
        root,
        second_root,
        policy_key,
        agent,
        stranger,
        component: TestKey::new(0x16, "agent:github-proxy"),
        policy_version: String::new(),
        interactive_mandate: String::new(),
        standing_mandate: String::new(),
        narrow_mandate: String::new(),
        budgeted_mandate: String::new(),
        signal_id: String::new(),
    }
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
            Outcome::Rejected { reason, detail, .. } => {
                assert_eq!(reason, expected, "wrong reason code (detail: {detail})")
            }
            Outcome::Accepted(appended) => {
                panic!(
                    "expected {expected}, but the envelope was accepted as {}",
                    appended.id
                )
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
        let document = self
            .policy_key
            .sign(&stozher_kernel::policy::baseline_conservative(
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
                "components": ["gateway", "kernel", "boruna", "github"],
                "actions": ["github.*", "slack.*", "fs.*", "kernel.*", "-"],
                "classes": ["read", "benign", "consequential", "prohibited"],
                "resources": ["*"]
            },
            "nonce": "00000000000000000000000000000002"
        }));
        self.standing_mandate = signed::object_id(&standing).expect("mandate id");
        let envelope = self
            .core_envelope("mandate", json!({ "mandate": standing }))
            .await;
        self.accept(&envelope, &[]).await;

        // A grant that covers exactly one read action, so scope, window and revocation refusals can
        // be provoked without disturbing the wide mandate the other fixtures rely on.
        self.narrow_mandate = self
            .grant_standing(
                "00000000000000000000000000000003",
                json!({
                    "not-after": "2026-09-01T00:00:00.000Z",
                    "scope": {
                        "components": ["gateway"],
                        "actions": ["github.get_file"],
                        "classes": ["read"],
                        "resources": ["repo:acme/backend"]
                    }
                }),
            )
            .await;

        // A grant with a budget, so a delegated child can try to exceed it.
        self.budgeted_mandate = self
            .grant_standing(
                "00000000000000000000000000000004",
                json!({ "budget": { "requests": 10 } }),
            )
            .await;
    }

    /// Publish a signed policy document through the full gated path.
    pub async fn publish_policy(&mut self, document: &Value) {
        let version = document["policy-version"]
            .as_str()
            .expect("policy-version")
            .to_owned();
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
            "reason": reason.map_or(Value::Null, Value::from)
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
        let args_hash = draft["execution"]["args-hash"]
            .as_str()
            .expect("args-hash")
            .to_owned();
        let target = draft["execution"]["target"]
            .as_str()
            .expect("target")
            .to_owned();
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

// -------------------------------------------------------------------------------------------
// fixture builders, one per envelope kind and one per gate variation
// -------------------------------------------------------------------------------------------

impl World {
    /// Grant an additional standing mandate to the agent and return its id.
    pub async fn grant_standing(&self, nonce: &str, overrides: Value) -> String {
        let object = mandate_object(&self.root, &self.agent, nonce, overrides);
        let signed_object = self.root.sign(&object);
        let id = signed::object_id(&signed_object).expect("mandate id");
        let envelope = self
            .core_envelope("mandate", json!({ "mandate": signed_object }))
            .await;
        self.accept(&envelope, &[]).await;
        id
    }

    /// An effect signed by a key other than the mandate's grantee.
    pub async fn effect_as(
        &self,
        signer: &TestKey,
        action: &str,
        class: &str,
        overrides: Value,
    ) -> Value {
        let draft = self.effect(action, class, overrides).await;
        let mut body = draft.as_object().expect("object").clone();
        body.remove("sig");
        let mut body = Value::Object(body);
        merge(
            &mut body,
            json!({ "identity": { "subject": signer.subject, "key": signer.id.as_str() } }),
        );
        signer.sign(&body)
    }

    /// A `cognition` envelope: identity, resource, cost, and nowhere for a prompt to live (§02 §6).
    pub async fn cognition(&self, overrides: Value) -> Value {
        let (seq, prev) = self.head(EFFECT_STREAM).await;
        let mut body = json!({
            "v": stozher_core::VERSION,
            "kind": "cognition",
            "emitted-at": self.clock.now(),
            "stream": EFFECT_STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": { "subject": self.agent.subject, "key": self.agent.id.as_str(), "component": "boruna" },
            "mandate-ref": self.standing_mandate,
            "resource": { "kind": "model", "name": "claude-opus-5" },
            "cost": { "tokens-in": 18422, "tokens-out": 1200, "money-eur": "0.41", "wall-clock-ms": 9310 }
        });
        merge(&mut body, overrides);
        self.agent.sign(&body)
    }

    /// An aggregation record over a folded window of reads (§02 §7).
    pub async fn aggregate(&self, overrides: Value) -> Value {
        let (seq, prev) = self.head(EFFECT_STREAM).await;
        let sample = crypto::sha256_hex(format!("sample-{seq}").as_bytes());
        let mut body = json!({
            "v": stozher_core::VERSION,
            "kind": "aggregate",
            "emitted-at": self.clock.now(),
            "stream": EFFECT_STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": { "subject": self.agent.subject, "key": self.agent.id.as_str(), "component": "gateway" },
            "mandate-ref": self.standing_mandate,
            "policy-version": self.policy_version,
            "classification": "read",
            "window": { "from": "2026-07-26T08:56:00.000Z", "to": "2026-07-26T09:00:00.000Z" },
            "counts": { "total": 412, "by-action": { "github.get_file": 380, "github.list_issues": 32 } },
            "sample-hashes": [sample]
        });
        merge(&mut body, overrides);
        self.agent.sign(&body)
    }

    /// A `revocation` envelope. The envelope **is** the revocation object, so it is signed by the
    /// revoker and its `identity.key` is the revoker's key (§02 §2, §03 §7).
    pub async fn revocation(&self, revoker: &TestKey, target: &str, at: &str) -> Value {
        let (seq, prev) = self.head(CORE_STREAM).await;
        revoker.sign(&json!({
            "v": stozher_core::VERSION,
            "kind": "revocation",
            "emitted-at": self.clock.now(),
            "stream": CORE_STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": { "subject": revoker.subject, "key": revoker.id.as_str(), "component": "kernel" },
            "revokes": target,
            "revoked-at": at,
            "reason": "laptop lost"
        }))
    }

    /// A checkpoint envelope signed by an arbitrary key — for the "not the kernel's key" case.
    pub async fn checkpoint(
        &self,
        signer: &TestKey,
        stream: &str,
        from_seq: u64,
        to_seq: u64,
        overrides: Value,
    ) -> Value {
        let mut body = self
            .checkpoint_body(signer.id.as_str(), stream, from_seq, to_seq)
            .await;
        merge(&mut body, overrides);
        signer.sign(&body)
    }

    /// A checkpoint envelope signed by the kernel's own checkpoint key.
    pub async fn kernel_checkpoint(
        &self,
        stream: &str,
        from_seq: u64,
        to_seq: u64,
        overrides: Value,
    ) -> Value {
        let key = self.ingest().kernel_key();
        let mut body = self
            .checkpoint_body(key.id().as_str(), stream, from_seq, to_seq)
            .await;
        merge(&mut body, overrides);
        key.sign(&body).expect("signing a checkpoint")
    }

    async fn checkpoint_body(
        &self,
        signer_key: &str,
        stream: &str,
        from_seq: u64,
        to_seq: u64,
    ) -> Value {
        let checkpoint_stream = "kernel:checkpoints";
        let (seq, prev) = self.head(checkpoint_stream).await;
        let head_hash = self
            .ingest()
            .store()
            .range(stream, to_seq, to_seq)
            .await
            .expect("reading the attested envelope")
            .first()
            .map(|e| signed::object_id(e).expect("envelope id"))
            .unwrap_or_else(|| "0".repeat(64));
        json!({
            "v": stozher_core::VERSION,
            "kind": "checkpoint",
            "emitted-at": self.clock.now(),
            "stream": checkpoint_stream,
            "seq": seq,
            "prev-hash": prev,
            "identity": { "subject": "agent:kernel", "key": signer_key, "component": "kernel" },
            "checkpoint": {
                "stream": stream,
                "from-seq": from_seq,
                "to-seq": to_seq,
                "head-hash": head_hash,
                "count": to_seq - from_seq + 1,
                "observed-at": self.clock.now()
            }
        })
    }

    /// A `policy-change` envelope plus the payload carrying the document, without submitting it.
    pub async fn policy_change(&self, document: &Value) -> (Value, Vec<Value>) {
        let version = document["policy-version"].as_str().unwrap_or("unversioned");
        let hash = jcs::object_hash(document).expect("policy hash");
        let target = format!("policy:{version}");
        let authorization = self.authorize(&Ask {
            requester: &self.agent,
            component: "kernel",
            mandate_ref: &self.standing_mandate,
            policy_version: &self.policy_version,
            classification: "consequential",
            action: "kernel.publish_policy",
            target: &target,
            args_hash: &hash,
        });
        let envelope = self
            .core_envelope(
                "policy-change",
                json!({
                    "mandate-ref": self.standing_mandate,
                    "policy-version": self.policy_version,
                    "classification": "consequential",
                    "execution": {
                        "action": "kernel.publish_policy",
                        "target": target,
                        "args-hash": hash,
                        "outcome": "applied",
                        "started-at": self.clock.now(),
                        "finished-at": self.clock.now()
                    },
                    "evidence": {
                        "schema": "kernel.publish_policy.v1",
                        "media-type": "application/json",
                        "payload-hash": hash,
                        "retain-until": "2027-07-26T00:00:00.000Z"
                    },
                    "authorization": authorization
                }),
            )
            .await;
        let payload = json!({
            "payload-hash": hash,
            "media-type": "application/json",
            "payload": document
        });
        (envelope, vec![payload])
    }

    /// A `kernel.register_component` envelope plus the manifest payload.
    ///
    /// With `green_conformance`, an applied `kernel.conformance_run` envelope committing to this
    /// manifest's hash is appended first — §08 §3.3's "no green conformance run, no registration"
    /// made concrete: the run is itself an audited claim, not a sentence in a README.
    pub async fn register_component(
        &self,
        manifest: &Value,
        green_conformance: bool,
    ) -> (Value, Vec<Value>) {
        let hash = jcs::object_hash(manifest).expect("manifest hash");
        if green_conformance {
            let run = self
                .effect(
                    "kernel.conformance_run",
                    "benign",
                    json!({ "execution": { "target": format!("manifest:{hash}"), "args-hash": hash } }),
                )
                .await;
            self.accept(&run, &[]).await;
        }
        let target = format!("manifest:{hash}");
        let authorization = self.authorize(&Ask {
            requester: &self.agent,
            component: "gateway",
            mandate_ref: &self.standing_mandate,
            policy_version: &self.policy_version,
            classification: "consequential",
            action: "kernel.register_component",
            target: &target,
            args_hash: &hash,
        });
        let envelope = self
            .effect(
                "kernel.register_component",
                "consequential",
                json!({
                    "execution": { "target": target, "args-hash": hash },
                    "evidence": {
                        "schema": "kernel.register_component.v1",
                        "media-type": "application/json",
                        "payload-hash": hash,
                        "retain-until": "2027-07-26T00:00:00.000Z"
                    },
                    "authorization": authorization
                }),
            )
            .await;
        let payload = json!({
            "payload-hash": hash,
            "media-type": "application/json",
            "payload": manifest
        });
        (envelope, vec![payload])
    }

    /// A gated effect whose approval is signed by `approver` rather than the policy's approver.
    pub async fn gated_effect_approved_by(&self, approver: &TestKey, action: &str) -> Value {
        let draft = self.effect(action, "consequential", json!({})).await;
        let request = self.action_request(&Ask {
            requester: &self.agent,
            component: "gateway",
            mandate_ref: &self.standing_mandate,
            policy_version: &self.policy_version,
            classification: "consequential",
            action,
            target: draft["execution"]["target"].as_str().expect("target"),
            args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
        });
        let decision = self.decide(&request, "approve", None, approver);
        revise(
            &draft,
            json!({ "authorization": { "request": request, "decision": decision } }),
            &self.agent,
        )
    }

    /// A gated effect carrying a decision with an arbitrary verdict, correctly signed and hashed.
    pub async fn gated_effect_with_verdict(&self, verdict: &str, reason: Option<&str>) -> Value {
        let action = "github.create_issue";
        let draft = self.effect(action, "consequential", json!({})).await;
        let request = self.action_request(&Ask {
            requester: &self.agent,
            component: "gateway",
            mandate_ref: &self.standing_mandate,
            policy_version: &self.policy_version,
            classification: "consequential",
            action,
            target: draft["execution"]["target"].as_str().expect("target"),
            args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
        });
        let decision = self.decide(&request, verdict, reason, &self.root);
        revise(
            &draft,
            json!({ "authorization": { "request": request, "decision": decision } }),
            &self.agent,
        )
    }

    /// A gated effect that a human denied and the component did not apply — §06 §4.5's record.
    pub async fn denied_effect(&self, action: &str) -> Value {
        let draft = self
            .effect(
                action,
                "consequential",
                json!({ "execution": { "outcome": "denied" } }),
            )
            .await;
        let request = self.action_request(&Ask {
            requester: &self.agent,
            component: "gateway",
            mandate_ref: &self.standing_mandate,
            policy_version: &self.policy_version,
            classification: "consequential",
            action,
            target: draft["execution"]["target"].as_str().expect("target"),
            args_hash: draft["execution"]["args-hash"].as_str().expect("args-hash"),
        });
        let decision = self.decide(
            &request,
            "deny",
            Some("we don't file public issues on behalf of customers"),
            &self.root,
        );
        revise(
            &draft,
            json!({ "authorization": { "request": request, "decision": decision } }),
            &self.agent,
        )
    }

    /// Re-seal an envelope's `authorization` after a fixture rewrote part of it: recompute
    /// `request-hash` over the request as it now stands and re-sign the decision, then re-sign the
    /// envelope. Without this, every fixture that edits a request or a decision would be refused for
    /// the *wrong* reason — a broken hash or a broken signature — instead of the one under test.
    pub fn reseal_authorization(&self, envelope: &Value) -> Value {
        let request = envelope["authorization"]["request"].clone();
        let mut decision = envelope["authorization"]["decision"]
            .as_object()
            .expect("a decision object")
            .clone();
        decision.remove("sig");
        decision.insert(
            "request-hash".to_owned(),
            Value::from(jcs::object_hash(&request).expect("request hash")),
        );
        let decision = self.root.sign(&Value::Object(decision));
        revise(
            envelope,
            json!({ "authorization": { "request": request, "decision": decision } }),
            &self.agent,
        )
    }

    /// A signed effect suitable for being mutated into an invalid one. Not appended.
    ///
    /// Deliberately synchronous and position-agnostic: callers use it to build a fixture that will be
    /// refused, so its chain position never matters.
    #[must_use]
    pub fn last_effect_draft(&self) -> Value {
        self.agent.sign(&json!({
            "v": stozher_core::VERSION,
            "kind": "effect",
            "emitted-at": NOW,
            "stream": EFFECT_STREAM,
            "seq": 0,
            "prev-hash": Value::Null,
            "identity": { "subject": self.agent.subject, "key": self.agent.id.as_str(), "component": "gateway" },
            "mandate-ref": self.standing_mandate,
            "policy-version": self.policy_version,
            "classification": "read",
            "execution": {
                "action": "github.get_file",
                "target": "repo:acme/backend",
                "args-hash": crypto::sha256_hex(b"draft-args"),
                "outcome": "applied",
                "started-at": NOW,
                "finished-at": NOW
            }
        }))
    }

    /// A valid delegated grant at depth 1, narrowing its parent in every dimension.
    pub async fn delegated_grant(&self) -> Value {
        let object = mandate_object(
            &self.agent,
            &self.stranger,
            "0000000000000000000000000000aaaa",
            json!({
                "mandate-kind": "delegated",
                "parent": self.standing_mandate,
                "grantor": { "subject": self.agent.subject, "key": self.agent.id.as_str(), "role": "agent" },
                "grantee": { "subject": "agent:worker", "key": self.stranger.id.as_str() },
                "max-depth": 1,
                "not-before": "2026-07-26T09:00:00.000Z",
                "not-after": "2026-08-01T00:00:00.000Z",
                "scope": {
                    "components": ["gateway"],
                    "actions": ["github.create_issue"],
                    "classes": ["consequential"],
                    "resources": ["repo:acme/backend"]
                }
            }),
        );
        self.core_envelope("mandate", json!({ "mandate": self.agent.sign(&object) }))
            .await
    }
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

/// Apply `overrides` and **re-sign**, so the fixture is a validly signed envelope that is wrong in
/// exactly one way. Without the re-signing every schema fixture would be refused `sig-invalid`
/// first, and the schema check would never be exercised.
pub fn revise(envelope: &Value, overrides: Value, signer: &TestKey) -> Value {
    let mut map = envelope.as_object().expect("an object").clone();
    map.remove("sig");
    let mut body = Value::Object(map);
    merge(&mut body, overrides);
    signer.sign(&body)
}

/// Apply `overrides` **after** signing, leaving the signature covering different bytes. This is the
/// only way to produce a genuine `sig-invalid`.
pub fn tamper(envelope: &Value, overrides: Value) -> Value {
    let mut body = envelope.clone();
    merge(&mut body, overrides);
    body
}

/// A mandate object, ready to be signed by its grantor.
///
/// `overrides` is merged over a valid standing grant, so a fixture states only what it is changing.
pub fn mandate_object(
    grantor: &TestKey,
    grantee: &TestKey,
    nonce: &str,
    overrides: Value,
) -> Value {
    let mut body = json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "mandate-kind": "standing",
        "grantor": { "subject": grantor.subject, "key": grantor.id.as_str(), "role": "human" },
        "grantee": { "subject": grantee.subject, "key": grantee.id.as_str() },
        "issued-at": NOW,
        "not-before": NOW,
        "not-after": "2026-09-01T00:00:00.000Z",
        "parent": Value::Null,
        "max-depth": 2,
        "scope": {
            "components": ["gateway"],
            "actions": ["github.*"],
            "classes": ["read", "benign", "consequential"],
            "resources": ["repo:acme/backend"]
        },
        "nonce": nonce
    });
    merge(&mut body, overrides);
    body
}

/// A manifest object, ready to be signed by the component's key (§08 §1).
pub fn manifest_object(name: &str, version: &str, overrides: Value) -> Value {
    let mut body = json!({
        "v": stozher_core::VERSION,
        "kind": "manifest",
        "name": name,
        "version": version,
        "subject-class": "tool-proxy",
        "description": "a fixture component",
        "actions": [
            {
                "action": format!("{name}.get_file"),
                "class": "read",
                "evidence-schema": format!("{name}.get_file.v1"),
                "aggregate": { "sampling": "first-and-last", "max-samples": 8 },
                "idempotent": true,
                "target-kind": "repo-path"
            },
            {
                "action": format!("{name}.create_issue"),
                "class": "consequential",
                "evidence-schema": format!("{name}.create_issue.v1"),
                "idempotent": false,
                "target-kind": "repo",
                "degrade": Value::Null
            }
        ],
        "evidence-schemas": {
            format!("{name}.get_file.v1"): {
                "type": "object",
                "required": ["path"],
                "properties": { "path": { "type": "string" } },
                "additionalProperties": false
            },
            format!("{name}.create_issue.v1"): {
                "type": "object",
                "required": ["title"],
                "properties": { "title": { "type": "string" } },
                "additionalProperties": false
            }
        },
        "budget-dimensions": ["requests", "wall-clock-seconds"],
        "durable-objects": [
            {
                "object-type": format!("{name}.ticket"),
                "id-kind": "ticket-id",
                "transitions": [
                    { "transition": "opened",   "from": [],          "to": "open",     "signers": ["agent"] },
                    { "transition": "closed",   "from": ["open"],    "to": "closed",   "signers": ["agent"] },
                    { "transition": "approved", "from": ["open"],    "to": "approved", "signers": ["human"] }
                ]
            }
        ],
        "conformance": { "self-test": format!("{name}.selftest"), "vectors-version": stozher_core::VERSION }
    });
    merge(&mut body, overrides);
    body
}

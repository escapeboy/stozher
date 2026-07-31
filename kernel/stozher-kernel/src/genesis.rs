//! The root key ceremony — the two genesis envelopes of `spec/05 §5.2` and ADR-0006 §2.
//!
//! # Why this is a builder, not a route
//!
//! Genesis is **not** a bypass and this module is not privileged. It builds the same two envelopes
//! any operator could build by hand and hands them back as ordinary `POST /v1/ingest` request
//! bodies; every check in [`crate::ingest`] runs over them. There is no code path here that reaches
//! [`crate::store::Store::append`], and the kernel service never calls this module at all.
//!
//! # Why it is offline
//!
//! Everything here is pure computation over a seed the operator holds. No socket is opened, no
//! configuration is read, and the private seed never leaves the process. That is what lets the
//! ceremony run on the operator's own machine while the kernel runs somewhere else: the operator
//! ships two signed JSON documents and the *public* halves of their keys, and nothing else.
//!
//! # The two envelopes
//!
//! `spec/05 §5.2` wants the first policy at `seq` 1 of the kernel's own stream, gated. A gated
//! effect needs a mandate, and `spec/03 §1` forbids self-grant, so the mandate has to come first:
//!
//! * **`seq` 0 — an interactive mandate.** A named human root grants the bootstrap subject the
//!   authority to act on `kernel.*` for the length of the ceremony, and no longer.
//! * **`seq` 1 — the first policy change**, carrying an approval the root signed over the exact
//!   `object-hash` of the policy document.
//!
//! Both are fully validated. Nothing is pre-installed and nothing is exempt.

use serde_json::{Value, json};
use stozher_core::error::{Error, Result};
use stozher_core::signed::KeyId;
use stozher_core::{crypto, jcs, signed};

use crate::clock;
use crate::keys::{ROLE_AGENT_SUBJECT, ROLE_HUMAN_ROOT, ROLE_ORG_POLICY, Seed};

/// How long the ceremony's interactive mandate lives, in seconds.
///
/// An interactive mandate is a grant for the task at hand (§03 §2). Eight hours is one working day:
/// long enough that a ceremony interrupted by lunch does not have to start over, short enough that
/// the bootstrap subject cannot still be acting next week.
pub const CEREMONY_SECONDS: i64 = 8 * 3_600;

/// How long the first policy's evidence payload is retained, in seconds.
///
/// `evidence-ttl.consequential` in the baseline profile is `P365D`, and a policy change is
/// `consequential`, so this is the ceiling that profile permits (§05 §4).
const POLICY_EVIDENCE_SECONDS: i64 = 365 * 86_400;

/// The public half of a ceremony — everything the operator may safely copy to the server.
#[derive(Debug)]
pub struct Identity {
    /// The human root key, `m/1054'/0'/0'`.
    pub root: KeyId,
    /// The bootstrap agent key, `m/1054'/1'/0'`.
    pub agent: KeyId,
    /// The kernel's checkpoint key, `m/1054'/3'/0'`.
    pub checkpoint: KeyId,
    /// The organization's policy key, `m/1054'/4'/0'`.
    pub policy: KeyId,
}

impl Identity {
    /// Derive every public identifier a seed yields.
    ///
    /// # Errors
    ///
    /// Propagates SLIP-0010 derivation failures.
    pub fn of(seed: &Seed) -> Result<Self> {
        Ok(Self {
            root: seed.derive(ROLE_HUMAN_ROOT, 0)?.id().clone(),
            agent: seed.derive(ROLE_AGENT_SUBJECT, 0)?.id().clone(),
            checkpoint: seed
                .derive(crate::keys::ROLE_KERNEL_CHECKPOINT, 0)?
                .id()
                .clone(),
            policy: seed.derive(ROLE_ORG_POLICY, 0)?.id().clone(),
        })
    }
}

/// What the operator states about the deployment they are founding.
#[derive(Debug, Clone)]
pub struct Ceremony {
    /// The founding root's named human subject, `human:<name>`.
    pub root_subject: String,
    /// The bootstrap subject the root grants to, `agent:<name>`.
    pub agent_subject: String,
    /// The first policy version. Opaque and monotonic; never parsed for meaning (§05 §1).
    pub policy_version: String,
    /// A second enrolled root, if the operator has one. `None` is a supported deployment and a
    /// stated limitation, not a silent one — see [`Genesis::warnings`].
    pub second_root: Option<(String, KeyId)>,
    /// The kernel's own stream.
    pub core_stream: String,
    /// The instant the ceremony is performed at.
    pub now: String,
}

/// The artefacts of a ceremony: two ingest requests and the configuration they presuppose.
#[derive(Debug)]
pub struct Genesis {
    /// `POST /v1/ingest` body for `seq` 0 — the interactive root mandate.
    pub root_mandate: Value,
    /// `POST /v1/ingest` body for `seq` 1 — the first policy change.
    pub first_policy: Value,
    /// The `policy-key` and `roots` members the kernel must already carry when these arrive.
    pub config_fragment: Value,
    /// The signed policy document, so an operator can diff what they published.
    pub policy_document: Value,
    /// `object-hash` of the interactive mandate — what later envelopes cite as `mandate-ref`.
    pub mandate_ref: String,
    /// Findings the operator must read. Never a silent default.
    pub warnings: Vec<String>,
}

/// Build the ceremony's two envelopes from one operator seed.
///
/// The root key, the bootstrap subject key and the organization's policy key are three derivations
/// of the same seed (§01 §6) — one secret to back up, three subjects to recover. An organization
/// that wants them held by different people uses different seeds; nothing here assumes otherwise
/// beyond the convenience of a single-operator start.
///
/// # Errors
///
/// `config-malformed` if a subject is not of the required form, `key-id-malformed`,
/// `kernel-entropy-unavailable`, or any clock or canonicalization failure.
pub fn build(seed: &Seed, ceremony: &Ceremony) -> Result<Genesis> {
    require_subject(&ceremony.root_subject, "human:")?;
    require_subject(&ceremony.agent_subject, "agent:")?;
    if ceremony.policy_version.trim().is_empty() {
        return Err(Error::new(
            "config-malformed",
            "the first policy needs a version",
        ));
    }
    clock::parse_timestamp(&ceremony.now)?;

    let root = seed.derive(ROLE_HUMAN_ROOT, 0)?;
    let agent = seed.derive(ROLE_AGENT_SUBJECT, 0)?;
    let policy_key = seed.derive(ROLE_ORG_POLICY, 0)?;
    let now = ceremony.now.as_str();

    // -- seq 0: a named human grants the bootstrap subject an interactive mandate ---------------
    let mandate = root.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "mandate-kind": "interactive",
        "grantor": { "subject": ceremony.root_subject, "key": root.id().as_str(), "role": "human" },
        "grantee": { "subject": ceremony.agent_subject, "key": agent.id().as_str() },
        "issued-at": now,
        "not-before": now,
        "not-after": clock::shift(now, CEREMONY_SECONDS)?,
        "parent": Value::Null,
        "max-depth": 2,
        // Exactly the ceremony's reach: the kernel's own actions, for the ceremony's own window.
        "scope": {
            "components": ["kernel"],
            "actions": ["kernel.*"],
            "classes": ["read", "benign", "consequential"],
            "resources": ["*"]
        },
        "nonce": nonce()?
    }))?;
    let mandate_ref = signed::object_id(&mandate)?;
    let identity = json!({
        "subject": ceremony.agent_subject,
        "key": agent.id().as_str(),
        "component": "kernel"
    });
    let envelope_zero = agent.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "emitted-at": now,
        "stream": ceremony.core_stream,
        "seq": 0,
        "prev-hash": Value::Null,
        "identity": identity,
        "mandate": mandate
    }))?;

    // -- seq 1: the bootstrap subject publishes the first policy, approved by the root ----------
    let document = policy_key.sign(&crate::policy::baseline_conservative(
        &ceremony.policy_version,
        now,
        &ceremony.root_subject,
    ))?;
    let document_hash = jcs::object_hash(&document)?;
    let target = format!("policy:{}", ceremony.policy_version);
    let request = json!({
        "v": stozher_core::VERSION,
        "kind": "action-request",
        "requested-at": now,
        "subject": ceremony.agent_subject,
        "key": agent.id().as_str(),
        "component": "kernel",
        "mandate-ref": mandate_ref,
        // Nothing is published yet, so the change is evaluated against the version it installs —
        // the one circularity §05 §5.2 permits, and the only one.
        "policy-version": ceremony.policy_version,
        "classification": "consequential",
        "action": "kernel.publish_policy",
        "target": target,
        "args-hash": document_hash,
        "nonce": nonce()?,
        "not-after": clock::shift(now, CEREMONY_SECONDS)?
    });
    // The approval is a real signature by a named human over the exact bytes of the document that
    // takes effect (§05 §5.3). The root and the bootstrap subject are different keys and different
    // subjects, so §06 §5's self-approval rule is satisfied rather than side-stepped.
    let decision = root.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "gate-decision",
        "request-hash": jcs::object_hash(&request)?,
        "decision": "approve",
        "decided-at": now,
        "not-after": clock::shift(now, CEREMONY_SECONDS)?,
        "single-use": true,
        "reason": Value::Null
    }))?;
    let envelope_one = agent.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "policy-change",
        "emitted-at": now,
        "stream": ceremony.core_stream,
        "seq": 1,
        "prev-hash": signed::object_id(&envelope_zero)?,
        "identity": identity,
        "mandate-ref": mandate_ref,
        "policy-version": ceremony.policy_version,
        "classification": "consequential",
        "execution": {
            "action": "kernel.publish_policy",
            "target": target,
            "args-hash": document_hash,
            "outcome": "applied",
            "started-at": now,
            "finished-at": now
        },
        "evidence": {
            "schema": "kernel.publish_policy.v1",
            "media-type": "application/json",
            "payload-hash": document_hash,
            "retain-until": clock::shift(now, POLICY_EVIDENCE_SECONDS)?
        },
        "authorization": { "request": request, "decision": decision }
    }))?;

    let mut roots = vec![json!({
        "subject": ceremony.root_subject,
        "key": root.id().as_str(),
        "enrolled-at": now
    })];
    let mut warnings = Vec::new();
    match &ceremony.second_root {
        Some((subject, key)) => {
            require_subject(subject, "human:")?;
            if key == root.id() {
                return Err(Error::new(
                    "config-malformed",
                    "the second root must be a different key — two names on one key is one root",
                ));
            }
            roots.push(json!({ "subject": subject, "key": key.as_str(), "enrolled-at": now }));
        }
        None => warnings.push(
            "one enrolled root. A human acting directly cannot satisfy `mandate-ref` (spec 03 \
             section 1 forbids self-grant), so changing the root set needs a mandate another human \
             granted — that is, a second enrolled root (ADR-0006 section 3). Enrol one before you \
             need one: with a single root, losing that seed loses the ability to change the root \
             set at all."
                .to_owned(),
        ),
    }

    Ok(Genesis {
        root_mandate: json!({ "envelope": envelope_zero, "payloads": [] }),
        first_policy: json!({
            "envelope": envelope_one,
            "payloads": [ {
                "payload-hash": document_hash,
                "media-type": "application/json",
                "payload": document
            } ]
        }),
        config_fragment: json!({ "policy-key": policy_key.id().as_str(), "roots": roots }),
        policy_document: document,
        mandate_ref,
        warnings,
    })
}

/// A subject is `<class>:<name>` and the class is not decoration: `human:` is what §06 §5 means by
/// "a named human", and a root that is not one cannot be nudged (maxim 3).
fn require_subject(subject: &str, prefix: &str) -> Result<()> {
    if subject.starts_with(prefix) && subject.len() > prefix.len() {
        Ok(())
    } else {
        Err(Error::new(
            "config-malformed",
            format!("{subject:?} must be of the form {prefix}<name>"),
        ))
    }
}

/// 128 bits of entropy, lowercase hex — what §06 §1.1 requires of a request nonce so that an
/// approval of one request is never an approval of an otherwise identical one.
fn nonce() -> Result<String> {
    let mut octets = [0u8; 16];
    getrandom::fill(&mut octets)
        .map_err(|e| Error::new("kernel-entropy-unavailable", e.to_string()))?;
    Ok(hex::encode(octets))
}

/// Where a deployment puts things, so the ceremony can emit a configuration the kernel will accept.
#[derive(Debug, Clone)]
pub struct Deployment<'a> {
    /// Address the service binds.
    pub bind: &'a str,
    /// SQLite path, as the *kernel* will see it.
    pub database: &'a str,
    /// Seed path, as the kernel will see it. Never the operator's seed: that one derives the root
    /// key, and a server that holds it is a server that can sign approvals.
    pub kernel_seed: &'a str,
    /// Where the console answers, for the link inside an approver ping.
    pub console_base_url: &'a str,
    /// Subjects that may talk to the kernel. One fresh token is generated per subject.
    pub callers: &'a [String],
}

/// A caller credential: the subject, the token to hand out, and the digest configuration keeps.
#[derive(Debug)]
pub struct Credential {
    /// The subject a successful credential resolves to.
    pub subject: String,
    /// The bearer token itself. Printed once, never written to the configuration file.
    pub token: String,
}

/// Build a complete kernel configuration around a ceremony's public material.
///
/// Emitting the whole file rather than a fragment removes a JSON processor from the install path,
/// and removes with it the class of mistake where an operator merges a fragment by hand and drops
/// the root they were supposed to enrol.
///
/// # Errors
///
/// `kernel-entropy-unavailable` if the platform RNG fails.
pub fn kernel_config(
    genesis: &Genesis,
    deployment: &Deployment<'_>,
) -> Result<(Value, Vec<Credential>)> {
    let mut credentials = Vec::new();
    let mut callers = Vec::new();
    for subject in deployment.callers {
        let (token, token_sha256) = caller_token()?;
        callers.push(json!({ "subject": subject, "token-sha256": token_sha256 }));
        credentials.push(Credential {
            subject: subject.clone(),
            token,
        });
    }
    let config = json!({
        "bind": deployment.bind,
        "database": deployment.database,
        "kernel-seed": deployment.kernel_seed,
        "policy-key": genesis.config_fragment["policy-key"],
        "roots": genesis.config_fragment["roots"],
        "callers": callers,
        // ADR-0002 allows three channels and this configures none: a single operator watching the
        // console is a legitimate deployment, and the pending page says "no channel is configured"
        // in words rather than rendering an empty column that reads like "delivered".
        "notifications": [],
        "console-base-url": deployment.console_base_url
    });
    Ok((config, credentials))
}

/// What a root is granting, and to whom.
#[derive(Debug, Clone)]
pub struct Grant<'a> {
    /// The granting root's named human subject.
    pub root_subject: &'a str,
    /// The grantee's subject.
    pub grantee_subject: &'a str,
    /// The grantee's key — for a gateway caller, its device key at role `2'` (§10 §1).
    pub grantee_key: &'a KeyId,
    /// How long the grant lives, in days. Bounded by the policy's `max-standing-lifetime`.
    pub days: i64,
    /// Components the grantee may act through.
    pub components: Vec<String>,
    /// Action patterns (§03 §4.1: exact, `*`, or a `x.*` segment prefix).
    pub actions: Vec<String>,
    /// Weight classes.
    pub classes: Vec<String>,
    /// Resources.
    pub resources: Vec<String>,
    /// The instant the grant is issued at.
    pub now: &'a str,
}

/// Sign a standing mandate a component can carry — the grant that lets an agent act at all.
///
/// `spec/03 §1` forbids self-grant, so this cannot be produced by the component that will use it,
/// and it is not produced by the kernel service either: it is signed here, in the root's own
/// process, from the root's own seed. The component is handed the resulting object and publishes it
/// itself at session open (§10 §1.4).
///
/// `classes` deliberately includes `prohibited` in the default the CLI passes. A mandate that does
/// not cover it would make the kernel refuse the emitter's *record of the attempt* — and per
/// ADR-0007 §6 that refusal wedges the emitter's stream. Attempts are the most audit-valuable
/// records in the system (`docs/design/policy-model.md`); policy still hard-blocks the action.
///
/// # Errors
///
/// `config-malformed` for a subject of the wrong form or an empty scope dimension,
/// `kernel-entropy-unavailable`, or a clock or canonicalization failure.
pub fn standing_grant(seed: &Seed, grant: &Grant<'_>) -> Result<Value> {
    require_subject(grant.root_subject, "human:")?;
    if !grant.grantee_subject.contains(':') {
        return Err(Error::new(
            "config-malformed",
            "the grantee subject must be of the form <class>:<name>",
        ));
    }
    if grant.days <= 0 {
        return Err(Error::new(
            "config-malformed",
            "a grant with no lifetime grants nothing",
        ));
    }
    for (name, values) in [
        ("components", &grant.components),
        ("actions", &grant.actions),
        ("classes", &grant.classes),
        ("resources", &grant.resources),
    ] {
        if values.is_empty() {
            // An empty dimension permits nothing, so a grant with one is a grant that silently
            // refuses everything the operator thought they had authorized.
            return Err(Error::new(
                "config-malformed",
                format!("scope.{name} must name at least one pattern"),
            ));
        }
    }
    clock::parse_timestamp(grant.now)?;
    let root = seed.derive(ROLE_HUMAN_ROOT, 0)?;
    if root.id() == grant.grantee_key {
        return Err(Error::new(
            "config-malformed",
            "the root cannot grant to itself — spec 03 section 1 forbids self-grant",
        ));
    }
    root.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "mandate-kind": "standing",
        "grantor": { "subject": grant.root_subject, "key": root.id().as_str(), "role": "human" },
        "grantee": { "subject": grant.grantee_subject, "key": grant.grantee_key.as_str() },
        // A minute of backdating, so a component whose clock is a second behind the operator's does
        // not refuse the mandate it was just handed (§03 §5 checks `not-before` against its own now).
        "issued-at": clock::shift(grant.now, -60)?,
        "not-before": clock::shift(grant.now, -60)?,
        "not-after": clock::shift(grant.now, grant.days * 86_400)?,
        "parent": Value::Null,
        "max-depth": 1,
        "scope": {
            "components": grant.components,
            "actions": grant.actions,
            "classes": grant.classes,
            "resources": grant.resources
        },
        "nonce": nonce()?
    }))
}

/// The bearer credential a caller presents, and the hash configuration stores instead of it.
///
/// The token is generated where it is used and printed once; only its digest is written to a file.
/// A configuration file is copied, diffed and pasted into tickets, and a token in one is a secret in
/// all three places (§09 §8).
///
/// # Errors
///
/// `kernel-entropy-unavailable` if the platform RNG fails.
pub fn caller_token() -> Result<(String, String)> {
    let mut octets = [0u8; 32];
    getrandom::fill(&mut octets)
        .map_err(|e| Error::new("kernel-entropy-unavailable", e.to_string()))?;
    let token = hex::encode(octets);
    let digest = crypto::sha256_hex(token.as_bytes());
    Ok((token, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Seed {
        Seed::generate().expect("entropy")
    }

    fn ceremony() -> Ceremony {
        Ceremony {
            root_subject: "human:ivan".to_owned(),
            agent_subject: "agent:bootstrap".to_owned(),
            policy_version: "2026.07.1".to_owned(),
            second_root: None,
            core_stream: "kernel:core".to_owned(),
            now: "2026-07-26T09:00:00.000Z".to_owned(),
        }
    }

    #[test]
    fn the_ceremony_produces_two_chained_envelopes_and_nothing_else() {
        let genesis = build(&seed(), &ceremony()).unwrap();
        let zero = &genesis.root_mandate["envelope"];
        let one = &genesis.first_policy["envelope"];
        assert_eq!(zero["seq"].as_u64(), Some(0));
        assert!(zero["prev-hash"].is_null());
        assert_eq!(one["seq"].as_u64(), Some(1));
        assert_eq!(
            one["prev-hash"].as_str(),
            Some(signed::object_id(zero).unwrap().as_str()),
            "seq 1 must chain onto seq 0 — the ceremony builds a chain, not two documents"
        );
        assert_eq!(zero["kind"].as_str(), Some("mandate"));
        assert_eq!(one["kind"].as_str(), Some("policy-change"));
    }

    #[test]
    fn every_signature_in_the_ceremony_verifies() {
        let genesis = build(&seed(), &ceremony()).unwrap();
        for envelope in [
            &genesis.root_mandate["envelope"],
            &genesis.first_policy["envelope"],
            &genesis.root_mandate["envelope"]["mandate"],
            &genesis.first_policy["envelope"]["authorization"]["decision"],
            &genesis.policy_document,
        ] {
            signed::verify_signed_object(envelope).expect("a ceremony signature must verify");
        }
    }

    #[test]
    fn the_approval_binds_the_exact_policy_document_that_takes_effect() {
        let genesis = build(&seed(), &ceremony()).unwrap();
        let request = &genesis.first_policy["envelope"]["authorization"]["request"];
        assert_eq!(
            request["args-hash"].as_str(),
            Some(jcs::object_hash(&genesis.policy_document).unwrap().as_str())
        );
        let decision = &genesis.first_policy["envelope"]["authorization"]["decision"];
        assert_eq!(
            decision["request-hash"].as_str(),
            Some(jcs::object_hash(request).unwrap().as_str()),
            "the human's signature must cover the request verbatim"
        );
    }

    #[test]
    fn the_approver_is_never_the_subject_it_approves() {
        let genesis = build(&seed(), &ceremony()).unwrap();
        let authorization = &genesis.first_policy["envelope"]["authorization"];
        assert_ne!(
            authorization["decision"]["sig"]["key"], authorization["request"]["key"],
            "self-approval at genesis would make the ceremony the bypass it exists to avoid"
        );
    }

    #[test]
    fn the_baseline_profile_classifies_the_gateway_s_own_bookkeeping() {
        // ADR-0007 section 4: an org that does not classify `gateway.session_open` would gate its
        // own session opens, and the gateway refuses to start rather than discover that at the
        // first call. A baseline that cannot run the shipped gateway is not a baseline.
        let genesis = build(&seed(), &ceremony()).unwrap();
        let by_action = &genesis.policy_document["classification"]["by-action"];
        assert_eq!(by_action["gateway.session_open"].as_str(), Some("benign"));
        // And the record a gateway writes when a downstream it fronts cannot be reached. Left to
        // `default-unknown` it would be `consequential` — so the one moment the gateway most needs
        // to be able to say something would be the moment it was gated, and a declared server would
        // go missing from `tools/list` with nothing in the audit to say why.
        assert_eq!(
            by_action["gateway.downstream_unavailable"].as_str(),
            Some("benign")
        );
        assert_eq!(
            genesis.policy_document["classification"]["default-unknown"].as_str(),
            Some("consequential"),
            "an unknown tool must park at first call — that is the whole first-call gate"
        );
    }

    #[test]
    fn a_single_root_deployment_is_supported_and_says_what_it_costs() {
        let genesis = build(&seed(), &ceremony()).unwrap();
        assert_eq!(
            genesis.config_fragment["roots"].as_array().unwrap().len(),
            1
        );
        assert!(
            genesis.warnings.iter().any(|w| w.contains("second")),
            "a one-root ceremony must state the prerequisite, not discover it later"
        );

        let mut two = ceremony();
        let other = seed().derive(ROLE_HUMAN_ROOT, 0).unwrap().id().clone();
        two.second_root = Some(("human:mira".to_owned(), other));
        let genesis = build(&seed(), &two).unwrap();
        assert_eq!(
            genesis.config_fragment["roots"].as_array().unwrap().len(),
            2
        );
        assert!(genesis.warnings.is_empty());
    }

    #[test]
    fn a_root_must_be_a_named_human_and_the_bootstrap_subject_an_agent() {
        let mut broken = ceremony();
        broken.root_subject = "the-team".to_owned();
        assert_eq!(
            build(&seed(), &broken).unwrap_err().code(),
            "config-malformed"
        );

        let mut broken = ceremony();
        broken.agent_subject = "human:ivan".to_owned();
        assert_eq!(
            build(&seed(), &broken).unwrap_err().code(),
            "config-malformed"
        );
    }

    #[test]
    fn two_names_on_one_key_is_refused_as_one_root() {
        let seed = seed();
        let mut same = ceremony();
        same.second_root = Some((
            "human:mira".to_owned(),
            seed.derive(ROLE_HUMAN_ROOT, 0).unwrap().id().clone(),
        ));
        let error = build(&seed, &same).unwrap_err();
        assert_eq!(error.code(), "config-malformed");
        assert!(error.detail().contains("one root"), "{}", error.detail());
    }

    fn grant<'a>(seed: &Seed, grantee: &'a KeyId) -> Grant<'a> {
        let _ = seed;
        Grant {
            root_subject: "human:ivan",
            grantee_subject: "agent:claude-code/laptop",
            grantee_key: grantee,
            days: 30,
            components: vec!["gateway".to_owned()],
            actions: vec!["*".to_owned()],
            classes: ["read", "benign", "consequential", "prohibited"]
                .map(str::to_owned)
                .to_vec(),
            resources: vec!["*".to_owned()],
            now: "2026-07-26T09:00:00.000Z",
        }
    }

    #[test]
    fn a_standing_grant_is_signed_by_the_root_and_never_by_its_grantee() {
        let operator = seed();
        let component = seed();
        let grantee = component.derive(2, 0).unwrap().id().clone();
        let mandate = standing_grant(&operator, &grant(&operator, &grantee)).unwrap();
        let signer = signed::verify_signed_object(&mandate).unwrap();
        assert_eq!(&signer, operator.derive(ROLE_HUMAN_ROOT, 0).unwrap().id());
        assert_eq!(mandate["grantee"]["key"].as_str(), Some(grantee.as_str()));
        assert_eq!(mandate["mandate-kind"].as_str(), Some("standing"));
        assert!(mandate["parent"].is_null());
    }

    #[test]
    fn a_grant_covers_prohibited_so_the_attempt_record_is_appendable() {
        // ADR-0006 section 4: an attempted prohibited action is accepted and flagged, because the
        // kernel records effects and does not apply them. A scope that excluded the class would make
        // the kernel refuse that record — and per ADR-0007 section 6 the refusal wedges the stream.
        let operator = seed();
        let grantee = seed().derive(2, 0).unwrap().id().clone();
        let mandate = standing_grant(&operator, &grant(&operator, &grantee)).unwrap();
        let classes = mandate["scope"]["classes"].as_array().unwrap();
        assert!(classes.iter().any(|c| c == "prohibited"));
    }

    #[test]
    fn a_root_cannot_grant_to_itself() {
        let operator = seed();
        let own = operator.derive(ROLE_HUMAN_ROOT, 0).unwrap().id().clone();
        let error = standing_grant(&operator, &grant(&operator, &own)).unwrap_err();
        assert_eq!(error.code(), "config-malformed");
        assert!(error.detail().contains("self-grant"));
    }

    #[test]
    fn an_empty_scope_dimension_is_refused_rather_than_silently_permitting_nothing() {
        let operator = seed();
        let grantee = seed().derive(2, 0).unwrap().id().clone();
        let mut empty = grant(&operator, &grantee);
        empty.actions = Vec::new();
        assert_eq!(
            standing_grant(&operator, &empty).unwrap_err().code(),
            "config-malformed"
        );
    }

    #[test]
    fn the_emitted_configuration_is_one_the_kernel_accepts_and_holds_no_token() {
        let genesis = build(&seed(), &ceremony()).unwrap();
        let callers = ["agent:gateway".to_owned()];
        let (config, credentials) = kernel_config(
            &genesis,
            &Deployment {
                bind: "0.0.0.0:8787",
                database: "/var/lib/stozher/data/stozher.db",
                kernel_seed: "/var/lib/stozher/keys/kernel.seed",
                console_base_url: "http://127.0.0.1:8787",
                callers: &callers,
            },
        )
        .unwrap();

        // The whole point: what the ceremony writes is what the kernel parses, checked here rather
        // than discovered at `docker compose up`.
        let parsed = crate::Config::parse(&config).expect("the ceremony's configuration must load");
        assert_eq!(parsed.roots.len(), 1);
        assert_eq!(parsed.callers.len(), 1);
        assert_eq!(
            parsed.authenticate(&credentials[0].token).unwrap(),
            "agent:gateway"
        );

        let rendered = serde_json::to_string(&config).unwrap();
        assert!(
            !rendered.contains(&credentials[0].token),
            "a configuration file is copied, diffed and pasted into tickets; a token in one is a \
             secret in all three places"
        );
    }

    #[test]
    fn a_caller_token_is_never_its_own_digest() {
        let (token, digest) = caller_token().unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(digest, crypto::sha256_hex(token.as_bytes()));
        assert_ne!(token, digest);
    }
}

//! The conformance harness — `spec/08 §4`, assembled.
//!
//! # Why the run happens against a throwaway kernel
//!
//! §08 §4 requires a run to be deterministic and re-runnable by the operator. A run performed
//! against the organization's live kernel would be neither: it would leave the component's sample
//! envelopes, its eight deliberate refusals and a payload decay in the production audit log, and the
//! second run would start from a different store than the first. Worse, §4.7 requires *deleting*
//! payloads, which is not something a certification exercise may do to a real deployment.
//!
//! So every run builds its own kernel in memory, performs its own root ceremony, mints its own
//! mandate for the component's key, and throws all of it away. Nothing about the organization is
//! consulted and nothing about it is touched. What survives is the result document.
//!
//! # Why the harness does not sign the registration
//!
//! The run produces [`crate::conformance::Run::evidence`] and stops. `spec/08 §3.1` requires a human
//! signature over the manifest hash for registration, and ADR-0012 makes `kernel.conformance_run`
//! root-approved. A harness that submitted its own green result to the live kernel would be a
//! program deciding that a third party's code may run in the organization — which is exactly the
//! decision the product exists to keep with a person.
//!
//! # The clock
//!
//! Fixed, and the instant is handed to the component in every request's `context` (§08 §4.8), so two
//! runs of the same component produce the same bytes and the same signatures. It moves exactly once:
//! §4.4 needs a mandate that has run out, and expiry is judged against an envelope's `emitted-at`,
//! so nothing but a clock move can produce one honestly.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};
use stozher_core::error::{Error, Result};
use stozher_core::signed::KeyId;

use crate::clock::{Clock, FixedClock, SharedClock};
use crate::conformance::{
    GroupResult, Run, check_aggregation, check_decay_independence, check_durable_objects,
    check_negative_cases, check_offline_behaviour, check_per_action_emission, check_vectors,
};
use crate::driver::ComponentDriver;
use crate::genesis::{Ceremony, Grant};
use crate::keys::{ROLE_AGENT_SUBJECT, ROLE_HUMAN_ROOT, ROLE_KERNEL_CHECKPOINT, Seed};
use crate::manifest::Manifest;
use crate::{Config, Ingest, Kernel, Outcome, Store, checkpoint, codes, genesis};

/// The run's own kernel stream.
const CORE_STREAM: &str = "kernel:core";
/// The root the run's ceremony enrols. Named for what it is: nobody's organization has this person.
const ROOT_SUBJECT: &str = "human:conformance-operator";
/// The bootstrap subject the ceremony grants to.
const AGENT_SUBJECT: &str = "agent:conformance";
/// The policy version the run publishes. Opaque, per §05 §1.
const POLICY_VERSION: &str = "conformance.1";
/// How long the run's mandate to the component lives. Longer than the clock move §4.4 performs.
const GRANT_DAYS: i64 = 30;
/// How far the clock moves before §4.4's expired-mandate case. Past the brief mandate, well short of
/// the grant the rest of the run acts under.
const EXPIRY_MOVE_SECONDS: i64 = 60 * 60 * 24 * 2;

fn failed(detail: impl Into<String>) -> Error {
    Error::new(codes::CONFORMANCE_HARNESS_FAILED, detail)
}

/// What a run is performed against.
pub struct Plan<'a> {
    /// The manifest under test. Its hash is what the result commits to.
    pub manifest: &'a Manifest,
    /// The loaded `spec/vectors/` documents §4.1 compares against.
    pub corpus: Vec<Value>,
    /// The instant every envelope in the run is stamped with.
    pub at: String,
}

/// Perform every group of §08 §4 against a component and return the result.
///
/// The result starts red and each group moves it, so a harness that dies halfway leaves a document
/// naming exactly what it did not get to rather than one that reads like a pass.
///
/// # Errors
///
/// [`codes::CONFORMANCE_HARNESS_FAILED`] if the throwaway kernel could not be built, or
/// [`codes::STORE_UNAVAILABLE`] if it stopped answering mid-run. Neither is a statement about the
/// component, and neither is recorded as one — a failed run and a failing component must not look
/// the same to the operator reading the output.
pub async fn run<D: ComponentDriver>(driver: &D, plan: &Plan<'_>) -> Result<Run> {
    let mut result = Run::new(plan.manifest.hash(), plan.manifest.name(), &plan.at);

    let seed = Seed::generate()?;
    let clock = Arc::new(FixedClock::new(&plan.at)?);
    let kernel = bootstrap(&seed, Arc::clone(&clock) as SharedClock, &plan.at).await?;
    let ingest = &kernel.ingest;

    // Who are we certifying? The component names its own subject, key and stream, and the harness
    // mandates that key — so a run needs no prior relationship with the component at all.
    let hello = driver
        .ask(json!({ "case": "hello" }))
        .await
        .map_err(|e| failed(format!("the component would not identify itself: {e}")))?;
    let (subject, key, stream) = introduction(&hello)?;
    // The key answering must be the key the manifest was signed with. Otherwise the run certifies
    // one program's behaviour against another program's declaration, and the registration a human
    // later signs would name a component nobody tested.
    if &key != plan.manifest.component_key() {
        return Err(failed(format!(
            "the component signs as {key} and the manifest was signed by {}",
            plan.manifest.component_key()
        )));
    }
    let mandate_ref = grant_to(&seed, ingest, &subject, &key, &plan.at).await?;
    let context = json!({
        "at": plan.at,
        "mandate-ref": mandate_ref,
        "policy-version": POLICY_VERSION
    });

    result.record("vectors", check_vectors(driver, &plan.corpus).await);

    let samples = collect_samples(
        driver,
        &seed,
        plan.manifest,
        &context,
        (&subject, &key),
        &plan.at,
    )
    .await;
    match samples {
        Ok(samples) => {
            let group = check_per_action_emission(ingest, plan.manifest, &samples).await?;
            result.record("per-action-emission", group);
        }
        Err(detail) => result.record("per-action-emission", GroupResult::Failed { detail }),
    }

    let group = check_aggregation(driver, ingest, plan.manifest, &context).await?;
    result.record("aggregation", group);

    // §4.4 needs a mandate that has run out. Minted before the move so it was valid when granted,
    // used after it so it is expired when cited — which is the only honest way to reach that
    // refusal, a mandate born expired having never been appendable in the first place.
    let brief = brief_grant(&seed, ingest, &subject, &key, &plan.at).await?;
    clock.advance_seconds(EXPIRY_MOVE_SECONDS);
    let late = clock.now();
    let late_context = json!({
        "at": late,
        "mandate-ref": mandate_ref,
        "policy-version": POLICY_VERSION
    });
    let prepared = prepare_negatives(
        &seed,
        plan.manifest,
        &mandate_ref,
        &brief,
        &subject,
        &key,
        &late,
    )?;
    let group = check_negative_cases(driver, ingest, &late_context, &prepared).await?;
    result.record("negative-cases", group);

    match offline_actions(plan.manifest) {
        Some((actions, gated)) => {
            let group =
                check_offline_behaviour(driver, ingest, &late_context, &actions, &gated).await?;
            result.record("offline-behaviour", group);
        }
        None => result.record(
            "offline-behaviour",
            GroupResult::Failed {
                detail: "the manifest declares no consequential action, so the offline profile's \
                         central claim — that a gated action is blocked rather than applied — has \
                         nothing to be demonstrated on"
                    .to_owned(),
            },
        ),
    }

    result.record("durable-objects", check_durable_objects(plan.manifest));
    result.record("decay-independence", decay_group(ingest, &stream).await?);
    Ok(result)
}

/// Build the throwaway kernel: a store, a ceremony, and the first policy.
async fn bootstrap(seed: &Seed, clock: SharedClock, at: &str) -> Result<Kernel> {
    let ceremony = Ceremony {
        root_subject: ROOT_SUBJECT.to_owned(),
        agent_subject: AGENT_SUBJECT.to_owned(),
        policy_version: POLICY_VERSION.to_owned(),
        second_root: None,
        core_stream: CORE_STREAM.to_owned(),
        now: at.to_owned(),
    };
    let built = genesis::build(seed, &ceremony)?;
    let config = Config::parse(&json!({
        "bind": "127.0.0.1:0",
        "database": ":memory:",
        "kernel-seed": "/nonexistent/conformance.seed",
        "policy-key": built.config_fragment["policy-key"],
        "roots": built.config_fragment["roots"],
        "kernel-core-stream": CORE_STREAM,
        "checkpoint-stream": "kernel:checkpoints",
        "rejection-stream": "kernel:rejections",
        "callers": []
    }))?;
    let store = Store::open_memory("kernel:rejections").await?;
    let kernel_key = seed.derive(ROLE_KERNEL_CHECKPOINT, 0)?;
    let kernel = Kernel::assemble(config, store, kernel_key, clock).await?;

    accept(&kernel.ingest, &built.root_mandate).await?;
    accept(&kernel.ingest, &built.first_policy).await?;
    Ok(kernel)
}

/// Submit something the harness built itself. A refusal here is a harness bug, not a verdict.
async fn accept(ingest: &Ingest, body: &Value) -> Result<()> {
    let raw = stozher_core::jcs::canonicalize(body)?;
    match ingest.submit(raw.as_bytes(), Some(AGENT_SUBJECT)).await {
        Outcome::Accepted(_) => Ok(()),
        Outcome::Rejected { reason, detail, .. } => Err(failed(format!(
            "the harness's own envelope was refused {reason}: {detail}"
        ))),
        Outcome::Unavailable(detail) => Err(Error::new(codes::STORE_UNAVAILABLE, detail)),
    }
}

/// The component's `hello`: who it is, what key it signs with, which stream it writes.
fn introduction(hello: &Value) -> Result<(String, KeyId, String)> {
    let subject = hello["subject"]
        .as_str()
        .ok_or_else(|| failed("the component's hello names no subject"))?;
    let key = hello["key"]
        .as_str()
        .ok_or_else(|| failed("the component's hello names no key"))?;
    let stream = hello["stream"]
        .as_str()
        .ok_or_else(|| failed("the component's hello names no stream"))?;
    Ok((subject.to_owned(), KeyId::parse(key)?, stream.to_owned()))
}

/// Mint and append a standing mandate for the component's key.
async fn grant_to(
    seed: &Seed,
    ingest: &Ingest,
    subject: &str,
    key: &KeyId,
    at: &str,
) -> Result<String> {
    let grant = genesis::standing_grant(
        seed,
        &Grant {
            root_subject: ROOT_SUBJECT,
            grantee_subject: subject,
            grantee_key: key,
            days: GRANT_DAYS,
            components: vec!["gateway".to_owned(), "kernel".to_owned()],
            actions: vec!["*".to_owned()],
            // `prohibited` included deliberately: §08 §4.4 requires the *record* of a prohibited
            // attempt to be accepted, and a mandate that did not cover the class would make the
            // kernel refuse the record rather than the action (ADR-0007 §6).
            classes: vec![
                "read".to_owned(),
                "benign".to_owned(),
                "consequential".to_owned(),
                "prohibited".to_owned(),
            ],
            resources: vec!["*".to_owned()],
            now: at,
        },
    )?;
    publish_mandate(seed, ingest, &grant, at).await
}

/// A mandate that expires inside the clock move §4.4 performs.
async fn brief_grant(
    seed: &Seed,
    ingest: &Ingest,
    subject: &str,
    key: &KeyId,
    at: &str,
) -> Result<String> {
    let grant = genesis::standing_grant(
        seed,
        &Grant {
            root_subject: ROOT_SUBJECT,
            grantee_subject: subject,
            grantee_key: key,
            days: 1,
            components: vec!["gateway".to_owned()],
            actions: vec!["*".to_owned()],
            classes: vec!["read".to_owned()],
            resources: vec!["*".to_owned()],
            now: at,
        },
    )?;
    publish_mandate(seed, ingest, &grant, at).await
}

/// Wrap a signed mandate object in an envelope on the run's core stream and append it.
async fn publish_mandate(seed: &Seed, ingest: &Ingest, grant: &Value, at: &str) -> Result<String> {
    let agent = seed.derive(ROLE_AGENT_SUBJECT, 0)?;
    let head = ingest.store().stream_head(CORE_STREAM).await?;
    let (seq, prev) = head.map_or((0, Value::Null), |(seq, id)| (seq + 1, Value::from(id)));
    let envelope = agent.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "mandate",
        "emitted-at": at,
        "stream": CORE_STREAM,
        "seq": seq,
        "prev-hash": prev,
        "identity": { "subject": AGENT_SUBJECT, "key": agent.id().as_str(), "component": "kernel" },
        "mandate": grant
    }))?;
    accept(ingest, &json!({ "envelope": envelope, "payloads": [] })).await?;
    stozher_core::jcs::object_hash(grant)
}

/// One sample per declared action, for §4.2.
///
/// A gated action's sample carries an approval the harness signed, because "passes ingest" includes
/// the gate and a sample exempted from it would certify the component against a weaker bar than
/// production applies. The approval commits to an exact target and args-hash, so the harness names
/// both and the component emits what it was given.
async fn collect_samples<D: ComponentDriver>(
    driver: &D,
    seed: &Seed,
    manifest: &Manifest,
    context: &Value,
    who: (&str, &KeyId),
    at: &str,
) -> std::result::Result<Vec<Value>, String> {
    let mut samples = Vec::new();
    for declared in manifest.document()["actions"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(action) = declared["action"].as_str() else {
            continue;
        };
        let target = "conformance:sample";
        let args_hash =
            stozher_core::crypto::sha256_hex(format!("conformance-sample-{action}").as_bytes());
        let mut request = json!({
            "case": "emit", "context": context, "action": action, "count": 1,
            "target": target, "args-hash": args_hash
        });
        if declared["class"].as_str() == Some("consequential") {
            let mandate_ref = context["mandate-ref"].as_str().unwrap_or_default();
            let approval = authorization(seed, who, mandate_ref, action, target, &args_hash, at)
                .map_err(|e| format!("the harness could not sign an approval for {action}: {e}"))?;
            request["authorization"] = approval;
        }
        let answer = driver
            .ask(request)
            .await
            .map_err(|e| format!("the component could not be driven for {action}: {e}"))?;
        if let Some(error) = answer["error"].as_str() {
            return Err(format!("{action}: the component answered {error}"));
        }
        for submission in answer["submissions"].as_array().into_iter().flatten() {
            samples.push(submission.clone());
        }
    }
    Ok(samples)
}

/// The material only the harness can produce for §4.4: the approvals, and the expired mandate.
///
/// The gated cases need an approval signed by the run's root, and an approval commits to an exact
/// target and args-hash — so the harness chooses both and tells the component what to emit. That is
/// the division §08 §4.8 draws: the harness decides what the attempt *is*, the component signs it,
/// and the kernel decides what happens to it.
fn prepare_negatives(
    seed: &Seed,
    manifest: &Manifest,
    mandate_ref: &str,
    brief: &str,
    subject: &str,
    key: &KeyId,
    at: &str,
) -> Result<BTreeMap<String, Value>> {
    let mut prepared = BTreeMap::new();
    let Some(gated) = consequential_action(manifest) else {
        return Ok(prepared);
    };
    let approved_target = "conformance:approved";
    let args_hash = stozher_core::crypto::sha256_hex(b"conformance-args");
    let authorization = authorization(
        seed,
        (subject, key),
        mandate_ref,
        &gated,
        approved_target,
        &args_hash,
        at,
    )?;

    // The mismatch case: a real approval, and an envelope naming a different target. Both halves
    // have to be genuine, or the kernel would refuse it for the wrong reason and the case would
    // pass while proving nothing about the gate.
    prepared.insert(
        "gate-authorization-action-mismatch".to_owned(),
        json!({
            "authorization": authorization,
            "action": gated,
            "target": "conformance:elsewhere",
            "args-hash": args_hash
        }),
    );
    prepared.insert(
        "gate-authorization-replayed".to_owned(),
        json!({
            "authorization": authorization,
            "action": gated,
            "target": approved_target,
            "args-hash": args_hash
        }),
    );
    prepared.insert(
        "gate-authorization-missing".to_owned(),
        json!({ "action": gated, "target": approved_target }),
    );
    prepared.insert(
        "mandate-expired".to_owned(),
        json!({ "context": { "at": at, "mandate-ref": brief, "policy-version": POLICY_VERSION } }),
    );
    Ok(prepared)
}

/// An approval signed by the run's root, over the exact action the component is told to emit.
///
/// The harness holds the root key and the component holds neither it nor any other approver's, which
/// is the division that makes a run meaningful: nothing the component does can produce an approval,
/// and nothing the harness does can produce the component's signature.
fn authorization(
    seed: &Seed,
    who: (&str, &KeyId),
    mandate_ref: &str,
    action: &str,
    target: &str,
    args_hash: &str,
    at: &str,
) -> Result<Value> {
    let (subject, key) = who;
    let root = seed.derive(ROLE_HUMAN_ROOT, 0)?;
    let not_after = crate::clock::shift(at, 60 * 60 * 24 * GRANT_DAYS)?;
    let request = json!({
        "v": stozher_core::VERSION,
        "kind": "action-request",
        "requested-at": at,
        "subject": subject,
        "key": key.as_str(),
        "component": "gateway",
        "mandate-ref": mandate_ref,
        "policy-version": POLICY_VERSION,
        "classification": "consequential",
        "action": action,
        "target": target,
        "args-hash": args_hash,
        "nonce": stozher_core::crypto::sha256_hex(format!("{action}|{target}").as_bytes())[..32]
            .to_owned(),
        "not-after": not_after
    });
    let decision = root.sign(&json!({
        "v": stozher_core::VERSION,
        "kind": "gate-decision",
        "request-hash": stozher_core::jcs::object_hash(&request)?,
        "decision": "approve",
        "decided-at": at,
        "not-after": not_after,
        "single-use": true,
        "reason": Value::Null
    }))?;
    Ok(json!({ "request": request, "decision": decision }))
}

fn consequential_action(manifest: &Manifest) -> Option<String> {
    manifest.document()["actions"]
        .as_array()?
        .iter()
        .find(|a| a["class"].as_str() == Some("consequential"))?["action"]
        .as_str()
        .map(str::to_owned)
}

/// The actions §4.5 drives offline, and which of them must be blocked.
fn offline_actions(manifest: &Manifest) -> Option<(Vec<String>, String)> {
    let gated = consequential_action(manifest)?;
    let mut actions: Vec<String> = manifest.document()["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| a["class"].as_str() == Some("read"))
        .filter_map(|a| a["action"].as_str().map(str::to_owned))
        .collect();
    actions.push(gated.clone());
    Some((actions, gated))
}

/// §4.7 — decay every payload the run's samples referenced and compare the chain either side.
async fn decay_group(ingest: &Ingest, stream: &str) -> Result<GroupResult> {
    let before = match checkpoint::verify_stream(ingest, stream).await {
        Ok(verified) => verified["head-hash"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        Err(e) => {
            return Ok(GroupResult::Failed {
                detail: format!("{stream} did not verify before decay: {e}"),
            });
        }
    };
    let report = checkpoint::decay_with_checkpoints(ingest, "kernel:checkpoints").await?;
    let (verified, after) = match checkpoint::verify_stream(ingest, stream).await {
        Ok(verified) => (
            true,
            verified["head-hash"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        ),
        Err(_) => (false, String::new()),
    };
    Ok(check_decay_independence(
        &before,
        &after,
        verified,
        report.payloads_deleted,
    ))
}

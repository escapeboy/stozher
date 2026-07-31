//! Conformance run results — `spec/08 §4`, `docs/product-completion-design.md` §4.3.
//!
//! # Why this exists before the checks do
//!
//! `spec/08 §3.3` is "no green conformance run, no registration", and the kernel enforces it by
//! looking for an applied `kernel.conformance_run` envelope committing to the manifest's hash
//! ([`crate::store::Store::conformance_run_is_green`]). **The existence of that envelope is the whole
//! gate.** Nothing downstream re-derives what the run actually checked.
//!
//! That makes a partially-built harness worse than no harness. One that ran two of §08 §4's seven
//! groups and emitted its result would unlock registration on the strength of five checks that never
//! happened — and it would look exactly like a harness that ran them all. The failure would surface
//! as a third-party component in production that nobody had actually certified.
//!
//! So this module is the result document and the rule about it, written **first**: a run is green
//! only when every group §08 §4 requires has an outcome, and a group nobody implemented is
//! [`GroupResult::NotRun`], which is not an outcome. Adding a check later can only move a group from
//! red to green; it can never be forgotten into looking green, because the default is red and the
//! list of groups is fixed here rather than assembled from whatever ran.
//!
//! # What is here
//!
//! All seven groups. Three are decidable from what the kernel and the manifest already hold: §4.6
//! durable objects from the manifest alone, §4.7 decay independence from the head hashes either side
//! of a decay, and §4.2 per-action emission from the component's sample envelopes — which go through
//! the real [`crate::ingest::Ingest`], because "passes ingest" includes the mandate walk, the
//! classification and the payload binding, and a harness with its own opinion about those would be a
//! second implementation to keep correct.
//!
//! The other four need a live component to *drive*, through the self-test its manifest declares
//! (§08 §1.1) over the protocol of §08 §4.8: §4.1 the vector corpus, §4.3 more than `max-samples`
//! real calls, §4.4 eight refusals **the component signs** — which the harness cannot construct,
//! because it must not hold the component's key — and §4.5 the component running with the kernel
//! unreachable. [`crate::driver`] is the transport and [`crate::harness`] is the run. ADR-0016
//! records why the component drives its own refusals rather than lending out a key.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::codes;
use crate::driver::ComponentDriver;

/// The check groups `spec/08 §4` requires, in its order.
///
/// Fixed here rather than derived from what a run happened to execute. A list assembled from
/// completed checks would make "every group passed" true of a run that skipped six of them, which is
/// the whole failure this module exists to prevent.
pub const REQUIRED_GROUPS: [&str; 7] = [
    "vectors",
    "per-action-emission",
    "aggregation",
    "negative-cases",
    "offline-behaviour",
    "durable-objects",
    "decay-independence",
];

/// What one group of §08 §4 concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupResult {
    /// Every check in the group ran and held. `checks` is how many, so a group that asserted
    /// nothing is visible as such rather than reading like a pass.
    Passed {
        /// How many individual assertions the group made.
        checks: u32,
    },
    /// The group ran and the component failed it.
    Failed {
        /// What went wrong, for the operator reading the run.
        detail: String,
    },
    /// The group genuinely does not apply to this component — §08 §4.6's durable objects, for a
    /// manifest that declares none.
    ///
    /// Deliberately distinct from [`Self::Passed`]: "there was nothing to check" and "it was checked
    /// and held" are different claims, and a reader of the run must be able to tell them apart. It
    /// is accepted as satisfying the group only for the groups that can be inapplicable at all.
    NotApplicable {
        /// Why nothing applied.
        why: String,
    },
    /// The group was not executed. **Not an outcome**, and never green.
    NotRun {
        /// Why not — an unimplemented check says so here rather than being absent.
        why: String,
    },
}

impl GroupResult {
    /// Whether this result satisfies its group.
    #[must_use]
    pub fn satisfied(&self) -> bool {
        matches!(self, Self::Passed { .. } | Self::NotApplicable { .. })
    }

    fn as_json(&self) -> Value {
        match self {
            Self::Passed { checks } => json!({ "result": "passed", "checks": checks }),
            Self::Failed { detail } => json!({ "result": "failed", "detail": detail }),
            Self::NotApplicable { why } => json!({ "result": "not-applicable", "why": why }),
            Self::NotRun { why } => json!({ "result": "not-run", "why": why }),
        }
    }
}

/// Groups that may legitimately not apply to a component.
///
/// Only §08 §4.6, and only for a manifest declaring no durable objects. Every other group applies to
/// every component — a component with no `read` action still has to satisfy §4.3 by having none, and
/// saying "not applicable" to the negative cases would be saying the trust boundary is optional.
const MAY_NOT_APPLY: [&str; 1] = ["durable-objects"];

/// The result of one conformance run against one manifest.
#[derive(Debug, Clone)]
pub struct Run {
    /// `object-hash` of the manifest under test — what the envelope commits to.
    pub manifest_hash: String,
    /// The component's name, for the operator reading the run.
    pub component: String,
    /// When the run finished.
    pub at: String,
    /// The outcome per group. Groups absent from this map are [`GroupResult::NotRun`] by default.
    pub groups: BTreeMap<String, GroupResult>,
}

impl Run {
    /// A run in which nothing has been checked yet: every required group is `NotRun`.
    ///
    /// The starting point is red, and a check moves a group out of it. The reverse — starting green
    /// and marking failures — would make a harness that crashed halfway emit a pass.
    #[must_use]
    pub fn new(manifest_hash: &str, component: &str, at: &str) -> Self {
        Self {
            manifest_hash: manifest_hash.to_owned(),
            component: component.to_owned(),
            at: at.to_owned(),
            groups: BTreeMap::new(),
        }
    }

    /// Record a group's outcome.
    ///
    /// # Panics
    ///
    /// If `group` is not one of [`REQUIRED_GROUPS`]. A harness reporting a group nobody asked for is
    /// a harness whose author and this module disagree about what §08 §4 says, and the disagreement
    /// must be loud rather than silently ignored.
    pub fn record(&mut self, group: &str, result: GroupResult) {
        assert!(
            REQUIRED_GROUPS.contains(&group),
            "{group} is not a group spec/08 section 4 defines"
        );
        if let GroupResult::NotApplicable { .. } = result {
            assert!(
                MAY_NOT_APPLY.contains(&group),
                "{group} applies to every component; it cannot be reported as not-applicable"
            );
        }
        self.groups.insert(group.to_owned(), result);
    }

    /// The groups that are not satisfied, in `REQUIRED_GROUPS` order.
    ///
    /// A group nobody recorded counts as unsatisfied, which is the point: silence is not a pass.
    #[must_use]
    pub fn outstanding(&self) -> Vec<&'static str> {
        REQUIRED_GROUPS
            .into_iter()
            .filter(|group| !self.groups.get(*group).is_some_and(GroupResult::satisfied))
            .collect()
    }

    /// Whether this run may be emitted as a green one.
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.outstanding().is_empty()
    }

    /// The run as evidence for a `kernel.conformance_run` envelope (§08 §4).
    ///
    /// Every required group appears whatever happened to it, so "it passed conformance" is an
    /// audited claim a reader can take apart — with a date, a manifest hash, and the outcome of each
    /// group — rather than a sentence in a README.
    #[must_use]
    pub fn evidence(&self) -> Value {
        let absent = GroupResult::NotRun {
            why: "the harness did not execute this group".to_owned(),
        };
        let groups: serde_json::Map<String, Value> = REQUIRED_GROUPS
            .into_iter()
            .map(|group| {
                let result = self.groups.get(group).unwrap_or(&absent);
                (group.to_owned(), result.as_json())
            })
            .collect();
        json!({
            "schema": "kernel.conformance_run.v1",
            "manifest-hash": self.manifest_hash,
            "component": self.component,
            "at": self.at,
            "green": self.is_green(),
            "outstanding": self.outstanding(),
            "groups": groups
        })
    }
}

/// §08 §4.2 — for every declared action type, the component emits a sample envelope that passes
/// ingest.
///
/// The samples come from the component; obtaining them is the driver's problem and checking them is
/// this one's. Submitting them through the real [`crate::ingest::Ingest`] is the point — "passes
/// ingest" is not a property a harness can evaluate by reading an envelope, because it includes the
/// mandate walk, the policy classification and the payload binding, and a harness with its own
/// opinion about those would be a second implementation to keep correct.
///
/// **Coverage is checked first and separately.** A component that submitted one perfect envelope for
/// one action and nothing for the other nine would otherwise pass a group whose whole subject is
/// "for every declared action type" — and it is the *undeclared* half of a manifest that a
/// third-party component is most likely to get wrong.
///
/// # Errors
///
/// [`codes::STORE_UNAVAILABLE`] if the store cannot answer. A store outage is not a component
/// failure and must not be recorded as one.
pub async fn check_per_action_emission(
    ingest: &crate::ingest::Ingest,
    manifest: &crate::manifest::Manifest,
    samples: &[Value],
) -> stozher_core::error::Result<GroupResult> {
    let declared: Vec<String> = manifest.document()["actions"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|a| a["action"].as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if declared.is_empty() {
        return Ok(GroupResult::Failed {
            detail: "the manifest declares no actions, so there is nothing it could conform to"
                .to_owned(),
        });
    }

    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut checks = 0u32;
    for sample in samples {
        let Some(action) = sample["envelope"]["execution"]["action"]
            .as_str()
            .or_else(|| sample["execution"]["action"].as_str())
        else {
            return Ok(GroupResult::Failed {
                detail: "a sample carries no execution.action".to_owned(),
            });
        };
        let action = action.to_owned();

        let raw = match stozher_core::jcs::canonicalize(sample) {
            Ok(raw) => raw,
            Err(e) => {
                return Ok(GroupResult::Failed {
                    detail: format!("the sample for {action} does not canonicalize: {e}"),
                });
            }
        };
        match ingest
            .submit(raw.as_bytes(), Some("agent:conformance"))
            .await
        {
            crate::ingest::Outcome::Accepted(_) => {}
            crate::ingest::Outcome::Rejected { reason, detail, .. } => {
                return Ok(GroupResult::Failed {
                    detail: format!("the sample for {action} was rejected {reason}: {detail}"),
                });
            }
            // The kernel could not answer. Not the component's fault and not recorded as such.
            crate::ingest::Outcome::Unavailable(detail) => {
                return Err(stozher_core::error::Error::new(
                    codes::STORE_UNAVAILABLE,
                    detail,
                ));
            }
        }
        covered.insert(action);
        checks += 1;
    }

    let missing: Vec<&String> = declared
        .iter()
        .filter(|action| !covered.contains(*action))
        .collect();
    if !missing.is_empty() {
        return Ok(GroupResult::Failed {
            detail: format!(
                "no sample was emitted for {} of {} declared actions: {missing:?}",
                missing.len(),
                declared.len()
            ),
        });
    }
    // One assertion per declared action, plus the coverage check itself. A group reporting fewer
    // checks than the manifest has actions would be describing a run that skipped some.
    Ok(GroupResult::Passed { checks: checks + 1 })
}

/// §08 §4.6 — replay a declared transition sequence, and attack it.
///
/// Three claims, and the second and third are the ones that matter: "replaying a transition sequence
/// folds to the expected state; an **illegal transition is rejected**; a `human`-only transition
/// signed by an **agent key is rejected**." A harness that only replayed the happy path would certify
/// a component whose state machine accepts anything — which is the same as no state machine.
///
/// Returns [`GroupResult::NotApplicable`] when the manifest declares no durable objects, and says so
/// rather than passing: "there was nothing to check" and "it was checked" are different claims.
#[must_use]
pub fn check_durable_objects(manifest: &crate::manifest::Manifest) -> GroupResult {
    let objects = manifest.document()["durable-objects"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if objects.is_empty() {
        return GroupResult::NotApplicable {
            why: "the manifest declares no durable objects".to_owned(),
        };
    }

    let mut checks = 0u32;
    for object in &objects {
        let Some(object_type) = object["object-type"].as_str() else {
            return GroupResult::Failed {
                detail: "a declared durable object has no object-type".to_owned(),
            };
        };
        let transitions = object["transitions"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        // 1. Every declared transition is accepted from a state it declares as a `from`, by a signer
        //    role it declares. This is the fold, and on its own it certifies nothing.
        for transition in &transitions {
            let Some(name) = transition["transition"].as_str() else {
                return GroupResult::Failed {
                    detail: format!("{object_type} declares a transition with no name"),
                };
            };
            let from = transition["from"]
                .as_array()
                .and_then(|list| list.first())
                .and_then(Value::as_str)
                .map(str::to_owned);
            let Some(role) = transition["signers"]
                .as_array()
                .and_then(|list| list.first())
                .and_then(Value::as_str)
            else {
                return GroupResult::Failed {
                    detail: format!("{object_type}.{name} declares no signer role"),
                };
            };
            if let Err(e) = manifest.check_transition(object_type, name, role, from.as_deref()) {
                return GroupResult::Failed {
                    detail: format!(
                        "{object_type}.{name} was refused from its own declared state: {e}"
                    ),
                };
            }
            checks += 1;
        }

        // 2. A transition the manifest does not declare is refused. Without this, "the state machine
        //    accepted the sequence" is true of one that accepts everything.
        if manifest
            .check_transition(object_type, "no-such-transition", "agent", None)
            .is_ok()
        {
            return GroupResult::Failed {
                detail: format!("{object_type} accepted a transition it does not declare"),
            };
        }
        checks += 1;

        // 3. A `human`-only transition signed by an agent key is refused. This is the one that
        //    matters to an auditor: it is the boundary between "an agent moved the object" and "a
        //    person did", and a component that blurs it makes every later record unattributable.
        for transition in &transitions {
            let signers: Vec<&str> = transition["signers"]
                .as_array()
                .map(|list| list.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if signers != ["human"] {
                continue;
            }
            let Some(name) = transition["transition"].as_str() else {
                continue;
            };
            let from = transition["from"]
                .as_array()
                .and_then(|list| list.first())
                .and_then(Value::as_str)
                .map(str::to_owned);
            if manifest
                .check_transition(object_type, name, "agent", from.as_deref())
                .is_ok()
            {
                return GroupResult::Failed {
                    detail: format!(
                        "{object_type}.{name} is declared human-only and was accepted from an agent key"
                    ),
                };
            }
            checks += 1;
        }
    }
    GroupResult::Passed { checks }
}

/// §08 §4.7 — after deleting every payload the component's samples referenced, the chain still
/// verifies and produces the **same head hash** (§04 §5.1).
///
/// The property is what makes evidence erasable at all: a deletion that moved a head hash would mean
/// the audit trail and the GDPR obligation were in direct conflict. Asserting only "it still
/// verifies" would miss the half that matters — a rebuilt chain also verifies.
///
/// `before` and `after` are the head hashes either side of decay, and `verified` is whether the chain
/// verified after it. The caller does the deleting, because that is a store operation and this module
/// holds no store.
#[must_use]
pub fn check_decay_independence(
    before: &str,
    after: &str,
    verified: bool,
    payloads_deleted: usize,
) -> GroupResult {
    if payloads_deleted == 0 {
        // Deleting nothing and finding the head unchanged is not evidence of anything. A group that
        // passed here would certify decay independence for a component that never decayed.
        return GroupResult::Failed {
            detail: "no payload was deleted, so nothing about decay was demonstrated".to_owned(),
        };
    }
    if !verified {
        return GroupResult::Failed {
            detail: "the chain did not verify after payload decay".to_owned(),
        };
    }
    if before != after {
        return GroupResult::Failed {
            detail: format!("the head hash moved across decay: {before} became {after}"),
        };
    }
    GroupResult::Passed { checks: 3 }
}

// -- The four groups that need the component to act (§08 §4.8) ------------------------------------

/// What the kernel did with one submission.
///
/// A third variant is deliberately absent: a store outage is not a verdict about a component and is
/// returned as an error from [`submit`] instead, so it can never be recorded as a failure the
/// component caused.
#[derive(Debug, Clone)]
enum Verdict {
    Accepted,
    Rejected { reason: String, detail: String },
}

/// Put one `{envelope, payloads}` request through the real ingest.
///
/// `as_caller` is the identity the submission claims. It is a parameter because §08 §4.4's eighth
/// case is precisely "does claiming an administrative identity change the answer", and a helper that
/// hard-coded one caller could not ask that question.
async fn submit(
    ingest: &crate::ingest::Ingest,
    submission: &Value,
    as_caller: Option<&str>,
) -> stozher_core::error::Result<Verdict> {
    let raw = stozher_core::jcs::canonicalize(submission)?;
    match ingest.submit(raw.as_bytes(), as_caller).await {
        crate::ingest::Outcome::Accepted(_) => Ok(Verdict::Accepted),
        crate::ingest::Outcome::Rejected { reason, detail, .. } => {
            Ok(Verdict::Rejected { reason, detail })
        }
        crate::ingest::Outcome::Unavailable(detail) => Err(stozher_core::error::Error::new(
            codes::STORE_UNAVAILABLE,
            detail,
        )),
    }
}

/// The component's answer, or the reason it is not usable.
fn answer_error(answer: &Value) -> Option<String> {
    answer["error"]
        .as_str()
        .map(|e| format!("the component answered with an error: {e}"))
}

/// The vector kinds §08 §4.1 requires, and the members of each that are **answers** rather than
/// inputs.
///
/// The split is load-bearing. §08 §4.8 requires the harness to strip every expected value before
/// sending a vector, and this table is what "expected value" means per kind — a component that
/// received `canonical` alongside `input-json` could pass §4.1 by echoing its input back, and the
/// group would then certify a component with no canonicalizer at all.
///
/// The five kinds are §4.1's own list: canonicalization, hashing, signing, envelope hashing and
/// chain construction. A component is not asked to reproduce mandate evaluation or the gate
/// algorithm — those are the kernel's, and a component that reimplemented them would be a second
/// authority rather than an emitter.
pub const VECTOR_KINDS: [(&str, &[&str]); 5] = [
    ("jcs", &["canonical", "canonical-sha256"]),
    ("sha256", &["sha256"]),
    ("ed25519", &["signature", "verifies"]),
    (
        "object-hash",
        &[
            "expected-jcs",
            "expected-object-hash",
            "expected-signing-input",
            "expected-signing-input-sha256",
            "expected-signature-valid",
        ],
    ),
    ("chain", &["expected"]),
];

/// §08 §4.1 — the component reproduces every expected value in `spec/vectors/` for the primitives it
/// uses.
///
/// `documents` are the loaded corpus files, each `{ "kind": …, "vectors": [ … ] }`. Kinds outside
/// [`VECTOR_KINDS`] are ignored — §4.1 scopes the group to the primitives a component actually
/// implements — but every kind *in* that table must be present, because a corpus that arrived
/// missing three files would otherwise produce a green group having asked three fewer questions.
///
/// The request carries inputs only. What comes back is compared against the corpus, which the
/// component never sees.
///
/// # Errors
///
/// Never returns `Err`; the signature matches the other driven groups so a caller can treat them
/// uniformly. A driver failure is a conformance failure and is reported as [`GroupResult::Failed`].
pub async fn check_vectors<D: ComponentDriver>(driver: &D, documents: &[Value]) -> GroupResult {
    let mut requests: Vec<Value> = Vec::new();
    let mut expected: BTreeMap<String, Value> = BTreeMap::new();
    let mut present: BTreeSet<&str> = BTreeSet::new();

    for document in documents {
        let Some(kind) = document["kind"].as_str() else {
            continue;
        };
        let Some((kind, answers)) = VECTOR_KINDS.iter().find(|(k, _)| *k == kind) else {
            continue;
        };
        present.insert(kind);
        for vector in document["vectors"].as_array().into_iter().flatten() {
            let Some(name) = vector["name"].as_str() else {
                return GroupResult::Failed {
                    detail: format!("a {kind} vector has no name, so the corpus is unusable"),
                };
            };
            let id = format!("{kind}/{name}");

            // One member is an answer in some vectors and an input in others: an `ed25519` vector
            // carrying a secret key asks the component to *produce* the signature, and one without
            // asks it to verify a signature it must therefore be given. Stripping it from both
            // would ask a component to verify nothing.
            let answers: Vec<&str> = answers
                .iter()
                .copied()
                .filter(|member| {
                    *member != "signature" || *kind != "ed25519" || !vector["secret-key"].is_null()
                })
                .collect();

            // Inputs only: every answer member is removed before the vector is sent.
            let mut request = vector.clone();
            let mut wanted = serde_json::Map::new();
            for member in &answers {
                if let Some(value) = request.as_object_mut().and_then(|v| v.remove(*member)) {
                    wanted.insert((*member).to_owned(), value);
                }
            }
            if wanted.is_empty() {
                // A vector of a required kind carrying none of that kind's answers would be checked
                // against nothing.
                continue;
            }
            request["id"] = json!(id);
            request["kind"] = json!(kind);
            requests.push(request);
            expected.insert(id, Value::Object(wanted));
        }
    }

    let missing: Vec<&str> = VECTOR_KINDS
        .iter()
        .map(|(kind, _)| *kind)
        .filter(|kind| !present.contains(kind))
        .collect();
    if !missing.is_empty() {
        return GroupResult::Failed {
            detail: format!("the corpus handed to the harness has no vectors of kind {missing:?}"),
        };
    }
    if requests.is_empty() {
        return GroupResult::Failed {
            detail: "the corpus contains no vectors, so nothing was asked".to_owned(),
        };
    }

    let answer = match driver
        .ask(json!({ "case": "vectors", "vectors": requests }))
        .await
    {
        Ok(answer) => answer,
        Err(e) => {
            return GroupResult::Failed {
                detail: format!("the component could not be driven: {e}"),
            };
        }
    };
    if let Some(detail) = answer_error(&answer) {
        return GroupResult::Failed { detail };
    }
    let Some(answers) = answer["answers"].as_object() else {
        return GroupResult::Failed {
            detail: "the component's answer carries no `answers` object".to_owned(),
        };
    };

    let mut checks = 0u32;
    for (id, wanted) in &expected {
        let Some(got) = answers.get(id) else {
            return GroupResult::Failed {
                detail: format!("the component did not answer vector {id}"),
            };
        };
        for (member, value) in wanted.as_object().expect("expected answers are an object") {
            // An expected value that is itself an object states its members individually — the
            // chain vectors say `{valid, error, head-hash, count}` for a chain that verifies and
            // `{valid, error, failed-at-seq}` for one that does not, and a component cannot know
            // which shape to answer with. The corpus is authoritative about what must match; a
            // component reporting more than was asked is not a failure.
            let compared: Vec<(String, &Value)> = match value.as_object() {
                Some(members) => members
                    .iter()
                    .map(|(inner, value)| (format!("{member}.{inner}"), value))
                    .collect(),
                None => vec![(member.clone(), value)],
            };
            for (path, expected) in compared {
                let got = path
                    .split('.')
                    .fold(got, |value, step| value.get(step).unwrap_or(&Value::Null));
                if got != expected {
                    return GroupResult::Failed {
                        detail: format!(
                            "vector {id}: {path} was {got} where the corpus says {expected}"
                        ),
                    };
                }
                checks += 1;
            }
        }
    }
    GroupResult::Passed { checks }
}

/// §08 §4.3 — for every `read` action, driving N > `max-samples` calls produces aggregation records
/// that satisfy §02 §7.
///
/// Two of the four assertions are ones the kernel cannot make for itself, which is why they belong
/// here. Ingest validates a record against §02 §7 — count arithmetic, window bound, the sixteen-sample
/// ceiling — but it does not know how many calls the emitter *actually made*, and it has never seen
/// the manifest's own, tighter `max-samples`. So this group asserts what only something standing on
/// both sides can: that the totals describe the N calls the harness asked for, and that the sampling
/// obeys the rule the component itself declared.
///
/// The first assertion is the one that matters most: **something was aggregated at all.** A component
/// that itemized all N reads would satisfy every rule in §02 §7 vacuously — there being no aggregation
/// record to violate them — while doing the exact thing §02 §7 exists to prevent.
///
/// # Errors
///
/// [`codes::STORE_UNAVAILABLE`] if the store cannot answer.
pub async fn check_aggregation<D: ComponentDriver>(
    driver: &D,
    ingest: &crate::ingest::Ingest,
    manifest: &crate::manifest::Manifest,
    context: &Value,
) -> stozher_core::error::Result<GroupResult> {
    let reads: Vec<(String, u64)> = manifest.document()["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| a["class"].as_str() == Some("read"))
        .filter_map(|a| {
            let action = a["action"].as_str()?.to_owned();
            let max = a["aggregate"]["max-samples"].as_u64()?;
            Some((action, max))
        })
        .collect();
    if reads.is_empty() {
        // Not `NotApplicable`: §4.3 applies to every component, and a component with no read action
        // satisfies it by having none. The assertion is that the manifest really declares none —
        // which is a claim about the manifest, and one this group is entitled to make.
        return Ok(GroupResult::Passed { checks: 1 });
    }

    let mut checks = 0u32;
    for (action, max_samples) in reads {
        // N > max-samples, which is the condition §4.3 names. One past the ceiling is the boundary,
        // and the boundary is where an off-by-one in a component's window logic lives.
        let calls = max_samples + 1;
        let answer = match driver
            .ask(json!({ "case": "emit", "context": context, "action": action, "count": calls }))
            .await
        {
            Ok(answer) => answer,
            Err(e) => {
                return Ok(GroupResult::Failed {
                    detail: format!("the component could not be driven for {action}: {e}"),
                });
            }
        };
        if let Some(detail) = answer_error(&answer) {
            return Ok(GroupResult::Failed { detail });
        }
        let submissions: Vec<Value> = answer["submissions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if submissions.is_empty() {
            return Ok(GroupResult::Failed {
                detail: format!("the component emitted nothing for {calls} calls to {action}"),
            });
        }

        let mut aggregates = 0u32;
        let mut folded = 0u64;
        for submission in &submissions {
            match submit(ingest, submission, Some("agent:conformance")).await? {
                Verdict::Accepted => {}
                Verdict::Rejected { reason, detail } => {
                    return Ok(GroupResult::Failed {
                        detail: format!("an aggregation submission for {action} was rejected {reason}: {detail}"),
                    });
                }
            }
            let envelope = &submission["envelope"];
            if envelope["kind"].as_str() != Some("aggregate") {
                continue;
            }
            aggregates += 1;
            folded += envelope["counts"]["by-action"][&action].as_u64().unwrap_or(0);

            // The manifest's own ceiling, which the kernel has never read. §02 §7.4's sixteen is the
            // outer bound; a component that declared eight and sampled twelve has broken the rule an
            // auditor was told to expect.
            let samples = envelope["sample-hashes"]
                .as_array()
                .map_or(0, Vec::len);
            if samples == 0 || samples as u64 > max_samples {
                return Ok(GroupResult::Failed {
                    detail: format!(
                        "{action} sampled {samples} calls against its declared max-samples of {max_samples}"
                    ),
                });
            }
            checks += 1;

            // One window, one mandate, one policy version (§02 §7.2) — and they must be the ones the
            // harness granted for this run, not something the component carried in from elsewhere.
            if envelope["mandate-ref"] != context["mandate-ref"]
                || envelope["policy-version"] != context["policy-version"]
            {
                return Ok(GroupResult::Failed {
                    detail: format!(
                        "the aggregation record for {action} cites a mandate or policy version the run did not grant"
                    ),
                });
            }
            checks += 1;
        }

        if aggregates == 0 {
            return Ok(GroupResult::Failed {
                detail: format!(
                    "{calls} calls to {action} produced no aggregation record: the component itemized a window it declared it would fold"
                ),
            });
        }
        if folded != calls {
            return Ok(GroupResult::Failed {
                detail: format!(
                    "the aggregation records for {action} account for {folded} calls where the harness drove {calls}"
                ),
            });
        }
        checks += 1;
    }
    Ok(GroupResult::Passed { checks })
}

/// The eight refusals of §08 §4.4, by the name the driver protocol uses (§08 §4.8).
///
/// These are **case names, not reason codes**. Two of them expect a code the specification offers as
/// an alternative, and one expects no refusal at all — so a table keyed by the code a case happens to
/// produce would be a table that quietly changed shape when the kernel's wording did.
pub const NEGATIVE_CASES: [&str; 8] = [
    "gate-authorization-missing",
    "gate-authorization-action-mismatch",
    "gate-authorization-replayed",
    "mandate-expired",
    "mandate-root-not-human",
    "prohibited-attempted",
    "cognition-with-evidence",
    "administrative-path",
];

/// What the kernel must do with the last submission of a §4.4 case.
enum Expected {
    /// Refused, with one of these reason codes. More than one where §4.4 itself offers a choice.
    Refused(&'static [&'static str]),
    /// Accepted, and the envelope must record an attempt rather than an application.
    ///
    /// §4.4's `prohibited` case is the one where refusing the *record* would be the wrong answer: the
    /// action was attempted, and deleting the only evidence of the attempt to punish the attempt is
    /// how an audit log becomes a record of what nobody minded.
    AttemptRecorded,
}

fn expected_of(case: &str) -> Expected {
    match case {
        "gate-authorization-missing" | "administrative-path" => {
            Expected::Refused(&["gate-authorization-missing"])
        }
        "gate-authorization-action-mismatch" => {
            Expected::Refused(&["gate-authorization-action-mismatch"])
        }
        "gate-authorization-replayed" => Expected::Refused(&["gate-authorization-replayed"]),
        "mandate-expired" => Expected::Refused(&["mandate-expired"]),
        // §4.4 names both, because a chain that does not reach a human root and one that is too deep
        // to be traced are the same failure of provenance seen from two ends.
        "mandate-root-not-human" => Expected::Refused(&[
            "mandate-root-grantor-not-human",
            "mandate-delegation-depth-exceeded",
        ]),
        "cognition-with-evidence" => Expected::Refused(&["cognition-envelope-has-effect-fields"]),
        "prohibited-attempted" => Expected::AttemptRecorded,
        other => unreachable!("{other} is not one of spec/08 section 4.4's cases"),
    }
}

/// §08 §4.4 — the eight attempts that MUST fail, and the harness MUST fail the component if they
/// succeed.
///
/// # Why the component makes the attempt
///
/// Seven of the eight are envelopes signed by the component's key, and the harness does not have it.
/// It must not: a harness able to sign as the component could forge the very attribution it is
/// certifying. So the component emits them through the self-test its manifest declares (§08 §4.8),
/// the harness submits them, and the kernel's refusal is what is being measured. A component that
/// declines to emit an envelope it knows to be invalid fails this group — well-behaved as that is,
/// the group's subject is the kernel's answer, not the component's taste.
///
/// # The last submission is the one under test
///
/// A case may need to set something up: the replay case must land a valid authorization before it can
/// re-use it. So every submission but the last must be accepted, and the last carries the case's
/// expectation. A setup step that is itself refused fails the case, because whatever the last
/// submission then demonstrated, it was not the condition asked for.
///
/// `prepared` supplies the per-case material only the harness can produce — the authorizations it
/// signed with the run's root key, and the mandate refs it minted for the expired and rootless cases.
/// A case absent from it is asked with no extras.
///
/// # Errors
///
/// [`codes::STORE_UNAVAILABLE`] if the store cannot answer.
pub async fn check_negative_cases<D: ComponentDriver>(
    driver: &D,
    ingest: &crate::ingest::Ingest,
    context: &Value,
    prepared: &BTreeMap<String, Value>,
) -> stozher_core::error::Result<GroupResult> {
    let mut checks = 0u32;
    // Kept so the eighth case can re-submit it under an administrative identity. §06 §2's claim is
    // that no caller identity satisfies a gate, and the only way to test a claim about *identity* is
    // to send the same bytes twice under two of them.
    let mut gated_without_authorization: Option<Value> = None;

    for case in NEGATIVE_CASES {
        let submissions: Vec<Value> = if case == "administrative-path" {
            // Not a component case. §4.4's eighth attempt is against the kernel's own paths, and
            // asking a component to perform it would be asking it to answer for something it does
            // not own.
            let Some(envelope) = gated_without_authorization.clone() else {
                return Ok(GroupResult::Failed {
                    detail: "no gated submission was available to retry under an administrative identity".to_owned(),
                });
            };
            vec![envelope]
        } else {
            // What happens to the last submission, so the component knows whether the position it
            // used was occupied. A refused envelope never took one, and a component that advanced
            // its chain over seven refusals would leave a gap the next real envelope falls into.
            // Telling it here rather than expecting it to know keeps the self-test a mode that
            // emits what it is told (§08 §4.8).
            let expect = match expected_of(case) {
                Expected::Refused(_) => "refused",
                Expected::AttemptRecorded => "accepted",
            };
            let mut request = json!({
                "case": "negative", "negative": case, "context": context, "expect": expect
            });
            if let Some(extras) = prepared.get(case) {
                merge_request(&mut request, extras);
            }
            let answer = match driver.ask(request).await {
                Ok(answer) => answer,
                Err(e) => {
                    return Ok(GroupResult::Failed {
                        detail: format!("the component could not be driven for {case}: {e}"),
                    });
                }
            };
            if let Some(detail) = answer_error(&answer) {
                return Ok(GroupResult::Failed {
                    detail: format!("{case}: {detail}"),
                });
            }
            answer["submissions"].as_array().cloned().unwrap_or_default()
        };

        let Some((last, setup)) = submissions.split_last() else {
            return Ok(GroupResult::Failed {
                detail: format!("the component refused to attempt {case}; §08 §4.4 requires it to"),
            });
        };
        for step in setup {
            match submit(ingest, step, Some("agent:conformance")).await? {
                Verdict::Accepted => {}
                Verdict::Rejected { reason, detail } => {
                    return Ok(GroupResult::Failed {
                        detail: format!("{case}: a setup submission was rejected {reason}: {detail}"),
                    });
                }
            }
        }

        // The eighth case claims an administrative identity; every other submits as the component.
        let caller = if case == "administrative-path" {
            Some("operator:kernel-admin")
        } else {
            Some("agent:conformance")
        };
        let verdict = submit(ingest, last, caller).await?;
        if case == "gate-authorization-missing" {
            gated_without_authorization = Some(last.clone());
        }

        match (expected_of(case), verdict) {
            (Expected::Refused(codes), Verdict::Rejected { reason, .. })
                if codes.contains(&reason.as_str()) =>
            {
                checks += 1;
            }
            (Expected::Refused(codes), Verdict::Rejected { reason, detail }) => {
                return Ok(GroupResult::Failed {
                    detail: format!(
                        "{case} was refused {reason} ({detail}) where §08 §4.4 requires one of {codes:?}"
                    ),
                });
            }
            (Expected::Refused(codes), Verdict::Accepted) => {
                return Ok(GroupResult::Failed {
                    detail: format!("{case} was accepted; §08 §4.4 requires {codes:?}"),
                });
            }
            (Expected::AttemptRecorded, Verdict::Accepted) => {
                let outcome = last["envelope"]["execution"]["outcome"].as_str();
                if outcome != Some("attempted") {
                    return Ok(GroupResult::Failed {
                        detail: format!(
                            "a prohibited action was recorded with outcome {outcome:?}; §08 §4.4 requires \"attempted\""
                        ),
                    });
                }
                checks += 1;
            }
            (Expected::AttemptRecorded, Verdict::Rejected { reason, detail }) => {
                return Ok(GroupResult::Failed {
                    detail: format!(
                        "the record of a prohibited attempt was refused {reason}: {detail}; the attempt happened and must stay in the audit"
                    ),
                });
            }
        }
    }
    Ok(GroupResult::Passed { checks })
}

/// Shallow-merge a prepared case's extras into a driver request.
///
/// Shallow on purpose: the extras a harness prepares are whole members — an `authorization` object,
/// a `context` the case needs in place of the run's. A deep merge would let a half-specified context
/// inherit members from the run's, which is how a case meant to cite an expired mandate quietly ends
/// up citing a live one and passing for the wrong reason.
fn merge_request(request: &mut Value, extras: &Value) {
    let (Some(request), Some(extras)) = (request.as_object_mut(), extras.as_object()) else {
        return;
    };
    for (member, value) in extras {
        request.insert(member.clone(), value.clone());
    }
}

/// §08 §4.5 — with the kernel unreachable, envelopes queue and chain locally, a `consequential`
/// action under a gate rule is blocked rather than applied, and on reconnect the queued chain is
/// accepted **without renumbering**.
///
/// "Without renumbering" is the assertion with teeth. A component that reconnects and re-derives its
/// sequence numbers from the kernel's head produces a chain that verifies and is a different chain
/// from the one it recorded offline — so an offline period could be silently rewritten, which is
/// exactly the window in which an operator would most want the record to be fixed. The harness
/// therefore keeps the numbers the component assigned while it was alone and checks the accepted
/// envelopes still carry them.
///
/// # Errors
///
/// [`codes::STORE_UNAVAILABLE`] if the store cannot answer.
pub async fn check_offline_behaviour<D: ComponentDriver>(
    driver: &D,
    ingest: &crate::ingest::Ingest,
    context: &Value,
    actions: &[String],
    gated: &str,
) -> stozher_core::error::Result<GroupResult> {
    let answer = match driver
        .ask(json!({ "case": "offline", "context": context, "actions": actions, "gated": gated }))
        .await
    {
        Ok(answer) => answer,
        Err(e) => {
            return Ok(GroupResult::Failed {
                detail: format!("the component could not be driven offline: {e}"),
            });
        }
    };
    if let Some(detail) = answer_error(&answer) {
        return Ok(GroupResult::Failed { detail });
    }

    let submissions: Vec<Value> = answer["submissions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if submissions.is_empty() {
        // Nothing queued means nothing was demonstrated. A component that dropped its work while the
        // kernel was away would otherwise pass a group about what it does while the kernel is away.
        return Ok(GroupResult::Failed {
            detail: "the component queued nothing while the kernel was unreachable".to_owned(),
        });
    }

    let blocked: Vec<&str> = answer["blocked"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !blocked.contains(&gated) {
        return Ok(GroupResult::Failed {
            detail: format!(
                "{gated} is consequential under a gate rule and the component did not report blocking it offline"
            ),
        });
    }
    let mut checks = 1u32;

    // The queue chains locally: consecutive sequence numbers, each linked to the one before.
    let mut previous: Option<(u64, String)> = None;
    for submission in &submissions {
        let envelope = &submission["envelope"];
        let Some(seq) = envelope["seq"].as_u64() else {
            return Ok(GroupResult::Failed {
                detail: "a queued envelope carries no seq".to_owned(),
            });
        };
        if let Some((before, id)) = &previous {
            if seq != before + 1 {
                return Ok(GroupResult::Failed {
                    detail: format!("the queued chain jumps from seq {before} to {seq}"),
                });
            }
            if envelope["prev-hash"].as_str() != Some(id.as_str()) {
                return Ok(GroupResult::Failed {
                    detail: format!("the envelope at seq {seq} does not link to the one before it"),
                });
            }
            checks += 1;
        }
        // A gated action must not have been applied while nobody could approve it.
        if envelope["execution"]["action"].as_str() == Some(gated)
            && envelope["execution"]["outcome"].as_str() == Some("applied")
        {
            return Ok(GroupResult::Failed {
                detail: format!("{gated} was applied offline, with no approval it could have had"),
            });
        }
        let id = stozher_core::signed::object_id(envelope)?;
        previous = Some((seq, id));
    }

    // Reconnect. The numbers the component assigned while alone are the numbers that must land, so
    // the assertion is read back out of the store rather than off the request the harness still
    // holds — comparing a local document with itself would pass for a kernel that renumbered
    // everything it was sent.
    let Some(stream) = submissions[0]["envelope"]["stream"].as_str() else {
        return Ok(GroupResult::Failed {
            detail: "a queued envelope carries no stream".to_owned(),
        });
    };
    let before = ingest.store().stream_head(stream).await?;
    let expected_first = before.as_ref().map_or(0, |(seq, _)| seq + 1);
    if submissions[0]["envelope"]["seq"].as_u64() != Some(expected_first) {
        return Ok(GroupResult::Failed {
            detail: format!(
                "the queued chain starts at seq {} where {stream} continues at {expected_first}",
                submissions[0]["envelope"]["seq"]
            ),
        });
    }
    checks += 1;

    for submission in &submissions {
        match submit(ingest, submission, Some("agent:conformance")).await? {
            Verdict::Accepted => {}
            Verdict::Rejected { reason, detail } => {
                return Ok(GroupResult::Failed {
                    detail: format!("a queued envelope was refused on reconnect {reason}: {detail}"),
                });
            }
        }
        checks += 1;
    }

    let (last_seq, last_id) = previous.expect("the queue was checked to be non-empty");
    match ingest.store().stream_head(stream).await? {
        Some((seq, id)) if seq == last_seq && id == last_id => checks += 1,
        landed => {
            return Ok(GroupResult::Failed {
                detail: format!(
                    "the queue was accepted but {stream} now heads at {landed:?} rather than the ({last_seq}, {last_id}) the component recorded offline"
                ),
            });
        }
    }
    Ok(GroupResult::Passed { checks })
}

#[cfg(test)]
mod tests {
    use super::{GroupResult, REQUIRED_GROUPS, Run};

    fn run() -> Run {
        Run::new("a".repeat(64).as_str(), "notes", "2026-07-31T09:00:00.000Z")
    }

    fn pass_everything(run: &mut Run) {
        for group in REQUIRED_GROUPS {
            run.record(group, GroupResult::Passed { checks: 1 });
        }
    }

    #[test]
    fn a_new_run_is_red_and_names_every_group_it_has_not_done() {
        let run = run();
        assert!(!run.is_green());
        assert_eq!(run.outstanding(), REQUIRED_GROUPS.to_vec());
    }

    #[test]
    fn a_run_is_green_only_when_every_group_is_satisfied() {
        let mut run = run();
        pass_everything(&mut run);
        assert!(run.is_green(), "{:?}", run.outstanding());

        // Take any single group away and it is red again. This is the property that makes a
        // half-built harness harmless: it cannot emit the envelope that unlocks registration.
        for group in REQUIRED_GROUPS {
            let mut partial = run.clone();
            partial.record(
                group,
                GroupResult::NotRun {
                    why: "not implemented yet".to_owned(),
                },
            );
            assert!(
                !partial.is_green(),
                "a run with {group} unexecuted reported itself green"
            );
            assert_eq!(partial.outstanding(), vec![group]);
        }
    }

    #[test]
    fn a_failed_group_is_not_satisfied_and_neither_is_an_absent_one() {
        let mut run = run();
        pass_everything(&mut run);
        run.record(
            "negative-cases",
            GroupResult::Failed {
                detail: "a gated action applied with no authorization was accepted".to_owned(),
            },
        );
        assert!(!run.is_green());

        // Absence is the case a harness reaches by crashing, and it must read the same as failure.
        let mut crashed = run.clone();
        crashed.groups.remove("offline-behaviour");
        assert!(crashed.outstanding().contains(&"offline-behaviour"));
    }

    #[test]
    fn only_durable_objects_may_be_reported_as_not_applicable() {
        let mut run = run();
        pass_everything(&mut run);
        run.record(
            "durable-objects",
            GroupResult::NotApplicable {
                why: "the manifest declares none".to_owned(),
            },
        );
        assert!(
            run.is_green(),
            "a component with no durable objects cannot pass"
        );
    }

    #[test]
    #[should_panic(expected = "applies to every component")]
    fn the_negative_cases_cannot_be_declared_inapplicable() {
        // §08 §4.4 is the trust boundary for third-party code. A harness that could opt out of it
        // would certify a component precisely where certification matters most.
        run().record(
            "negative-cases",
            GroupResult::NotApplicable {
                why: "we would rather not".to_owned(),
            },
        );
    }

    #[test]
    #[should_panic(expected = "is not a group")]
    fn a_group_the_specification_does_not_define_is_refused() {
        run().record("vibes", GroupResult::Passed { checks: 1 });
    }

    #[test]
    fn the_evidence_names_every_group_including_the_ones_that_did_not_run() {
        // An operator reading a red run has to be able to see *which* checks are missing. Evidence
        // that listed only what ran would make a two-group run look like a two-group specification.
        let mut run = run();
        run.record("vectors", GroupResult::Passed { checks: 208 });
        let evidence = run.evidence();

        assert_eq!(evidence["green"].as_bool(), Some(false));
        for group in REQUIRED_GROUPS {
            assert!(
                evidence["groups"].get(group).is_some(),
                "the evidence omits {group}"
            );
        }
        assert_eq!(
            evidence["groups"]["vectors"]["result"].as_str(),
            Some("passed")
        );
        assert_eq!(
            evidence["groups"]["offline-behaviour"]["result"].as_str(),
            Some("not-run")
        );
        assert_eq!(
            evidence["outstanding"].as_array().map(Vec::len),
            Some(REQUIRED_GROUPS.len() - 1)
        );
    }

    #[test]
    fn the_group_list_is_the_one_the_specification_fixes() {
        // spec/08 §4 enumerates seven groups. If that list changes, this fails and the harness has
        // to be brought back into line rather than quietly certifying against an older reading.
        assert_eq!(REQUIRED_GROUPS.len(), 7);
        assert!(REQUIRED_GROUPS.contains(&"negative-cases"));
        assert!(REQUIRED_GROUPS.contains(&"offline-behaviour"));
    }
}

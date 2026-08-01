//! Policy documents and the evaluation order — `spec/05-policy-distribution.md`.
//!
//! The kernel is the source of truth for policy; components pull it and enforce locally. Two rules
//! shape this module:
//!
//! * **Fail closed on anything not understood.** A policy document carrying an unknown member is
//!   refused (`schema-unknown-member`), and a kernel with no published policy refuses ingest
//!   (`policy-not-published`). "Failing closed here means failing to start, not failing open"
//!   (§05 §1).
//! * **Evaluation happens in exactly one order** (§05 §3): classification → prohibition → mandate →
//!   gate rule → budget. [`Policy::classify`] and [`Policy::decision_for`] are the first and fourth
//!   steps; the others live in [`crate::ingest`], which calls them in that sequence and no other.

use std::collections::BTreeMap;

use serde_json::Value;
use stozher_core::envelope::CLASSES;
use stozher_core::error::{Error, Result};
use stozher_core::jcs;
use stozher_core::signed::{KeyId, verify_signed_object};

use crate::clock;
use crate::codes;

/// Top-level members of a policy document (§05 §1). Closed: anything else is a rejection.
const MEMBERS: [&str; 16] = [
    "v",
    "kind",
    "policy-version",
    "issued-at",
    "profile",
    "revoke-cached",
    "max-staleness-seconds",
    "checkpoint-interval",
    "aggregate-max-window",
    "classification",
    "gate-rules",
    "evidence-ttl",
    "budgets",
    "delegation",
    "offline",
    "sig",
];

/// The `decision` vocabulary of a `gate-rules` entry (§05 §1). Closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The action proceeds under the mandate alone.
    Allow,
    /// The action requires an approval signature per §06 before it may be applied.
    Gate {
        /// Subjects permitted to approve this scope. Always named humans (§06 §5).
        approvers: Vec<String>,
    },
    /// The action is refused outright by policy.
    Deny,
}

/// A verified, parsed policy document.
#[derive(Debug, Clone)]
pub struct Policy {
    document: Value,
    version: String,
    document_hash: String,
    policy_key: KeyId,
}

/// The request tuple classification is computed for (§03 §4.2).
#[derive(Debug, Clone)]
pub struct ClassifyInput<'a> {
    /// Acting subject.
    pub subject: &'a str,
    /// Action type.
    pub action: &'a str,
    /// Resource acted upon.
    pub resource: &'a str,
    /// The class the component's registered manifest proposes, if it has one (§08 §1.2).
    pub manifest_class: Option<&'a str>,
}

impl Policy {
    /// Parse and verify a policy document.
    ///
    /// The signature is checked against `policy_key`, the organization's enrolled key at role `4'`.
    /// A component "MUST refuse to run with an unverifiable policy rather than falling back to
    /// permissive defaults" (§05 §2.3); so does the kernel.
    ///
    /// # Errors
    ///
    /// `policy-sig-invalid`, `schema-unknown-member`, `schema-missing-member`,
    /// `schema-type-mismatch`, `envelope-version-unsupported`, `envelope-classification-unknown`,
    /// `gate-approver-not-human`, `encoding-bad-duration`, or [`codes::POLICY_OFFLINE_ALLOWS_GATED`].
    pub fn parse(document: &Value, policy_key: &KeyId) -> Result<Self> {
        let map = document
            .as_object()
            .ok_or_else(|| Error::new("schema-type-mismatch", "a policy must be a JSON object"))?;

        for key in map.keys() {
            if !MEMBERS.contains(&key.as_str()) {
                return Err(Error::new("schema-unknown-member", key.clone()));
            }
        }
        for required in MEMBERS {
            if !map.contains_key(required) {
                return Err(Error::new("schema-missing-member", required));
            }
        }
        if map["v"].as_str() != Some(stozher_core::VERSION) {
            return Err(Error::new(
                "envelope-version-unsupported",
                format!("policy v is {:?}", map["v"]),
            ));
        }
        if map["kind"].as_str() != Some("policy") {
            return Err(Error::new(
                "envelope-unknown-kind",
                format!("policy kind is {:?}", map["kind"]),
            ));
        }

        let signer = verify_signed_object(document)
            .map_err(|e| Error::new("policy-sig-invalid", e.detail().to_owned()))?;
        if &signer != policy_key {
            return Err(Error::new(
                "policy-sig-invalid",
                format!("signed by {signer}, expected the enrolled policy key {policy_key}"),
            ));
        }

        let version = string_member(map, "policy-version")?.to_owned();
        if version.is_empty() {
            return Err(Error::new(
                "schema-type-mismatch",
                "policy-version must be a non-empty string",
            ));
        }
        string_member(map, "profile")?;
        clock::parse_timestamp(string_member(map, "issued-at")?)?;
        if !map["revoke-cached"].is_boolean() {
            return Err(Error::new(
                "schema-type-mismatch",
                "revoke-cached must be a boolean",
            ));
        }
        if map["max-staleness-seconds"].as_u64().is_none() {
            return Err(Error::new(
                "schema-type-mismatch",
                "max-staleness-seconds must be a non-negative integer",
            ));
        }
        for duration in ["checkpoint-interval", "aggregate-max-window"] {
            clock::parse_duration_seconds(string_member(map, duration)?)?;
        }

        let policy = Self {
            document: document.clone(),
            version,
            document_hash: jcs::object_hash(document)?,
            policy_key: policy_key.clone(),
        };
        policy.validate_classification()?;
        policy.validate_gate_rules()?;
        policy.validate_retention()?;
        policy.validate_delegation()?;
        policy.validate_offline()?;
        Ok(policy)
    }

    /// The document as received, verbatim — this is what `/v1/policy/{version}` serves.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// The opaque monotonic version string. Never parsed for meaning (§05 §1).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// `object-hash` of the document — what an approval signature over a policy change binds.
    #[must_use]
    pub fn document_hash(&self) -> &str {
        &self.document_hash
    }

    /// The key this document was verified against.
    #[must_use]
    pub fn policy_key(&self) -> &KeyId {
        &self.policy_key
    }

    /// `revoke-cached`: components MUST re-pull before their next `consequential` action (§05 §6).
    #[must_use]
    pub fn revoke_cached(&self) -> bool {
        self.document["revoke-cached"].as_bool().unwrap_or(false)
    }

    /// `max-staleness-seconds` (§05 §6).
    #[must_use]
    pub fn max_staleness_seconds(&self) -> u64 {
        self.document["max-staleness-seconds"].as_u64().unwrap_or(0)
    }

    /// `checkpoint-interval` in seconds (§04 §4.6).
    #[must_use]
    pub fn checkpoint_interval_seconds(&self) -> i64 {
        self.document["checkpoint-interval"]
            .as_str()
            .and_then(|d| clock::parse_duration_seconds(d).ok())
            .unwrap_or(3_600)
    }

    /// `delegation.max-depth`, the deployment's cap on chain length (§03 §5).
    #[must_use]
    pub fn max_delegation_depth(&self) -> u32 {
        u32::try_from(
            self.document["delegation"]["max-depth"]
                .as_u64()
                .unwrap_or(3),
        )
        .unwrap_or(3)
    }

    /// The latest `not-after` a `standing` mandate issued at `issued_at` may carry (§03 §3).
    ///
    /// # Errors
    ///
    /// `encoding-bad-duration` or `encoding-bad-timestamp`.
    pub fn standing_lifetime_ceiling(&self, issued_at: &str) -> Result<String> {
        let lifetime = self.document["delegation"]["max-standing-lifetime"]
            .as_str()
            .unwrap_or("P90D");
        clock::add_duration(issued_at, lifetime)
    }

    /// Step 1 of §05 §3: the effective weight class.
    ///
    /// Order: `reclassify` (most specific first) → `by-action` → the component manifest's proposal →
    /// `default-unknown`. The manifest is a proposal, never a claim of authority (§08 §1.2).
    #[must_use]
    pub fn classify(&self, input: &ClassifyInput<'_>) -> String {
        let classification = &self.document["classification"];
        if let Some(entries) = classification["reclassify"].as_array() {
            let mut best: Option<(u32, &str)> = None;
            for entry in entries {
                if let Some((specificity, class)) = reclassify_match(entry, input) {
                    if best.is_none_or(|(current, _)| specificity > current) {
                        best = Some((specificity, class));
                    }
                }
            }
            if let Some((_, class)) = best {
                return class.to_owned();
            }
        }
        if let Some(class) = classification["by-action"]
            .get(input.action)
            .and_then(Value::as_str)
        {
            return class.to_owned();
        }
        if let Some(class) = input.manifest_class {
            return class.to_owned();
        }
        classification["default-unknown"]
            .as_str()
            .unwrap_or("consequential")
            .to_owned()
    }

    /// Step 4 of §05 §3: the first matching `gate-rules` entry decides.
    ///
    /// A class no rule matches is denied. A policy that forgot a class must not become a policy that
    /// permits it.
    #[must_use]
    pub fn decision_for(&self, class: &str) -> Decision {
        let Some(rules) = self.document["gate-rules"].as_array() else {
            return Decision::Deny;
        };
        for rule in rules {
            let matches = rule["classes"]
                .as_array()
                .is_some_and(|classes| classes.iter().any(|c| c.as_str() == Some(class)));
            if !matches {
                continue;
            }
            return match rule["decision"].as_str() {
                Some("allow") => Decision::Allow,
                Some("gate") => Decision::Gate {
                    approvers: rule["approvers"]
                        .as_array()
                        .map(|list| {
                            list.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                },
                _ => Decision::Deny,
            };
        }
        Decision::Deny
    }

    /// The maximum `evidence.retain-until` an emitter may claim for `class` (§05 §4).
    ///
    /// `None` means class `read` with `P0D`: no payload is stored at all.
    ///
    /// # Errors
    ///
    /// `encoding-bad-duration` or `encoding-bad-timestamp`.
    pub fn retention_ceiling(&self, class: &str, emitted_at: &str) -> Result<String> {
        let ttl = self.document["evidence-ttl"]
            .get(class)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new("schema-missing-member", format!("evidence-ttl.{class}")))?;
        clock::add_duration(emitted_at, ttl)
    }

    /// Whether policy stores payloads for `class` at all (`P0D` means it does not, §05 §4).
    #[must_use]
    pub fn stores_payloads(&self, class: &str) -> bool {
        self.document["evidence-ttl"]
            .get(class)
            .and_then(Value::as_str)
            .and_then(|ttl| clock::parse_duration_seconds(ttl).ok())
            .unwrap_or(0)
            > 0
    }

    /// `aggregate-max-window` in seconds (§02 §7.5).
    #[must_use]
    pub fn aggregate_max_window_seconds(&self) -> i64 {
        self.document["aggregate-max-window"]
            .as_str()
            .and_then(|d| clock::parse_duration_seconds(d).ok())
            .unwrap_or(300)
    }

    fn validate_classification(&self) -> Result<()> {
        let classification = self.document["classification"].as_object().ok_or_else(|| {
            Error::new("schema-type-mismatch", "classification must be an object")
        })?;
        for key in classification.keys() {
            if !["default-unknown", "by-action", "reclassify"].contains(&key.as_str()) {
                return Err(Error::new(
                    "schema-unknown-member",
                    format!("classification.{key}"),
                ));
            }
        }
        let default = classification
            .get("default-unknown")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new("schema-missing-member", "classification.default-unknown"))?;
        require_class(default)?;
        let by_action = classification
            .get("by-action")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                Error::new(
                    "schema-type-mismatch",
                    "classification.by-action must be an object",
                )
            })?;
        for class in by_action.values() {
            require_class(class.as_str().unwrap_or_default())?;
        }
        let reclassify = classification
            .get("reclassify")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Error::new(
                    "schema-type-mismatch",
                    "classification.reclassify must be an array",
                )
            })?;
        for entry in reclassify {
            let map = entry.as_object().ok_or_else(|| {
                Error::new(
                    "schema-type-mismatch",
                    "a reclassify entry must be an object",
                )
            })?;
            for key in map.keys() {
                if !["subject", "action", "resource", "class", "reason"].contains(&key.as_str()) {
                    return Err(Error::new(
                        "schema-unknown-member",
                        format!("classification.reclassify[].{key}"),
                    ));
                }
            }
            for required in ["subject", "action", "class"] {
                if !map.contains_key(required) {
                    return Err(Error::new(
                        "schema-missing-member",
                        format!("classification.reclassify[].{required}"),
                    ));
                }
            }
            require_class(map["class"].as_str().unwrap_or_default())?;
        }
        Ok(())
    }

    fn validate_gate_rules(&self) -> Result<()> {
        let rules = self.document["gate-rules"]
            .as_array()
            .ok_or_else(|| Error::new("schema-type-mismatch", "gate-rules must be an array"))?;
        for rule in rules {
            let map = rule.as_object().ok_or_else(|| {
                Error::new("schema-type-mismatch", "a gate rule must be an object")
            })?;
            for key in map.keys() {
                if !["classes", "decision", "approvers"].contains(&key.as_str()) {
                    return Err(Error::new(
                        "schema-unknown-member",
                        format!("gate-rules[].{key}"),
                    ));
                }
            }
            let classes = map
                .get("classes")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::new("schema-missing-member", "gate-rules[].classes"))?;
            for class in classes {
                require_class(class.as_str().unwrap_or_default())?;
            }
            match map.get("decision").and_then(Value::as_str) {
                Some("allow" | "deny") => {
                    if map.contains_key("approvers") {
                        return Err(Error::new(
                            "schema-unknown-member",
                            "gate-rules[].approvers is meaningful only for decision gate",
                        ));
                    }
                }
                Some("gate") => {
                    let approvers =
                        map.get("approvers")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                Error::new("schema-missing-member", "gate-rules[].approvers")
                            })?;
                    if approvers.is_empty() {
                        // A gate with nobody able to sign is a gate that can never open, which
                        // reads as "blocked" but is authored as "gated". Refuse the ambiguity.
                        return Err(Error::new(
                            "gate-approver-not-permitted",
                            "a gate rule names no approver",
                        ));
                    }
                    for approver in approvers {
                        let subject = approver.as_str().ok_or_else(|| {
                            Error::new("schema-type-mismatch", "an approver must be a string")
                        })?;
                        // §06 §5: a named human, never a group, a role or a rotation.
                        if !subject.starts_with("human:") || subject.len() <= "human:".len() {
                            return Err(Error::new(
                                "gate-approver-not-human",
                                format!("approver {subject:?} is not a named human"),
                            ));
                        }
                    }
                }
                other => {
                    return Err(Error::new(
                        "schema-type-mismatch",
                        format!("gate-rules[].decision is {other:?}"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_retention(&self) -> Result<()> {
        let ttl = self.document["evidence-ttl"]
            .as_object()
            .ok_or_else(|| Error::new("schema-type-mismatch", "evidence-ttl must be an object"))?;
        for key in ttl.keys() {
            require_class(key)?;
        }
        for class in CLASSES {
            let duration = ttl.get(class).and_then(Value::as_str).ok_or_else(|| {
                Error::new("schema-missing-member", format!("evidence-ttl.{class}"))
            })?;
            clock::parse_duration_seconds(duration)?;
        }
        Ok(())
    }

    fn validate_delegation(&self) -> Result<()> {
        let delegation = self.document["delegation"]
            .as_object()
            .ok_or_else(|| Error::new("schema-type-mismatch", "delegation must be an object"))?;
        for key in delegation.keys() {
            if !["max-depth", "max-standing-lifetime"].contains(&key.as_str()) {
                return Err(Error::new(
                    "schema-unknown-member",
                    format!("delegation.{key}"),
                ));
            }
        }
        if delegation
            .get("max-depth")
            .and_then(Value::as_u64)
            .is_none()
        {
            return Err(Error::new("schema-missing-member", "delegation.max-depth"));
        }
        let lifetime = delegation
            .get("max-standing-lifetime")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::new("schema-missing-member", "delegation.max-standing-lifetime")
            })?;
        clock::parse_duration_seconds(lifetime)?;
        Ok(())
    }

    fn validate_offline(&self) -> Result<()> {
        let offline = self.document["offline"]
            .as_object()
            .ok_or_else(|| Error::new("schema-type-mismatch", "offline must be an object"))?;
        for (class, behaviour) in offline {
            require_class(class)?;
            if !matches!(behaviour.as_str(), Some("allow" | "block" | "degrade")) {
                return Err(Error::new(
                    "schema-type-mismatch",
                    format!("offline.{class} is {behaviour}"),
                ));
            }
        }
        // §05 §7: `consequential` MUST NOT be offline-allowed while a gate rule applies to it — an
        // action requiring a human signature cannot acquire one offline.
        let consequential_offline = offline.get("consequential").and_then(Value::as_str);
        if consequential_offline == Some("allow")
            && matches!(self.decision_for("consequential"), Decision::Gate { .. })
        {
            return Err(Error::new(
                codes::POLICY_OFFLINE_ALLOWS_GATED,
                "offline.consequential is allow while a gate rule applies to consequential",
            ));
        }
        Ok(())
    }
}

/// Score how specifically a `reclassify` entry matches, or `None` if it does not (§05 §3 step 1).
/// What an exact match on one dimension is worth; a `<prefix>.*` match is worth half (§05 §3.1).
const DIMENSION_WEIGHT: u32 = 2;

fn reclassify_match<'a>(entry: &'a Value, input: &ClassifyInput<'_>) -> Option<(u32, &'a str)> {
    let mut specificity = 0;
    let dimension = |pattern: Option<&str>, value: &str, weight: u32, score: &mut u32| -> bool {
        match pattern {
            None => true,
            Some("*") => true,
            Some(p) if p == value => {
                *score += weight;
                true
            }
            Some(p) => match p.strip_suffix(".*") {
                Some(prefix) => {
                    let matched = value.len() > prefix.len()
                        && value.starts_with(prefix)
                        && value.as_bytes()[prefix.len()] == b'.';
                    if matched {
                        *score += weight / 2;
                    }
                    matched
                }
                None => false,
            },
        }
    };

    // Every dimension scores the same (§05 §3.1): exact 2, segment prefix 1, wildcard or absent 0.
    // Weighting them unequally would decide that naming a resource is narrower than naming an
    // action, which is true in some deployments and false in others — so the tie-break is "how many
    // dimensions did you name", which is what the person writing the policy means by specific.
    for (pattern, value) in [
        (entry["subject"].as_str(), input.subject),
        (entry["action"].as_str(), input.action),
        (
            entry.get("resource").and_then(Value::as_str),
            input.resource,
        ),
    ] {
        if !dimension(pattern, value, DIMENSION_WEIGHT, &mut specificity) {
            return None;
        }
    }
    entry["class"].as_str().map(|class| (specificity, class))
}

fn string_member<'a>(map: &'a serde_json::Map<String, Value>, name: &str) -> Result<&'a str> {
    map.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("schema-missing-member", name.to_owned()))
}

fn require_class(class: &str) -> Result<()> {
    if CLASSES.contains(&class) {
        Ok(())
    } else {
        Err(Error::new(
            "envelope-classification-unknown",
            format!("{class:?}"),
        ))
    }
}

/// Weight order, so "weaker than the effective policy's class" is a comparison and not an opinion.
#[must_use]
pub fn class_weight(class: &str) -> u8 {
    match class {
        "read" => 0,
        "benign" => 1,
        "consequential" => 2,
        "prohibited" => 3,
        _ => u8::MAX,
    }
}

/// Build the baseline conservative profile, signed by `policy_key` (§05 §1, policy-model Tier 1).
///
/// Used by tests and by the bootstrap path; the values are the specification's documented defaults.
#[must_use]
pub fn baseline_conservative(version: &str, issued_at: &str, approver: &str) -> Value {
    let mut by_action = BTreeMap::new();
    // The action classifications of §05 §1's worked document.
    by_action.insert("github.get_file", "read");
    by_action.insert("github.list_issues", "read");
    by_action.insert("github.create_issue", "consequential");
    by_action.insert("github.delete_repo", "prohibited");
    by_action.insert("slack.post_message", "consequential");
    by_action.insert("fs.read_file", "read");
    by_action.insert("kernel.conformance_run", "benign");
    by_action.insert("kernel.publish_policy", "consequential");
    by_action.insert("kernel.register_component", "consequential");
    by_action.insert("kernel.enroll_root", "consequential");
    by_action.insert("kernel.retire_root", "consequential");
    by_action.insert("kernel.erase_payload", "consequential");
    by_action.insert("kernel.seed_catalog_entry", "consequential");
    // The gateway's own bookkeeping. §10 §1.6 requires `gateway.session_open` to be `benign`, but
    // `default-unknown` here is `consequential`, so a profile that stayed silent would gate the
    // gateway's own session opens — and the gateway refuses to start rather than meet that at the
    // first call (ADR-0007 §4). A shipped baseline that cannot run the shipped gateway is not a
    // baseline, so the classification lives here rather than in every operator's first edit.
    by_action.insert("gateway.session_open", "benign");
    // Same reasoning, for the record a gateway writes when a downstream it was configured to front
    // cannot be reached. Left to `default-unknown` it would be `consequential`, so the one moment
    // the gateway most needs to be able to say something is the moment it would be gated — and the
    // failure that produces is the original defect exactly: a declared server silently absent from
    // `tools/list` with nothing in the audit to say so.
    by_action.insert("gateway.downstream_unavailable", "benign");
    serde_json::json!({
        "v": stozher_core::VERSION,
        "kind": "policy",
        "policy-version": version,
        "issued-at": issued_at,
        "profile": "baseline-conservative",
        "revoke-cached": false,
        "max-staleness-seconds": 300,
        "checkpoint-interval": "PT1H",
        "aggregate-max-window": "PT5M",
        "classification": {
            "default-unknown": "consequential",
            "by-action": by_action,
            "reclassify": []
        },
        "gate-rules": [
            { "classes": ["prohibited"], "decision": "deny" },
            { "classes": ["consequential"], "decision": "gate", "approvers": [approver] },
            { "classes": ["read", "benign"], "decision": "allow" }
        ],
        "evidence-ttl": {
            "read": "P0D", "benign": "P30D", "consequential": "P365D", "prohibited": "P3650D"
        },
        "budgets": { "defaults": { "requests": 10000, "money-eur": "50.00" } },
        "delegation": { "max-depth": 3, "max-standing-lifetime": "P90D" },
        "offline": { "read": "allow", "benign": "allow", "consequential": "block", "prohibited": "block" }
    })
}

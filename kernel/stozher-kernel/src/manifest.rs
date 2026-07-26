//! Extension manifests — `spec/08-extension-manifest.md`.
//!
//! A manifest is "declare your effects and your folds". The kernel uses it for two things:
//!
//! * at **registration**, as the object a human's approval signature binds to (§08 §3.1), validated
//!   in full here;
//! * at **ingest**, as the component's *proposed* baseline class and its durable-object transition
//!   table. The proposal never wins over org policy (§08 §1.2), and a `["human"]`-only transition is
//!   refused from an agent key regardless of that agent's mandate (§08 §2) — which is how "promotion
//!   requires a person" becomes structural rather than procedural.

use serde_json::Value;
use stozher_core::envelope::CLASSES;
use stozher_core::error::{Error, Result};
use stozher_core::jcs;
use stozher_core::signed::{KeyId, verify_signed_object};

use crate::codes::MANIFEST_MALFORMED;

const MEMBERS: [&str; 11] = [
    "v",
    "kind",
    "name",
    "version",
    "subject-class",
    "description",
    "actions",
    "evidence-schemas",
    "budget-dimensions",
    "durable-objects",
    "conformance",
];

const SUBJECT_CLASSES: [&str; 6] = [
    "tool-proxy",
    "browser-agent",
    "executor",
    "memory",
    "orchestrator-bridge",
    "kernel",
];

const ACTION_MEMBERS: [&str; 7] = [
    "action",
    "class",
    "evidence-schema",
    "aggregate",
    "idempotent",
    "target-kind",
    "degrade",
];

/// The budget dimensions a manifest may declare (§03 §4.3).
const BUDGET_DIMENSIONS: [&str; 5] = [
    "requests",
    "tokens",
    "tokens-in",
    "tokens-out",
    "wall-clock-seconds",
];

/// A validated manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    document: Value,
    name: String,
    version: String,
    hash: String,
    component_key: KeyId,
}

impl Manifest {
    /// Validate a manifest object in full (§08 §1).
    ///
    /// # Errors
    ///
    /// `manifest-action-namespace`, `manifest-evidence-schema-missing`,
    /// `manifest-prohibited-degrade`, `sig-invalid`, `schema-unknown-member`,
    /// `schema-missing-member`, `schema-type-mismatch`, `envelope-classification-unknown`, or
    /// [`MANIFEST_MALFORMED`].
    pub fn parse(document: &Value) -> Result<Self> {
        let map = document
            .as_object()
            .ok_or_else(|| Error::new(MANIFEST_MALFORMED, "a manifest must be a JSON object"))?;
        for key in map.keys() {
            if key != "sig" && !MEMBERS.contains(&key.as_str()) {
                return Err(Error::new("schema-unknown-member", key.clone()));
            }
        }
        for required in MEMBERS {
            if required == "description" {
                continue;
            }
            if !map.contains_key(required) {
                return Err(Error::new("schema-missing-member", required));
            }
        }
        if map["v"].as_str() != Some(stozher_core::VERSION) {
            return Err(Error::new(
                "envelope-version-unsupported",
                format!("manifest v is {}", map["v"]),
            ));
        }
        if map["kind"].as_str() != Some("manifest") {
            return Err(Error::new(
                "envelope-unknown-kind",
                format!("manifest kind is {}", map["kind"]),
            ));
        }

        let component_key = verify_signed_object(document)?;

        let name = map["name"]
            .as_str()
            .ok_or_else(|| Error::new("schema-type-mismatch", "name must be a string"))?;
        if !is_component_name(name) {
            return Err(Error::new(
                MANIFEST_MALFORMED,
                format!("name {name:?} does not match ^[a-z][a-z0-9-]{{1,31}}$"),
            ));
        }
        let version = map["version"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                Error::new("schema-type-mismatch", "version must be a non-empty string")
            })?;
        let subject_class = map["subject-class"].as_str().unwrap_or_default();
        if !SUBJECT_CLASSES.contains(&subject_class) {
            return Err(Error::new(
                MANIFEST_MALFORMED,
                format!("subject-class {subject_class:?} is not one of §08 §1.1"),
            ));
        }

        let schemas = map["evidence-schemas"].as_object().ok_or_else(|| {
            Error::new("schema-type-mismatch", "evidence-schemas must be an object")
        })?;
        for (id, schema) in schemas {
            let schema = schema.as_object().ok_or_else(|| {
                Error::new(
                    "schema-type-mismatch",
                    format!("evidence-schemas.{id} must be a JSON Schema object"),
                )
            })?;
            // §08 §1.1: the schemas are closed. A schema that admits extra members cannot make an
            // audit record typed, which is the only reason it is required.
            if schema.get("additionalProperties").and_then(Value::as_bool) != Some(false) {
                return Err(Error::new(
                    MANIFEST_MALFORMED,
                    format!("evidence-schemas.{id} must set additionalProperties: false"),
                ));
            }
        }

        let actions = map["actions"]
            .as_array()
            .ok_or_else(|| Error::new("schema-type-mismatch", "actions must be an array"))?;
        if actions.is_empty() {
            return Err(Error::new(MANIFEST_MALFORMED, "actions must be non-empty"));
        }
        for action in actions {
            let entry = action
                .as_object()
                .ok_or_else(|| Error::new("schema-type-mismatch", "an action must be an object"))?;
            for key in entry.keys() {
                if !ACTION_MEMBERS.contains(&key.as_str()) {
                    return Err(Error::new(
                        "schema-unknown-member",
                        format!("actions[].{key}"),
                    ));
                }
            }
            for required in [
                "action",
                "class",
                "evidence-schema",
                "idempotent",
                "target-kind",
            ] {
                if !entry.contains_key(required) {
                    return Err(Error::new(
                        "schema-missing-member",
                        format!("actions[].{required}"),
                    ));
                }
            }
            let identifier = entry["action"].as_str().unwrap_or_default();
            if !is_action_identifier(name, identifier) {
                return Err(Error::new(
                    "manifest-action-namespace",
                    format!("{identifier:?} is not in the {name:?} namespace"),
                ));
            }
            let class = entry["class"].as_str().unwrap_or_default();
            if !CLASSES.contains(&class) {
                return Err(Error::new(
                    "envelope-classification-unknown",
                    format!("actions[].class {class:?}"),
                ));
            }
            if !entry["idempotent"].is_boolean() {
                return Err(Error::new(
                    "schema-type-mismatch",
                    "actions[].idempotent must be a boolean",
                ));
            }
            let schema_id = entry["evidence-schema"].as_str().unwrap_or_default();
            if !schemas.contains_key(schema_id) {
                return Err(Error::new(
                    "manifest-evidence-schema-missing",
                    format!(
                        "{identifier} declares evidence-schema {schema_id:?}, which is not defined"
                    ),
                ));
            }
            let has_degrade = entry.get("degrade").is_some_and(|d| !d.is_null());
            if class == "prohibited" && has_degrade {
                return Err(Error::new(
                    "manifest-prohibited-degrade",
                    format!("{identifier} is prohibited and declares a degraded form"),
                ));
            }
            // §08 §1.2: `aggregate` is REQUIRED for class `read` and MUST NOT appear otherwise.
            let aggregate = entry.get("aggregate").filter(|a| !a.is_null());
            match (class, aggregate) {
                ("read", None) => {
                    return Err(Error::new(
                        MANIFEST_MALFORMED,
                        format!("{identifier} is class read and declares no aggregate rule"),
                    ));
                }
                ("read", Some(rule)) => {
                    let max = rule["max-samples"].as_u64().ok_or_else(|| {
                        Error::new(
                            "schema-missing-member",
                            format!("actions[].aggregate.max-samples for {identifier}"),
                        )
                    })?;
                    if max == 0 || max > 16 {
                        return Err(Error::new(
                            "aggregate-sample-bounds",
                            format!("{identifier} declares max-samples {max}, expected 1..=16"),
                        ));
                    }
                    if rule["sampling"].as_str().is_none() {
                        return Err(Error::new(
                            "schema-missing-member",
                            format!("actions[].aggregate.sampling for {identifier}"),
                        ));
                    }
                }
                (_, Some(_)) => {
                    return Err(Error::new(
                        MANIFEST_MALFORMED,
                        format!(
                            "{identifier} is class {class} and must not declare an aggregate rule"
                        ),
                    ));
                }
                (_, None) => {}
            }
        }

        let dimensions = map["budget-dimensions"].as_array().ok_or_else(|| {
            Error::new("schema-type-mismatch", "budget-dimensions must be an array")
        })?;
        for dimension in dimensions {
            let dimension = dimension.as_str().unwrap_or_default();
            let monetary = dimension
                .strip_prefix("money-")
                .is_some_and(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_lowercase()));
            if !BUDGET_DIMENSIONS.contains(&dimension) && !monetary {
                return Err(Error::new(
                    MANIFEST_MALFORMED,
                    format!(
                        "budget-dimensions holds {dimension:?}, which is not a budget dimension"
                    ),
                ));
            }
        }

        validate_durable_objects(&map["durable-objects"])?;

        let conformance = map["conformance"]
            .as_object()
            .ok_or_else(|| Error::new("schema-type-mismatch", "conformance must be an object"))?;
        for required in ["self-test", "vectors-version"] {
            if conformance.get(required).and_then(Value::as_str).is_none() {
                return Err(Error::new(
                    "schema-missing-member",
                    format!("conformance.{required}"),
                ));
            }
        }

        Ok(Self {
            document: document.clone(),
            name: name.to_owned(),
            version: version.to_owned(),
            hash: jcs::object_hash(document)?,
            component_key,
        })
    }

    /// The manifest as received.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// Organization-unique component name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Component semver.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// `object-hash` of the manifest — what the registration approval binds to.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// The component's own key, which signed the manifest.
    #[must_use]
    pub fn component_key(&self) -> &KeyId {
        &self.component_key
    }

    /// The class this manifest **proposes** for an action (§08 §1.2). A proposal, never authority.
    #[must_use]
    pub fn proposed_class(&self, action: &str) -> Option<&str> {
        self.action(action)?["class"].as_str()
    }

    /// The evidence schema identifier declared for an action.
    #[must_use]
    pub fn evidence_schema(&self, action: &str) -> Option<&str> {
        self.action(action)?["evidence-schema"].as_str()
    }

    fn action(&self, action: &str) -> Option<&Value> {
        self.document["actions"]
            .as_array()?
            .iter()
            .find(|entry| entry["action"].as_str() == Some(action))
    }

    /// Check a durable-object transition against the manifest's table (§08 §2).
    ///
    /// `folded_state` is the current state derived from the object's transition envelopes in chain
    /// order — `None` for an object with no transitions yet.
    ///
    /// # Errors
    ///
    /// `durable-transition-not-permitted` if the object type or transition is undeclared or the
    /// signer's role may not sign it, `durable-transition-illegal` if `from` does not contain the
    /// current folded state.
    pub fn check_transition(
        &self,
        object_type: &str,
        transition: &str,
        signer_role: &str,
        folded_state: Option<&str>,
    ) -> Result<String> {
        let declared = self.document["durable-objects"]
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|entry| entry["object-type"].as_str() == Some(object_type))
            })
            .ok_or_else(|| {
                Error::new(
                    "durable-transition-not-permitted",
                    format!("{} declares no durable object {object_type:?}", self.name),
                )
            })?;
        let entry = declared["transitions"]
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|t| t["transition"].as_str() == Some(transition))
            })
            .ok_or_else(|| {
                Error::new(
                    "durable-transition-not-permitted",
                    format!("{object_type} declares no transition {transition:?}"),
                )
            })?;
        let signers = entry["signers"]
            .as_array()
            .ok_or_else(|| Error::new("schema-missing-member", "transitions[].signers"))?;
        if !signers.iter().any(|s| s.as_str() == Some(signer_role)) {
            return Err(Error::new(
                "durable-transition-not-permitted",
                format!("{transition} on {object_type} may not be signed by a {signer_role}"),
            ));
        }
        let from = entry["from"]
            .as_array()
            .ok_or_else(|| Error::new("schema-missing-member", "transitions[].from"))?;
        let permitted = match folded_state {
            // `from: []` marks a creation transition, so an object that does not exist yet is
            // exactly what it applies to.
            None => from.is_empty(),
            Some(state) => from.iter().any(|f| f.as_str() == Some(state)),
        };
        if !permitted {
            return Err(Error::new(
                "durable-transition-illegal",
                format!(
                    "{transition} is not permitted from state {}",
                    folded_state.unwrap_or("<none>")
                ),
            ));
        }
        entry["to"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::new("schema-missing-member", "transitions[].to"))
    }
}

fn validate_durable_objects(objects: &Value) -> Result<()> {
    let objects = objects
        .as_array()
        .ok_or_else(|| Error::new("schema-type-mismatch", "durable-objects must be an array"))?;
    for object in objects {
        let map = object.as_object().ok_or_else(|| {
            Error::new("schema-type-mismatch", "a durable object must be an object")
        })?;
        for key in map.keys() {
            if !["object-type", "id-kind", "transitions"].contains(&key.as_str()) {
                return Err(Error::new(
                    "schema-unknown-member",
                    format!("durable-objects[].{key}"),
                ));
            }
        }
        for required in ["object-type", "id-kind", "transitions"] {
            if !map.contains_key(required) {
                return Err(Error::new(
                    "schema-missing-member",
                    format!("durable-objects[].{required}"),
                ));
            }
        }
        let transitions = map["transitions"]
            .as_array()
            .ok_or_else(|| Error::new("schema-type-mismatch", "transitions must be an array"))?;
        if transitions.is_empty() {
            return Err(Error::new(
                MANIFEST_MALFORMED,
                "a durable object declares no transitions",
            ));
        }
        for transition in transitions {
            let entry = transition.as_object().ok_or_else(|| {
                Error::new("schema-type-mismatch", "a transition must be an object")
            })?;
            for key in entry.keys() {
                if !["transition", "from", "to", "signers"].contains(&key.as_str()) {
                    return Err(Error::new(
                        "schema-unknown-member",
                        format!("transitions[].{key}"),
                    ));
                }
            }
            for required in ["transition", "from", "to", "signers"] {
                if !entry.contains_key(required) {
                    return Err(Error::new(
                        "schema-missing-member",
                        format!("transitions[].{required}"),
                    ));
                }
            }
            if entry["from"].as_array().is_none() {
                return Err(Error::new(
                    "schema-type-mismatch",
                    "transitions[].from must be an array",
                ));
            }
            let signers = entry["signers"].as_array().ok_or_else(|| {
                Error::new(
                    "schema-type-mismatch",
                    "transitions[].signers must be an array",
                )
            })?;
            if signers.is_empty() {
                return Err(Error::new(
                    MANIFEST_MALFORMED,
                    "transitions[].signers must be non-empty",
                ));
            }
            for signer in signers {
                if !matches!(signer.as_str(), Some("human" | "agent")) {
                    return Err(Error::new(
                        MANIFEST_MALFORMED,
                        format!("transitions[].signers holds {signer}"),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `^[a-z][a-z0-9-]{1,31}$` (§08 §1.1).
#[must_use]
pub fn is_component_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (2..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// `^<name>\.[a-z][a-z0-9_]{0,63}$` (§08 §1.2).
#[must_use]
pub fn is_action_identifier(component: &str, action: &str) -> bool {
    let Some(rest) = action
        .strip_prefix(component)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };
    let bytes = rest.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_identifiers_are_namespaced_by_the_manifest_name() {
        assert!(is_action_identifier("github", "github.create_issue"));
        assert!(!is_action_identifier("github", "githubx.create_issue"));
        assert!(!is_action_identifier("github", "slack.post_message"));
        assert!(!is_action_identifier("github", "github."));
        assert!(!is_action_identifier("github", "github.Create"));
    }

    #[test]
    fn component_names_are_bounded_and_lowercase() {
        assert!(is_component_name("github"));
        assert!(is_component_name("svod-foundry"));
        assert!(!is_component_name("GitHub"));
        assert!(!is_component_name("g"));
        assert!(!is_component_name(&"g".repeat(33)));
    }
}

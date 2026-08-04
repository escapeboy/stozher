//! Mandate chain verification — `spec/03-mandate.md` §5.
//!
//! *The mandate chain, or autonomy is unauditable.* Termination at a named human is structural: the
//! walk can only return `Ok` from the `interactive`/`standing` branch, which requires an enrolled
//! human root key. A cycle in `parent` links cannot reach acceptance, and the hop budget bounds the
//! walk so it terminates.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::error::{Result, err};
use crate::signed::{KeyId, object_id, verify_signed_object};

/// The tuple a mandate is checked against (§03 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandateRequest {
    /// Emitting component.
    pub component: String,
    /// Action type.
    pub action: String,
    /// Weight class.
    pub classification: String,
    /// Resource acted upon.
    pub resource: String,
}

impl MandateRequest {
    /// Read a request tuple from a JSON object.
    ///
    /// # Errors
    ///
    /// `schema-missing-member` if any of the four members is absent.
    pub fn from_value(value: &Value) -> Result<Self> {
        let field = |name: &str| -> Result<String> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| err!("schema-missing-member", "request.{name}"))
        };
        Ok(Self {
            component: field("component")?,
            action: field("action")?,
            classification: field("classification")?,
            resource: field("resource")?,
        })
    }
}

/// A successful walk to a human root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandateChainOk {
    /// The `subject` of the human who granted the root mandate.
    pub human_root: String,
    /// That human's key.
    pub root_key: KeyId,
    /// Number of delegated links traversed.
    pub depth: u32,
}

/// Parameters of a mandate chain verification.
#[derive(Debug, Clone)]
pub struct VerifyParams<'a> {
    /// Enrolled human root keys (§03 §6).
    pub roots: &'a [KeyId],
    /// Revocation objects to consider (§03 §7).
    pub revocations: &'a [Value],
    /// The instant at which validity is evaluated — the envelope's `emitted-at`.
    pub at: &'a str,
    /// The key that signed the envelope; must be the leaf mandate's grantee.
    pub subject_key: &'a KeyId,
    /// The deployment's cap on delegation chain length.
    pub max_delegation_depth: u32,
}

/// Walk a mandate chain from `leaf_ref` to a named human root.
///
/// # Errors
///
/// Any of the `mandate-*` codes of §03, or `sig-invalid`. See the specification's pseudocode: the
/// order of checks is normative because the vectors assert on which code fires first.
pub fn verify_mandate_chain(
    mandates: &Map<String, Value>,
    leaf_ref: &str,
    request: &MandateRequest,
    params: &VerifyParams<'_>,
) -> Result<MandateChainOk> {
    walk(mandates, leaf_ref, Scoped::Full(request), params)
}

/// Walk a mandate chain without matching a request against its scope.
///
/// For a record that carries no dimension of §03 §4.2's request tuple there is nothing to match.
/// **A `cognition` envelope is not such a record and MUST NOT use this entry point** — it carries
/// `resource` (§02 §6) and is verified by [`verify_mandate_chain_for_resource`].
///
/// This is deliberately a separate entry point rather than an option on [`VerifyParams`]: skipping
/// the scope check is a narrow, named exception, and a caller has to ask for it by name.
///
/// # Errors
///
/// As [`verify_mandate_chain`], minus `mandate-scope-not-permitted`.
pub fn verify_mandate_chain_unscoped(
    mandates: &Map<String, Value>,
    leaf_ref: &str,
    params: &VerifyParams<'_>,
) -> Result<MandateChainOk> {
    walk(mandates, leaf_ref, Scoped::Not, params)
}

/// Walk a mandate chain matching only the `resources` dimension of its scope (§03 §5).
///
/// A `cognition` envelope carries no `component`, `action` or `classification` and cannot be matched
/// on them — but it does carry `resource`, and until 2026-08-04 the scope check was skipped whole
/// because of the three it lacks. The consequence was that a mandate could not bound what an agent
/// spends cognition on **at all**: `resources: ["model:cheap-*"]` bound every effect and no
/// cognition. The dimensions the envelope cannot speak to are treated as unconstrained; the one it
/// can is enforced exactly as it is for any other record.
///
/// # Errors
///
/// As [`verify_mandate_chain`]; `mandate-scope-not-permitted` names only the resource.
pub fn verify_mandate_chain_for_resource(
    mandates: &Map<String, Value>,
    leaf_ref: &str,
    resource: &str,
    params: &VerifyParams<'_>,
) -> Result<MandateChainOk> {
    walk(mandates, leaf_ref, Scoped::ByResource(resource), params)
}

/// How much of §03 §4.2's request tuple the record being verified can supply.
///
/// An enum rather than an `Option` because there are three answers and the middle one is the whole
/// point: "this record has no scope to check" and "this record has one dimension of scope to check"
/// were the same branch, and the second was silently getting the first's treatment.
#[derive(Clone, Copy)]
enum Scoped<'a> {
    Full(&'a MandateRequest),
    ByResource(&'a str),
    Not,
}

fn walk(
    mandates: &Map<String, Value>,
    leaf_ref: &str,
    request: Scoped<'_>,
    params: &VerifyParams<'_>,
) -> Result<MandateChainOk> {
    let revoked = revocation_index(mandates, params);

    let mut current = resolve(mandates, leaf_ref)?;
    let mut current_ref = leaf_ref.to_owned();

    let grantee_key = key_at(current, "grantee")?;
    if &grantee_key != params.subject_key {
        return Err(err!(
            "mandate-grantee-key-mismatch",
            "mandate is held by {grantee_key}, envelope signed by {}",
            params.subject_key
        ));
    }

    let mut depth: u32 = 0;
    loop {
        let signer = verify_signed_object(current)?;
        let grantor_key = key_at(current, "grantor")?;
        if signer != grantor_key {
            return Err(err!(
                "mandate-signer-not-grantor",
                "signed by {signer}, grantor is {grantor_key}"
            ));
        }
        if grantor_key == key_at(current, "grantee")? {
            return Err(err!(
                "mandate-self-grant",
                "grantor and grantee are the same key"
            ));
        }

        let not_after = current
            .get("not-after")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                err!(
                    "mandate-missing-expiry",
                    "mandate {current_ref} has no not-after"
                )
            })?;
        let not_before = current
            .get("not-before")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("schema-missing-member", "not-before"))?;
        if params.at < not_before {
            return Err(err!(
                "mandate-not-yet-valid",
                "at {} precedes {not_before}",
                params.at
            ));
        }
        if params.at > not_after {
            return Err(err!(
                "mandate-expired",
                "at {} is after {not_after}",
                params.at
            ));
        }

        if let Some(revoked_at) = revoked.get(&current_ref) {
            if revoked_at.as_str() <= params.at {
                return Err(err!(
                    "mandate-revoked",
                    "mandate {current_ref} was revoked at {revoked_at}"
                ));
            }
        }

        let scope = current
            .get("scope")
            .ok_or_else(|| err!("schema-missing-member", "scope"))?;
        match request {
            Scoped::ByResource(resource) => {
                if !patterns(scope, "resources")?
                    .iter()
                    .any(|p| matches(p, resource))
                {
                    return Err(err!(
                        "mandate-scope-not-permitted",
                        "scope does not cover the resource {resource}"
                    ));
                }
            }
            Scoped::Not => {}
            Scoped::Full(request) => {
                if !scope_permits(scope, request)? {
                    return Err(err!(
                        "mandate-scope-not-permitted",
                        "scope does not cover {}/{} on {}",
                        request.component,
                        request.action,
                        request.resource
                    ));
                }
            }
        }

        let kind = current
            .get("mandate-kind")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("schema-missing-member", "mandate-kind"))?;
        let grantor_role = current
            .get("grantor")
            .and_then(|g| g.get("role"))
            .and_then(Value::as_str)
            .ok_or_else(|| err!("schema-missing-member", "grantor.role"))?;

        match kind {
            "interactive" | "standing" => {
                if !current.get("parent").is_none_or(Value::is_null) {
                    return Err(err!(
                        "mandate-root-has-parent",
                        "a root mandate must have parent null"
                    ));
                }
                if grantor_role != "human" {
                    return Err(err!(
                        "mandate-root-grantor-not-human",
                        "root mandate granted by role {grantor_role:?}"
                    ));
                }
                if !params.roots.contains(&grantor_key) {
                    return Err(err!(
                        "mandate-root-not-enrolled",
                        "{grantor_key} is not an enrolled human root"
                    ));
                }
                let subject = current
                    .get("grantor")
                    .and_then(|g| g.get("subject"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| err!("schema-missing-member", "grantor.subject"))?;
                return Ok(MandateChainOk {
                    human_root: subject.to_owned(),
                    root_key: grantor_key,
                    depth,
                });
            }
            "delegated" => {
                let parent_ref = current
                    .get("parent")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err!("mandate-delegated-without-parent", "parent is null"))?;
                if grantor_role != "agent" {
                    return Err(err!(
                        "mandate-delegated-grantor-not-agent",
                        "delegated mandate granted by role {grantor_role:?}"
                    ));
                }
                let parent = resolve(mandates, parent_ref)?;
                if grantor_key != key_at(parent, "grantee")? {
                    return Err(err!(
                        "mandate-delegation-not-held",
                        "{grantor_key} is not the parent's grantee"
                    ));
                }
                let parent_max = max_depth_of(parent)?;
                if parent_max < 1 {
                    return Err(err!(
                        "mandate-delegation-depth-exceeded",
                        "parent {parent_ref} permits no further delegation"
                    ));
                }
                if max_depth_of(current)? > parent_max - 1 {
                    return Err(err!(
                        "mandate-delegation-depth-exceeded",
                        "max-depth {} exceeds parent's budget",
                        max_depth_of(current)?
                    ));
                }
                let parent_scope = parent
                    .get("scope")
                    .ok_or_else(|| err!("schema-missing-member", "parent.scope"))?;
                if !scope_subset(scope, parent_scope)? {
                    return Err(err!(
                        "mandate-scope-widened",
                        "delegated scope is not a subset of the parent's"
                    ));
                }
                let (child_from, child_to) = window_of(current)?;
                let (parent_from, parent_to) = window_of(parent)?;
                if child_from < parent_from || child_to > parent_to {
                    return Err(err!(
                        "mandate-window-outside-parent",
                        "[{child_from}, {child_to}] is not inside [{parent_from}, {parent_to}]"
                    ));
                }
                if !budget_within(current.get("budget"), parent.get("budget"))? {
                    return Err(err!(
                        "mandate-budget-exceeds-parent",
                        "a delegated budget may only narrow"
                    ));
                }
                depth += 1;
                if depth > params.max_delegation_depth {
                    return Err(err!(
                        "mandate-delegation-depth-exceeded",
                        "chain depth {depth} exceeds the configured maximum {}",
                        params.max_delegation_depth
                    ));
                }
                current_ref = parent_ref.to_owned();
                current = parent;
            }
            other => return Err(err!("mandate-kind-unknown", "mandate-kind {other:?}")),
        }
    }
}

/// Parameters of a grant-time mandate check.
#[derive(Debug, Clone)]
pub struct GrantParams<'a> {
    /// Enrolled human root keys (§03 §6).
    pub roots: &'a [KeyId],
    /// For a `standing` mandate, the latest `not-after` policy permits, precomputed by the caller
    /// as `issued-at + delegation.max-standing-lifetime` (§03 §3).
    ///
    /// Timestamps are a single fixed format compared as strings (§01 §2.3), so this crate needs no
    /// date arithmetic and no calendar dependency.
    pub max_standing_not_after: Option<&'a str>,
}

/// Validate a mandate at **grant** time — when the `kind: "mandate"` envelope carrying it is
/// ingested, before any effect cites it (§03 §1–§4).
///
/// This is the complement of [`verify_mandate_chain`], which validates at *use* time against a
/// request tuple. The checks that are local to one grant are made here so that a malformed or
/// over-broad grant is refused when it is issued rather than when it is first exercised: the
/// delegation bound is "locally checkable at grant time, before any effect exists" (§03 §5).
///
/// `parent` is the resolved parent mandate, REQUIRED for `mandate-kind: "delegated"`.
///
/// # Errors
///
/// The `mandate-*` codes of §03, `scope-bad-pattern`, `sig-invalid`, or `schema-missing-member`.
pub fn verify_grant(
    mandate: &Value,
    parent: Option<&Value>,
    params: &GrantParams<'_>,
) -> Result<()> {
    let signer = verify_signed_object(mandate)?;
    let grantor_key = key_at(mandate, "grantor")?;
    if signer != grantor_key {
        return Err(err!(
            "mandate-signer-not-grantor",
            "signed by {signer}, grantor is {grantor_key}"
        ));
    }
    let grantee_key = key_at(mandate, "grantee")?;
    if grantor_key == grantee_key {
        return Err(err!(
            "mandate-self-grant",
            "grantor and grantee are the same key"
        ));
    }

    let str_member = |name: &'static str| -> Result<&str> {
        mandate
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| err!("schema-missing-member", "{name}"))
    };
    let issued_at = str_member("issued-at")?;
    let not_before = str_member("not-before")?;
    let not_after = mandate
        .get("not-after")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("mandate-missing-expiry", "not-after"))?;
    if not_after <= not_before {
        return Err(err!(
            "mandate-window-inverted",
            "not-after {not_after} does not follow not-before {not_before}"
        ));
    }
    if not_before < issued_at {
        return Err(err!(
            "mandate-window-inverted",
            "not-before {not_before} precedes issued-at {issued_at}"
        ));
    }
    let nonce = str_member("nonce")?;
    if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err!(
            "encoding-not-lowercase-hex",
            "nonce must be 32 hex digits"
        ));
    }
    if nonce.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(err!("encoding-not-lowercase-hex", "nonce is not lowercase"));
    }

    let scope = mandate
        .get("scope")
        .ok_or_else(|| err!("schema-missing-member", "scope"))?;
    validate_scope(scope)?;
    // Reading it here rejects a non-integer or absent hop budget before the branch that uses it.
    let own_max_depth = max_depth_of(mandate)?;

    let kind = str_member("mandate-kind")?;
    let grantor_role = mandate
        .get("grantor")
        .and_then(|g| g.get("role"))
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "grantor.role"))?;

    match kind {
        "interactive" | "standing" => {
            if !mandate.get("parent").is_none_or(Value::is_null) {
                return Err(err!(
                    "mandate-root-has-parent",
                    "a root mandate must have parent null"
                ));
            }
            if grantor_role != "human" {
                return Err(err!(
                    "mandate-root-grantor-not-human",
                    "root mandate granted by role {grantor_role:?}"
                ));
            }
            if !params.roots.contains(&grantor_key) {
                return Err(err!(
                    "mandate-root-not-enrolled",
                    "{grantor_key} is not an enrolled human root"
                ));
            }
            // §03 §6: a key MUST NOT be both a human root and an **agent** grantee. A human root
            // holding a mandate as a human is a different thing and is how a person acts under
            // authority someone else granted them — §05 §5's own worked example has a `human:`
            // subject citing a `mandate-ref`.
            let grantee_subject = current_grantee_subject(mandate)?;
            if params.roots.contains(&grantee_key) && grantee_subject.starts_with("agent:") {
                return Err(err!(
                    "root-key-used-as-agent",
                    "{grantee_key} is an enrolled human root and cannot be an agent grantee"
                ));
            }
            if kind == "standing" {
                if let Some(ceiling) = params.max_standing_not_after {
                    if not_after > ceiling {
                        return Err(err!(
                            "mandate-standing-lifetime-exceeded",
                            "not-after {not_after} exceeds the policy ceiling {ceiling}"
                        ));
                    }
                }
            }
            Ok(())
        }
        "delegated" => {
            if mandate
                .get("parent")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(err!("mandate-delegated-without-parent", "parent is null"));
            }
            if grantor_role != "agent" {
                return Err(err!(
                    "mandate-delegated-grantor-not-agent",
                    "delegated mandate granted by role {grantor_role:?}"
                ));
            }
            let parent = parent.ok_or_else(|| {
                err!(
                    "mandate-unresolved",
                    "the parent of a delegated grant must be resolvable"
                )
            })?;
            if grantor_key != key_at(parent, "grantee")? {
                return Err(err!(
                    "mandate-delegation-not-held",
                    "{grantor_key} is not the parent's grantee"
                ));
            }
            let parent_max = max_depth_of(parent)?;
            if parent_max < 1 {
                return Err(err!(
                    "mandate-delegation-depth-exceeded",
                    "the parent permits no further delegation"
                ));
            }
            if own_max_depth > parent_max - 1 {
                return Err(err!(
                    "mandate-delegation-depth-exceeded",
                    "max-depth {own_max_depth} exceeds the parent's budget"
                ));
            }
            let parent_scope = parent
                .get("scope")
                .ok_or_else(|| err!("schema-missing-member", "parent.scope"))?;
            if !scope_subset(scope, parent_scope)? {
                return Err(err!(
                    "mandate-scope-widened",
                    "delegated scope is not a subset of the parent's"
                ));
            }
            let (parent_from, parent_to) = window_of(parent)?;
            if not_before < parent_from || not_after > parent_to {
                return Err(err!(
                    "mandate-window-outside-parent",
                    "[{not_before}, {not_after}] is not inside [{parent_from}, {parent_to}]"
                ));
            }
            if !budget_within(mandate.get("budget"), parent.get("budget"))? {
                return Err(err!(
                    "mandate-budget-exceeds-parent",
                    "a delegated budget may only narrow"
                ));
            }
            Ok(())
        }
        other => Err(err!("mandate-kind-unknown", "mandate-kind {other:?}")),
    }
}

/// A scope pattern is exact equality, `"*"`, or a trailing `".*"` segment prefix — nothing else
/// (§03 §4.1). No regular expressions: a scope a human cannot read is a scope nobody reviewed.
fn validate_scope(scope: &Value) -> Result<()> {
    for dimension in DIMENSIONS {
        for pattern in patterns(scope, dimension)? {
            let bare = pattern.strip_suffix(".*").unwrap_or(pattern);
            if pattern != "*" && bare.contains('*') {
                return Err(err!(
                    "scope-bad-pattern",
                    "scope.{dimension} pattern {pattern:?} uses an unsupported wildcard"
                ));
            }
            if dimension == "classes"
                && pattern != "*"
                && !crate::envelope::CLASSES.contains(&pattern)
            {
                return Err(err!(
                    "scope-bad-pattern",
                    "scope.classes holds {pattern:?}, which is not a weight class"
                ));
            }
        }
    }
    Ok(())
}

/// Validate a revocation object (§03 §7).
///
/// # Errors
///
/// `revocation-not-authorized`, `revocation-before-issue`, `sig-invalid`, or
/// `schema-missing-member`.
pub fn verify_revocation(
    mandates: &Map<String, Value>,
    revocation: &Value,
    roots: &[KeyId],
) -> Result<()> {
    let signer = verify_signed_object(revocation)?;
    let target = revocation
        .get("revokes")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "revokes"))?;
    let revoked_at = revocation
        .get("revoked-at")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "revoked-at"))?;
    if !revoker_is_authorized(mandates, target, &signer, roots) {
        return Err(err!(
            "revocation-not-authorized",
            "{signer} may not revoke {target}"
        ));
    }
    if let Some(mandate) = mandates.get(target) {
        if let Some(issued_at) = mandate.get("issued-at").and_then(Value::as_str) {
            if revoked_at < issued_at {
                return Err(err!(
                    "revocation-before-issue",
                    "revoked-at {revoked_at} precedes issued-at {issued_at}"
                ));
            }
        }
    }
    Ok(())
}

fn resolve<'a>(mandates: &'a Map<String, Value>, id: &str) -> Result<&'a Value> {
    mandates
        .get(id)
        .ok_or_else(|| err!("mandate-unresolved", "no mandate with id {id}"))
}

fn current_grantee_subject(mandate: &Value) -> Result<&str> {
    mandate
        .get("grantee")
        .and_then(|g| g.get("subject"))
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "grantee.subject"))
}

fn key_at(mandate: &Value, party: &str) -> Result<KeyId> {
    let raw = mandate
        .get(party)
        .and_then(|p| p.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "{party}.key"))?;
    KeyId::parse(raw)
}

fn max_depth_of(mandate: &Value) -> Result<u32> {
    let raw = mandate
        .get("max-depth")
        .and_then(Value::as_u64)
        .ok_or_else(|| err!("schema-missing-member", "max-depth"))?;
    u32::try_from(raw).map_err(|_| err!("encoding-integer-out-of-range", "max-depth {raw}"))
}

fn window_of(mandate: &Value) -> Result<(&str, &str)> {
    let from = mandate
        .get("not-before")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("schema-missing-member", "not-before"))?;
    let to = mandate
        .get("not-after")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("mandate-missing-expiry", "not-after"))?;
    Ok((from, to))
}

/// A pattern covers a value: exact equality, `"*"`, or a `.`-segment prefix `"x.*"` (§03 §4.1).
fn matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return value.len() > prefix.len() + 1
            && value.starts_with(prefix)
            && value.as_bytes()[prefix.len()] == b'.';
    }
    false
}

/// A parent pattern covers a child pattern (used for non-widening checks).
fn covers_pattern(parent: &str, child: &str) -> bool {
    if parent == "*" || parent == child {
        return true;
    }
    if let Some(parent_prefix) = parent.strip_suffix(".*") {
        if let Some(child_prefix) = child.strip_suffix(".*") {
            return child_prefix == parent_prefix
                || (child_prefix.len() > parent_prefix.len()
                    && child_prefix.starts_with(parent_prefix)
                    && child_prefix.as_bytes()[parent_prefix.len()] == b'.');
        }
        return matches(parent, child);
    }
    false
}

const DIMENSIONS: [&str; 4] = ["components", "actions", "classes", "resources"];

fn patterns<'a>(scope: &'a Value, dimension: &str) -> Result<Vec<&'a str>> {
    let list = scope
        .get(dimension)
        .and_then(Value::as_array)
        .ok_or_else(|| err!("schema-missing-member", "scope.{dimension}"))?;
    list.iter()
        .map(|p| {
            p.as_str()
                .ok_or_else(|| err!("scope-bad-pattern", "scope.{dimension} holds a non-string"))
        })
        .collect()
}

fn scope_permits(scope: &Value, request: &MandateRequest) -> Result<bool> {
    let wanted = [
        request.component.as_str(),
        request.action.as_str(),
        request.classification.as_str(),
        request.resource.as_str(),
    ];
    for (dimension, value) in DIMENSIONS.iter().zip(wanted) {
        if !patterns(scope, dimension)?
            .iter()
            .any(|p| matches(p, value))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Scope may only narrow along a delegation chain (§03 §5).
fn scope_subset(child: &Value, parent: &Value) -> Result<bool> {
    for dimension in DIMENSIONS {
        let parent_patterns = patterns(parent, dimension)?;
        for child_pattern in patterns(child, dimension)? {
            if !parent_patterns
                .iter()
                .any(|p| covers_pattern(p, child_pattern))
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// A delegated budget must not exceed its parent's in any dimension the parent constrains.
fn budget_within(child: Option<&Value>, parent: Option<&Value>) -> Result<bool> {
    let Some(parent) = parent.and_then(Value::as_object) else {
        return Ok(true);
    };
    let Some(child) = child.and_then(Value::as_object) else {
        return Ok(true);
    };
    for (dimension, parent_value) in parent {
        let Some(child_value) = child.get(dimension) else {
            continue;
        };
        match (child_value, parent_value) {
            (Value::Number(c), Value::Number(p)) => {
                // §01 §2.5 bounds every protocol number to an integer in ±(2^53 - 1), so `as_i64`
                // is exact for anything that got this far, and a value that is not an integer in
                // that range is refused rather than coerced. The previous `as_f64` comparison read
                // as harmless because of that bound — but it left the *type* rule unchecked, so a
                // fractional budget silently became a float comparison after all.
                let (Some(c), Some(p)) = (c.as_i64(), p.as_i64()) else {
                    return Err(err!(
                        "schema-type-mismatch",
                        "budget.{dimension} must be an integer; fractional and monetary \
                         quantities are decimal strings (spec 01 section 2.5)"
                    ));
                };
                if c > p {
                    return Ok(false);
                }
            }
            (Value::String(c), Value::String(p)) => {
                // Exactly, never through `f64`. Parsing a decimal string back into binary64 to
                // compare it reintroduces the representation §01 §2.5 removed, at the one place it
                // decides whether authority narrows: `9007199254740993` and `9007199254740992` are
                // one apart and the same `f64`, so a child one unit over its parent compared equal.
                if !crate::decimal::at_most(c, p)? {
                    return Ok(false);
                }
            }
            _ => {
                return Err(err!(
                    "schema-type-mismatch",
                    "budget.{dimension} type mismatch"
                ));
            }
        }
    }
    Ok(true)
}

/// Map mandate id to the earliest instant at which an authorized revocation took effect.
fn revocation_index(
    mandates: &Map<String, Value>,
    params: &VerifyParams<'_>,
) -> HashMap<String, String> {
    let mut index: HashMap<String, String> = HashMap::new();
    for revocation in params.revocations {
        let Ok(signer) = verify_signed_object(revocation) else {
            continue;
        };
        let Some(target) = revocation.get("revokes").and_then(Value::as_str) else {
            continue;
        };
        let Some(revoked_at) = revocation.get("revoked-at").and_then(Value::as_str) else {
            continue;
        };
        if !revoker_is_authorized(mandates, target, &signer, params.roots) {
            continue;
        }
        if let Some(mandate) = mandates.get(target) {
            // A revocation MUST NOT be backdated before the mandate was issued (§03 §7).
            if let Some(issued_at) = mandate.get("issued-at").and_then(Value::as_str) {
                if revoked_at < issued_at {
                    continue;
                }
            }
        }
        index
            .entry(target.to_owned())
            .and_modify(|existing| {
                if revoked_at < existing.as_str() {
                    *existing = revoked_at.to_owned();
                }
            })
            .or_insert_with(|| revoked_at.to_owned());
    }
    // Revoking a mandate revokes everything delegated beneath it.
    propagate_revocations(mandates, &mut index);
    index
}

fn propagate_revocations(mandates: &Map<String, Value>, index: &mut HashMap<String, String>) {
    // Bounded by the number of mandates: each pass can only add descendants.
    for _ in 0..mandates.len() {
        let mut changed = false;
        for (id, mandate) in mandates {
            let Some(parent) = mandate.get("parent").and_then(Value::as_str) else {
                continue;
            };
            let Some(parent_revoked) = index.get(parent).cloned() else {
                continue;
            };
            let update = match index.get(id) {
                Some(existing) => parent_revoked < *existing,
                None => true,
            };
            if update {
                index.insert(id.clone(), parent_revoked);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn revoker_is_authorized(
    mandates: &Map<String, Value>,
    target: &str,
    signer: &KeyId,
    roots: &[KeyId],
) -> bool {
    if roots.contains(signer) {
        return true;
    }
    let mut cursor = target.to_owned();
    for _ in 0..=mandates.len() {
        let Some(mandate) = mandates.get(&cursor) else {
            return false;
        };
        if key_at(mandate, "grantor").is_ok_and(|k| &k == signer) {
            return true;
        }
        match mandate.get("parent").and_then(Value::as_str) {
            Some(parent) => cursor = parent.to_owned(),
            None => return false,
        }
    }
    false
}

/// Recompute a mandate's id.
///
/// # Errors
///
/// Propagates canonicalization.
pub fn mandate_id(mandate: &Value) -> Result<String> {
    object_id(mandate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_patterns_match_by_segment() {
        assert!(matches("github.*", "github.create_issue"));
        assert!(!matches("github.*", "github"));
        assert!(!matches("github.*", "githubx.create_issue"));
        assert!(matches("*", "anything"));
        assert!(!matches("github.create_issue", "github.create_issue_v2"));
    }

    #[test]
    fn scope_may_only_narrow() {
        let parent = serde_json::json!({
            "components": ["gateway"], "actions": ["github.*"],
            "classes": ["read", "consequential"], "resources": ["repo:a"]
        });
        let narrower = serde_json::json!({
            "components": ["gateway"], "actions": ["github.create_issue"],
            "classes": ["read"], "resources": ["repo:a"]
        });
        let wider = serde_json::json!({
            "components": ["gateway"], "actions": ["*"],
            "classes": ["read"], "resources": ["repo:a"]
        });
        assert!(scope_subset(&narrower, &parent).unwrap());
        assert!(!scope_subset(&wider, &parent).unwrap());
    }

    #[test]
    fn empty_dimension_permits_nothing() {
        let scope = serde_json::json!({
            "components": [], "actions": ["*"], "classes": ["*"], "resources": ["*"]
        });
        let request = MandateRequest {
            component: "gateway".into(),
            action: "x.y".into(),
            classification: "read".into(),
            resource: "r".into(),
        };
        assert!(!scope_permits(&scope, &request).unwrap());
    }
}

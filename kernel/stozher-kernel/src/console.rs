//! The read-only console — `docs/design/console.md`, served from this binary.
//!
//! # Read-only is a property of the route table, not a promise
//!
//! Every route below is registered with [`axum::routing::get`]. There is no `post`, `put`, `patch`
//! or `delete` anywhere in this module, and no handler here calls anything that writes: the console
//! reaches the store through [`crate::store::Store`]'s read methods only, and
//! [`crate::store::Store::append`] is crate-private and reachable exclusively from
//! [`crate::ingest::Ingest::submit`]. An "approve" here would therefore have to be a signature
//! travelling through `POST /v1/ingest` like everything else — which is what S4 builds. `spec/06 §2`
//! names an administrative append as a conformance failure, and the S1 suite attempts one.
//!
//! # Authentication is the kernel's, not a second scheme
//!
//! The console authenticates exactly as every other route does: the `Bearer` credential of
//! `spec/05 §2.2`, resolved by [`crate::config::Config::authenticate`]. An audit trail readable by
//! anyone who can reach the port is a different product, and a console-only login would be a second
//! credential path to hold correct — so there is not one.
//!
//! # Templates
//!
//! `console/templates/*.html`, compiled into the binary by askama (ADR-0003: server-rendered, no
//! SPA framework, one binary serves API and UI). Every interpolation is HTML-escaped by the
//! templating layer; nothing on these pages is rendered raw.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use serde_json::Value;

use crate::http::{Caller, caller};
use crate::store::EnvelopeQuery;
use crate::{Kernel, checkpoint};

/// How far ahead of expiry a standing rule is worth surfacing.
const EXPIRING_SOON_SECONDS: i64 = 7 * 86_400;
/// Rows shown on a summary panel before the full view is needed.
const PREVIEW_ROWS: i64 = 10;
/// The largest evidence payload rendered inline. Bigger evidence is named, not shown.
const PAYLOAD_PREVIEW_BYTES: usize = 8_192;

/// Build the console router.
pub fn router(kernel: Arc<Kernel>) -> Router {
    Router::new()
        .route("/console", get(overview))
        .route("/console/audit", get(audit))
        .route("/console/audit/export", get(export))
        .route("/console/attempts", get(attempts))
        .route("/console/pending", get(pending))
        .route("/console/mandates", get(mandates))
        .route("/console/streams", get(streams))
        .route("/console/streams/{stream}/verify", get(verify))
        .route("/console/rejections", get(rejections))
        .route("/console/envelopes/{id}", get(envelope))
        .with_state(kernel)
}

// -- view models ------------------------------------------------------------------------------
//
// Flattened to `String` on purpose. A template that has to reason about `Option`, about missing
// members of a `serde_json::Value`, or about which of two spellings a field has is a template that
// can render "null" at an auditor. Every absent value becomes an em dash exactly once, here.

/// One envelope, as a row or a page.
pub struct Row {
    /// `id()` of the envelope.
    pub id: String,
    /// First 12 hex digits of `id`, which is what fits in a table cell.
    pub short: String,
    /// The stream it belongs to.
    pub stream: String,
    /// Its chain position.
    pub seq: String,
    /// Envelope kind (§02 §2).
    pub kind: String,
    /// `emitted-at`.
    pub emitted_at: String,
    /// Acting subject.
    pub subject: String,
    /// Emitting component.
    pub component: String,
    /// The action executed.
    pub action: String,
    /// What was acted upon.
    pub target: String,
    /// Terminal state of the execution.
    pub outcome: String,
    /// The class policy computed.
    pub class: String,
    /// The human root the mandate walk reached.
    pub human_root: String,
    /// The mandate cited.
    pub mandate_ref: String,
    /// The policy version applied.
    pub policy_version: String,
    /// Set when the record confesses an effect policy did not permit.
    pub violation: String,
    /// A one-line description of the evidence commitment.
    pub evidence: String,
    /// The approver, when the envelope carries a decision.
    pub decided_by: String,
}

/// One stream, with the quiet-stream finding already computed.
pub struct StreamRow {
    /// Stream name.
    pub stream: String,
    /// `effect` or `signal`.
    pub stream_kind: String,
    /// Head position.
    pub head_seq: String,
    /// Head envelope id.
    pub head_short: String,
    /// When the stream was first written to.
    pub first_seen_at: String,
    /// When it was last written to.
    pub last_appended_at: String,
    /// How long it has been silent, in human units.
    pub silent_for: String,
    /// Whether that silence is long enough to be a finding.
    pub quiet: bool,
}

/// One mandate in the registry.
pub struct MandateRow {
    /// `mandate-id`.
    pub id: String,
    /// Short form of `id`.
    pub short: String,
    /// Parent `mandate-id`, or empty for a root mandate.
    pub parent: String,
    /// Short form of `parent`.
    pub parent_short: String,
    /// `interactive` | `standing` | `delegated`.
    pub kind: String,
    /// Who granted it.
    pub grantor_subject: String,
    /// Who holds it.
    pub grantee_subject: String,
    /// Expiry, which every mandate has.
    pub not_after: String,
    /// `revoked` | `expired` | `expiring` | `active`.
    pub state: String,
    /// CSS class matching `state`.
    pub state_class: String,
    /// Scope dimensions, rendered.
    pub components: String,
    /// Scope dimensions, rendered.
    pub actions: String,
    /// Scope dimensions, rendered.
    pub classes: String,
    /// Scope dimensions, rendered.
    pub resources: String,
}

/// One revocation in the feed.
pub struct RevocationRow {
    /// When the revocation took effect.
    pub revoked_at: String,
    /// The mandate it revokes.
    pub revokes: String,
    /// Short form of `revokes`.
    pub revokes_short: String,
    /// The stated reason, if any.
    pub reason: String,
    /// The key that signed it.
    pub signer: String,
}

/// One rejection record.
pub struct RejectionRow {
    /// Position in the kernel's rejection stream.
    pub seq: String,
    /// When the kernel received the refused bytes.
    pub received_at: String,
    /// The normative reason code.
    pub reason: String,
    /// Human-readable detail.
    pub detail: String,
    /// The authenticated caller that submitted it.
    pub submitted_by: String,
    /// The stream the refused object claimed.
    pub claimed_stream: String,
    /// The position it claimed.
    pub claimed_seq: String,
    /// The kind it claimed.
    pub claimed_kind: String,
}

/// One link of a mandate walk.
pub struct ChainLink {
    /// How many delegated hops from the leaf.
    pub depth: String,
    /// `mandate-id`.
    pub id: String,
    /// Short form of `id`.
    pub short: String,
    /// Mandate kind.
    pub kind: String,
    /// Granting subject.
    pub grantor: String,
    /// Receiving subject.
    pub grantee: String,
    /// Window start.
    pub not_before: String,
    /// Window end.
    pub not_after: String,
}

/// The audit explorer's filter state, echoed back into the form.
#[derive(Default)]
pub struct Filters {
    /// Acting subject.
    pub subject: String,
    /// Exact mandate.
    pub mandate_ref: String,
    /// A mandate and everything delegated beneath it.
    pub mandate_subtree_of: String,
    /// Effective weight class.
    pub classification: String,
    /// Envelope kind.
    pub kind: String,
    /// Action executed.
    pub action: String,
    /// Emitting component.
    pub component: String,
    /// One stream.
    pub stream: String,
    /// Execution outcome.
    pub outcome: String,
    /// The human root the walk reached.
    pub human_root: String,
    /// Durable object reference.
    pub commitment_id: String,
    /// Exact correlation reference.
    pub correlation_ref: String,
    /// Window lower bound.
    pub emitted_from: String,
    /// Window upper bound.
    pub emitted_to: String,
    /// Row cap.
    pub limit: String,
    /// Only records that confess a violation.
    pub violations_only: bool,
}

// -- templates --------------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "overview.html")]
struct OverviewPage {
    title: &'static str,
    policy_version: String,
    envelopes: String,
    attempts: String,
    violations: String,
    pending: String,
    rejections: String,
    quiet_count: String,
    quiet_after: String,
    rows: Vec<Row>,
    expiring: Vec<MandateRow>,
    quiet: Vec<StreamRow>,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    title: &'static str,
    f: Filters,
    query: String,
    count: String,
    rows: Vec<Row>,
}

#[derive(Template)]
#[template(path = "attempts.html")]
struct AttemptsPage {
    title: &'static str,
    rows: Vec<Row>,
    violations: Vec<Row>,
}

#[derive(Template)]
#[template(path = "pending.html")]
struct PendingPage {
    title: &'static str,
    rows: Vec<Row>,
    denied: Vec<Row>,
}

#[derive(Template)]
#[template(path = "mandates.html")]
struct MandatesPage {
    title: &'static str,
    total: String,
    expiring_count: String,
    revoked_count: String,
    epoch: String,
    rows: Vec<MandateRow>,
    revocations: Vec<RevocationRow>,
}

#[derive(Template)]
#[template(path = "streams.html")]
struct StreamsPage {
    title: &'static str,
    quiet_after: String,
    rows: Vec<StreamRow>,
}

#[derive(Template)]
#[template(path = "verify.html")]
struct VerifyPage {
    title: &'static str,
    stream: String,
    valid: bool,
    count: String,
    head_hash: String,
    anchored: bool,
    checkpoint: String,
    reason_code: String,
    reason: String,
    failed_at_seq: String,
}

#[derive(Template)]
#[template(path = "rejections.html")]
struct RejectionsPage {
    title: &'static str,
    chain_valid: bool,
    count: String,
    head_hash: String,
    rows: Vec<RejectionRow>,
}

#[derive(Template)]
#[template(path = "envelope.html")]
struct EnvelopePage {
    title: &'static str,
    r: Row,
    received_at: String,
    prev_hash: String,
    subject_key: String,
    proposed_class: String,
    authorization: String,
    chain: Vec<ChainLink>,
    evidence_schema: String,
    evidence_media_type: String,
    evidence_hash: String,
    evidence_retain_until: String,
    payload_state: String,
    payload_preview: String,
    canonical_json: String,
}

#[derive(Template)]
#[template(path = "notice.html")]
struct NoticePage {
    title: String,
    detail: String,
}

// -- handlers ---------------------------------------------------------------------------------

async fn overview(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let now = kernel.ingest.clock().now();
    let quiet_after = quiet_after_seconds(&kernel).await;

    let attempt_rows = match store
        .query(&EnvelopeQuery {
            outcome: Some("attempted"),
            limit: PREVIEW_ROWS,
            ..Default::default()
        })
        .await
    {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    let counts = match Counts::gather(&kernel).await {
        Ok(counts) => counts,
        Err(e) => return unavailable(&e),
    };
    let registry = match store.mandate_registry().await {
        Ok(rows) => rows,
        Err(e) => return unavailable(&e),
    };
    let stream_rows = match store.streams().await {
        Ok(rows) => rows,
        Err(e) => return unavailable(&e),
    };
    let quiet: Vec<StreamRow> = stream_rows
        .iter()
        .map(|s| stream_row(s, &now, quiet_after))
        .filter(|s| s.quiet)
        .collect();

    render(&OverviewPage {
        title: "Overview",
        policy_version: match store.current_policy().await {
            Ok(Some(document)) => text(&document["policy-version"]),
            Ok(None) => "none published".to_owned(),
            Err(e) => return unavailable(&e),
        },
        envelopes: counts.envelopes.to_string(),
        attempts: counts.attempts.to_string(),
        violations: counts.violations.to_string(),
        pending: counts.pending.to_string(),
        rejections: counts.rejections.to_string(),
        quiet_count: quiet.len().to_string(),
        quiet_after: humanize(quiet_after),
        rows: attempt_rows.iter().map(row).collect(),
        expiring: registry
            .iter()
            .take(PREVIEW_ROWS as usize)
            .map(|m| mandate_row(m, &now))
            .collect(),
        quiet,
    })
}

async fn audit(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let filters = Filters::from_params(&params);
    let records = match kernel.ingest.store().query(&filters.query()).await {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    render(&AuditPage {
        title: "Audit explorer",
        query: filters.to_query_string(),
        count: records.len().to_string(),
        rows: records.iter().map(row).collect(),
        f: filters,
    })
}

/// The regulator's copy: newline-delimited canonical envelopes, exactly as signed.
///
/// Not CSV. A spreadsheet cannot carry a signature, and an export a regulator cannot re-verify is
/// an assertion rather than evidence. Each line is the stored `JCS(envelope)`, so `id()` and the
/// Ed25519 signature reproduce from the file alone.
async fn export(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let filters = Filters::from_params(&params);
    let records = match kernel.ingest.store().query(&filters.query()).await {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    let mut body = String::new();
    for record in &records {
        match stozher_core::jcs::canonicalize(record) {
            Ok(line) => {
                body.push_str(&line);
                body.push('\n');
            }
            Err(e) => return unavailable(&e),
        }
    }
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/x-ndjson; charset=utf-8",
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"stozher-audit-export.ndjson\"",
            ),
        ],
        body,
    )
        .into_response()
}

async fn attempts(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let attempted = match store
        .query(&EnvelopeQuery {
            outcome: Some("attempted"),
            limit: 1_000,
            ..Default::default()
        })
        .await
    {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    let violations = match store
        .query(&EnvelopeQuery {
            violations_only: true,
            limit: 1_000,
            ..Default::default()
        })
        .await
    {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    render(&AttemptsPage {
        title: "Attempts and violations",
        rows: attempted.iter().map(row).collect(),
        violations: violations.iter().map(row).collect(),
    })
}

async fn pending(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let blocked = match store
        .query(&EnvelopeQuery {
            outcome: Some("blocked"),
            limit: 1_000,
            ..Default::default()
        })
        .await
    {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    let denied = match store
        .query(&EnvelopeQuery {
            outcome: Some("denied"),
            limit: 1_000,
            ..Default::default()
        })
        .await
    {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    render(&PendingPage {
        title: "Pending approvals",
        rows: blocked.iter().map(row).collect(),
        denied: denied.iter().map(row).collect(),
    })
}

async fn mandates(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let now = kernel.ingest.clock().now();
    let registry = match store.mandate_registry().await {
        Ok(rows) => rows,
        Err(e) => return unavailable(&e),
    };
    let (epoch, revocations) = match store.revocation_feed().await {
        Ok(feed) => feed,
        Err(e) => return unavailable(&e),
    };
    let rows: Vec<MandateRow> = registry.iter().map(|m| mandate_row(m, &now)).collect();
    render(&MandatesPage {
        title: "Mandate registry",
        total: rows.len().to_string(),
        expiring_count: rows
            .iter()
            .filter(|m| m.state == "expiring")
            .count()
            .to_string(),
        revoked_count: rows
            .iter()
            .filter(|m| m.state == "revoked")
            .count()
            .to_string(),
        epoch,
        rows,
        revocations: revocations.iter().map(revocation_row).collect(),
    })
}

async fn streams(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let now = kernel.ingest.clock().now();
    let quiet_after = quiet_after_seconds(&kernel).await;
    let rows = match kernel.ingest.store().streams().await {
        Ok(rows) => rows,
        Err(e) => return unavailable(&e),
    };
    render(&StreamsPage {
        title: "Streams",
        quiet_after: humanize(quiet_after),
        rows: rows
            .iter()
            .map(|s| stream_row(s, &now, quiet_after))
            .collect(),
    })
}

async fn verify(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(stream): Path<String>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let mut page = VerifyPage {
        title: "Chain verification",
        stream: stream.clone(),
        valid: false,
        count: "0".to_owned(),
        head_hash: "—".to_owned(),
        anchored: false,
        checkpoint: "—".to_owned(),
        reason_code: String::new(),
        reason: String::new(),
        failed_at_seq: String::new(),
    };
    match checkpoint::verify_stream(&kernel.ingest, &stream).await {
        Ok(report) => {
            page.valid = true;
            page.count = text(&report["count"]);
            page.head_hash = text(&report["head-hash"]);
            page.anchored = report["anchored"].as_bool().unwrap_or(false);
            let attested = &report["last-checkpoint"];
            page.checkpoint = if attested.is_null() {
                "—".to_owned()
            } else {
                format!(
                    "seq {}…{} attesting {}",
                    text(&attested["from-seq"]),
                    text(&attested["to-seq"]),
                    text(&attested["head-hash"])
                )
            };
        }
        Err(e) if e.code() == crate::codes::STORE_UNAVAILABLE => return unavailable(&e),
        Err(e) => {
            page.reason_code = e.code().to_owned();
            page.reason = e.detail().to_owned();
            page.failed_at_seq = e.seq().map(|s| s.to_string()).unwrap_or_default();
        }
    }
    render(&page)
}

async fn rejections(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let listed = match store.rejections(None, 1_000).await {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    let chain = match store.rejection_chain().await {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    let verified = crate::store::verify_rejection_chain(&chain, store.rejection_stream());
    render(&RejectionsPage {
        title: "Refused submissions",
        chain_valid: verified.is_ok(),
        count: listed.len().to_string(),
        head_hash: verified.ok().flatten().unwrap_or_else(|| "—".to_owned()),
        rows: listed.iter().map(rejection_row).collect(),
    })
}

async fn envelope(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let stored = match store.envelope_by_id(&id).await {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return notice(
                StatusCode::NOT_FOUND,
                "No such envelope",
                "Nothing in this store has that id. An audit citation that does not resolve is \
                 itself worth investigating.",
            );
        }
        Err(e) => return unavailable(&e),
    };
    let document = match stored.envelope() {
        Ok(document) => document,
        Err(e) => return unavailable(&e),
    };
    let record = serde_json::json!({
        "id": stored.id,
        "human-root": stored.human_root,
        "effective-class": stored.effective_class,
        "policy-violation": stored.policy_violation,
        "envelope": document,
    });

    let mut chain = Vec::new();
    if let Some(mandate_ref) = document["mandate-ref"].as_str() {
        match store.mandate_ancestry(mandate_ref, 16).await {
            Ok(ancestry) => {
                let mut cursor = Some(mandate_ref.to_owned());
                let mut depth = 0usize;
                while let Some(current) = cursor.take() {
                    let Some(mandate) = ancestry.get(&current) else {
                        break;
                    };
                    chain.push(ChainLink {
                        depth: depth.to_string(),
                        short: short(&current),
                        id: current,
                        kind: text(&mandate["mandate-kind"]),
                        grantor: text(&mandate["grantor"]["subject"]),
                        grantee: text(&mandate["grantee"]["subject"]),
                        not_before: text(&mandate["not-before"]),
                        not_after: text(&mandate["not-after"]),
                    });
                    cursor = mandate["parent"].as_str().map(str::to_owned);
                    depth += 1;
                }
            }
            Err(e) => return unavailable(&e),
        }
    }

    let evidence = &document["evidence"];
    let mut payload_state = "—".to_owned();
    let mut payload_preview = String::new();
    if let Some(hash) = evidence["payload-hash"].as_str() {
        match store.payload(hash).await {
            Ok(Some((media_type, bytes))) => {
                payload_state = format!("{} bytes, {media_type}", bytes.len());
                payload_preview = preview(&bytes);
            }
            // §04 §5.4: after decay the hash remains the commitment. An auditor who independently
            // holds the content can still prove it is the content that was recorded.
            Ok(None) => {
                payload_state =
                    "decayed — the payload has been deleted; the hash remains the commitment"
                        .to_owned();
            }
            Err(e) => return unavailable(&e),
        }
    }

    render(&EnvelopePage {
        title: "Envelope",
        received_at: stored.received_at.clone(),
        prev_hash: text(&document["prev-hash"]),
        subject_key: text(&document["identity"]["key"]),
        proposed_class: text(&document["classification"]),
        authorization: if document["authorization"].is_null() {
            "none — this envelope carries no gate decision".to_owned()
        } else {
            format!(
                "{} by {} at {}",
                text(&document["authorization"]["decision"]["decision"]),
                text(&document["authorization"]["decision"]["sig"]["key"]),
                text(&document["authorization"]["decision"]["decided-at"])
            )
        },
        chain,
        evidence_schema: text(&evidence["schema"]),
        evidence_media_type: text(&evidence["media-type"]),
        evidence_hash: text(&evidence["payload-hash"]),
        evidence_retain_until: text(&evidence["retain-until"]),
        payload_state,
        payload_preview,
        canonical_json: stored.canonical_json.clone(),
        r: row(&record),
    })
}

// -- shaping ----------------------------------------------------------------------------------

/// The overview's headline numbers.
struct Counts {
    envelopes: usize,
    attempts: usize,
    violations: usize,
    pending: usize,
    rejections: usize,
}

impl Counts {
    async fn gather(kernel: &Kernel) -> stozher_core::error::Result<Self> {
        let store = kernel.ingest.store();
        let count = async |outcome: Option<&str>, violations_only: bool| {
            store
                .query(&EnvelopeQuery {
                    outcome,
                    violations_only,
                    limit: 10_000,
                    ..Default::default()
                })
                .await
                .map(|records| records.len())
        };
        Ok(Self {
            envelopes: usize::try_from(store.envelope_count().await?).unwrap_or(usize::MAX),
            attempts: count(Some("attempted"), false).await?,
            violations: count(None, true).await?,
            pending: count(Some("blocked"), false).await?,
            rejections: store.rejections(None, 10_000).await?.len(),
        })
    }
}

fn row(record: &Value) -> Row {
    let envelope = &record["envelope"];
    let execution = &envelope["execution"];
    let evidence = &envelope["evidence"];
    let id = text(&record["id"]);
    Row {
        short: short(&id),
        id,
        stream: text(&envelope["stream"]),
        seq: text(&envelope["seq"]),
        kind: text(&envelope["kind"]),
        emitted_at: text(&envelope["emitted-at"]),
        subject: text(&envelope["identity"]["subject"]),
        component: text(&envelope["identity"]["component"]),
        action: text(&execution["action"]),
        target: text(&execution["target"]),
        outcome: text(&execution["outcome"]),
        class: text(&record["effective-class"]),
        human_root: text(&record["human-root"]),
        mandate_ref: envelope["mandate-ref"].as_str().unwrap_or("").to_owned(),
        policy_version: text(&envelope["policy-version"]),
        violation: record["policy-violation"].as_str().unwrap_or("").to_owned(),
        evidence: match evidence["schema"].as_str() {
            Some(schema) => format!("{schema} · {}", short(&text(&evidence["payload-hash"]))),
            None => "—".to_owned(),
        },
        decided_by: text(&envelope["authorization"]["decision"]["sig"]["key"]),
    }
}

fn stream_row(record: &Value, now: &str, quiet_after: i64) -> StreamRow {
    let last = text(&record["last-appended-at"]);
    let silent = age_seconds(&last, now);
    StreamRow {
        stream: text(&record["stream"]),
        stream_kind: text(&record["stream-kind"]),
        head_seq: text(&record["head-seq"]),
        head_short: short(&text(&record["head-hash"])),
        first_seen_at: text(&record["first-seen-at"]),
        last_appended_at: last,
        silent_for: silent.map(humanize).unwrap_or_else(|| "—".to_owned()),
        quiet: silent.is_some_and(|seconds| seconds > quiet_after),
    }
}

fn mandate_row(record: &Value, now: &str) -> MandateRow {
    let id = text(&record["mandate-id"]);
    let parent = record["parent"].as_str().unwrap_or("").to_owned();
    let not_after = text(&record["not-after"]);
    let revoked = record["revoked-at"].as_str();
    // Order matters: a revoked mandate that has also expired is reported as revoked, because that
    // is the fact an operator acted on.
    let state = if revoked.is_some() {
        "revoked"
    } else if not_after.as_str() < now {
        "expired"
    } else if age_seconds(now, &not_after).is_some_and(|left| left < EXPIRING_SOON_SECONDS) {
        "expiring"
    } else {
        "active"
    };
    MandateRow {
        short: short(&id),
        id,
        parent_short: short(&parent),
        parent,
        kind: text(&record["mandate-kind"]),
        grantor_subject: text(&record["grantor"]["subject"]),
        grantee_subject: text(&record["grantee-subject"]),
        not_after,
        state: state.to_owned(),
        state_class: match state {
            "revoked" | "expired" => "prohibited",
            "expiring" => "quiet",
            _ => "ok",
        }
        .to_owned(),
        components: patterns(&record["scope"]["components"]),
        actions: patterns(&record["scope"]["actions"]),
        classes: patterns(&record["scope"]["classes"]),
        resources: patterns(&record["scope"]["resources"]),
    }
}

fn revocation_row(record: &Value) -> RevocationRow {
    let revokes = text(&record["revokes"]);
    RevocationRow {
        revoked_at: text(&record["revoked-at"]),
        revokes_short: short(&revokes),
        revokes,
        reason: text(&record["reason"]),
        signer: text(&record["sig"]["key"]),
    }
}

fn rejection_row(record: &Value) -> RejectionRow {
    RejectionRow {
        seq: text(&record["seq"]),
        received_at: text(&record["received-at"]),
        reason: text(&record["reason"]),
        detail: text(&record["detail"]),
        submitted_by: text(&record["submitted-by"]),
        claimed_stream: text(&record["claimed-stream"]),
        claimed_seq: text(&record["claimed-seq"]),
        claimed_kind: text(&record["claimed-kind"]),
    }
}

impl Filters {
    fn from_params(params: &HashMap<String, String>) -> Self {
        let get = |name: &str| params.get(name).cloned().unwrap_or_default();
        Self {
            subject: get("subject"),
            mandate_ref: get("mandate-ref"),
            mandate_subtree_of: get("mandate-subtree-of"),
            classification: get("classification"),
            kind: get("kind"),
            action: get("action"),
            component: get("component"),
            stream: get("stream"),
            outcome: get("outcome"),
            human_root: get("human-root"),
            commitment_id: get("commitment-id"),
            correlation_ref: get("correlation-ref"),
            emitted_from: get("emitted-from"),
            emitted_to: get("emitted-to"),
            limit: match get("limit") {
                empty if empty.is_empty() => "200".to_owned(),
                given => given,
            },
            violations_only: get("violations-only") == "true",
        }
    }

    fn query(&self) -> EnvelopeQuery<'_> {
        fn set(value: &str) -> Option<&str> {
            if value.is_empty() { None } else { Some(value) }
        }
        EnvelopeQuery {
            subject: set(&self.subject),
            mandate_ref: set(&self.mandate_ref),
            mandate_subtree_of: set(&self.mandate_subtree_of),
            classification: set(&self.classification),
            kind: set(&self.kind),
            action: set(&self.action),
            component: set(&self.component),
            stream: set(&self.stream),
            emitted_from: set(&self.emitted_from),
            emitted_to: set(&self.emitted_to),
            correlation_ref: set(&self.correlation_ref),
            correlation_prefix: None,
            commitment_id: set(&self.commitment_id),
            outcome: set(&self.outcome),
            human_root: set(&self.human_root),
            violations_only: self.violations_only,
            limit: self.limit.parse().unwrap_or(200),
        }
    }

    fn to_query_string(&self) -> String {
        let mut parts = Vec::new();
        let mut push = |name: &str, value: &str| {
            if !value.is_empty() {
                parts.push(format!("{name}={}", percent_encode(value)));
            }
        };
        push("subject", &self.subject);
        push("mandate-ref", &self.mandate_ref);
        push("mandate-subtree-of", &self.mandate_subtree_of);
        push("classification", &self.classification);
        push("kind", &self.kind);
        push("action", &self.action);
        push("component", &self.component);
        push("stream", &self.stream);
        push("outcome", &self.outcome);
        push("human-root", &self.human_root);
        push("commitment-id", &self.commitment_id);
        push("correlation-ref", &self.correlation_ref);
        push("emitted-from", &self.emitted_from);
        push("emitted-to", &self.emitted_to);
        push("limit", &self.limit);
        if self.violations_only {
            parts.push("violations-only=true".to_owned());
        }
        parts.join("&")
    }
}

// -- small conversions --------------------------------------------------------------------------

/// A JSON value as display text, with every flavour of absence rendered the same way.
fn text(value: &Value) -> String {
    match value {
        Value::Null => "—".to_owned(),
        Value::String(s) if s.is_empty() => "—".to_owned(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The first 12 hex digits of a hash — enough to recognize, never enough to cite.
fn short(hash: &str) -> String {
    match hash.len() {
        0 => "—".to_owned(),
        len if len <= 12 => hash.to_owned(),
        _ => hash[..12].to_owned(),
    }
}

fn patterns(value: &Value) -> String {
    match value.as_array() {
        Some(items) if !items.is_empty() => items.iter().map(text).collect::<Vec<_>>().join(", "),
        _ => "—".to_owned(),
    }
}

/// Seconds between two timestamps, or `None` when either will not parse.
fn age_seconds(from: &str, to: &str) -> Option<i64> {
    let from = crate::clock::parse_timestamp(from).ok()?;
    let to = crate::clock::parse_timestamp(to).ok()?;
    Some((to - from) / 1_000)
}

fn humanize(seconds: i64) -> String {
    match seconds {
        s if s < 0 => "in the future".to_owned(),
        s if s < 120 => format!("{s}s"),
        s if s < 7_200 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3_600),
        s => format!("{}d", s / 86_400),
    }
}

/// Evidence rendered for a human, truncated so a large payload cannot flood the page.
fn preview(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let pretty = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok())
        .unwrap_or_else(|| text.into_owned());
    if pretty.len() <= PAYLOAD_PREVIEW_BYTES {
        return pretty;
    }
    let cut = pretty
        .char_indices()
        .take_while(|(index, _)| *index <= PAYLOAD_PREVIEW_BYTES)
        .last()
        .map_or(0, |(index, _)| index);
    format!(
        "{}\n… truncated; the full payload is at GET /v1/payloads/",
        &pretty[..cut]
    )
}

/// Percent-encode a query-string value. Unreserved characters (RFC 3986 §2.3) pass through.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// The policy's checkpoint interval is the honest threshold for "this stream has gone quiet": it is
/// the longest a live stream can be silent and still be producing the records the kernel expects.
async fn quiet_after_seconds(kernel: &Kernel) -> i64 {
    let Ok(Some(document)) = kernel.ingest.store().current_policy().await else {
        return 3_600;
    };
    crate::policy::Policy::parse(&document, kernel.ingest.policy_key())
        .map_or(3_600, |policy| policy.checkpoint_interval_seconds())
}

// -- responses -------------------------------------------------------------------------------

fn render<T: Template>(page: &T) -> Response {
    match page.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "a console template failed to render");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>the console could not render this page</h1>"),
            )
                .into_response()
        }
    }
}

fn notice(status: StatusCode, title: &str, detail: &str) -> Response {
    let page = NoticePage {
        title: title.to_owned(),
        detail: detail.to_owned(),
    };
    match page.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(_) => (status, Html(format!("<h1>{title}</h1>"))).into_response(),
    }
}

fn unavailable(error: &stozher_core::error::Error) -> Response {
    tracing::error!(error = %error, "the store could not answer the console");
    notice(
        StatusCode::SERVICE_UNAVAILABLE,
        "The kernel could not answer",
        "The store did not respond. Nothing was changed by this request — the console cannot \
         change anything — so it is safe to retry.",
    )
}

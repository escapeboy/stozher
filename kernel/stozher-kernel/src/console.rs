//! The console — `docs/design/console.md`, served from this binary.
//!
//! # One mutating route, and it does not mutate anything
//!
//! Every route below is registered with [`axum::routing::get`] except exactly one:
//! `POST /console/pending/{request-hash}/decide`. That route records a human's answer to a parked
//! request — the only mutating capability the console has in v1 — and it holds the property S3
//! predicted it would have to:
//!
//! > *"An 'approve' here would have to be a signature travelling through `POST /v1/ingest` like
//! > everything else."*
//!
//! It is. The route accepts an **already-signed** `gate-decision` object (§06 §1.2), checks it, and
//! submits a `gate-decision` envelope through [`crate::ingest::Ingest::submit`], which is still the
//! only path to [`crate::store::Store::append`]. There is no verdict parameter the kernel turns
//! into a signature, and no boolean anywhere on the path.
//!
//! # Where the approver's private key lives: nowhere in Stozher
//!
//! This is the most consequential decision in S4 and it is deliberate. The kernel holds **no**
//! approver key material, has no route that produces an approver's signature, and therefore cannot
//! manufacture an approval — not for an operator with a shell on the box, not for a compromised
//! kernel process, not for its own maintenance code. The party that enforces the gate is
//! structurally unable to satisfy it.
//!
//! The cost is real and is not hidden: the console cannot offer a one-click approve to a human who
//! has only a browser. The approver signs with `stozher-kernel decide`, which reads their own
//! owner-only seed file in their own process, and submits the resulting object. Browser-side
//! signing (WebCrypto Ed25519) plus a console session scheme would remove the friction without
//! moving the key onto the server — and ADR-0008 already places the console session scheme at S5,
//! which is where that pair belongs.
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
use axum::routing::{get, post};
use serde_json::Value;

use crate::http::Caller;
use crate::store::{EnvelopeQuery, Store};
use crate::{Kernel, checkpoint};

/// How far ahead of expiry a standing rule is worth surfacing.
const EXPIRING_SOON_SECONDS: i64 = 7 * 86_400;
/// Rows shown on a summary panel before the full view is needed.
const PREVIEW_ROWS: i64 = 10;
/// The largest evidence payload rendered inline. Bigger evidence is named, not shown.
const PAYLOAD_PREVIEW_BYTES: usize = 8_192;
/// Rows the regulator export pulls per round trip. Not a cap on the export — it pages until the
/// filtered set is exhausted — only a bound on how much of it is in flight at once.
const EXPORT_PAGE_ROWS: i64 = 10_000;
/// How far a mandate walk follows `parent` looking for the human root, matching the envelope page.
const MANDATE_CHAIN_LINKS: u32 = 16;

/// Build the console router.
pub fn router(kernel: Arc<Kernel>) -> Router {
    Router::new()
        .route("/console", get(overview))
        .route("/console/audit", get(audit))
        .route("/console/audit/export", get(export))
        .route("/console/attempts", get(attempts))
        .route("/console/pending", get(pending))
        // The one mutating route in v1. It records a signature; it does not create one.
        .route("/console/pending/{request_hash}/decide", post(decide))
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
    /// How long until that moment, in human units, or how long since it passed.
    pub expires_in: String,
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

/// One parked request in the kernel-native pending queue (§06 §4.3).
pub struct PendingRow {
    /// `object-hash` of the request — what a signature covers.
    pub request_hash: String,
    /// Short form, for a table cell.
    pub short: String,
    /// The subject that asked.
    pub subject: String,
    /// The key that will sign the effect, and that any approval binds.
    pub subject_key: String,
    /// The authenticated caller that submitted the request, which need not be the subject it names.
    pub submitted_by: String,
    /// Emitting component.
    pub component: String,
    /// Weight class.
    pub class: String,
    /// Action type.
    pub action: String,
    /// Thing acted upon.
    pub target: String,
    /// `object-hash` of the call's arguments — what the approval pins, not what it displays.
    pub args_hash: String,
    /// The mandate the effect will cite.
    pub mandate_ref: String,
    /// Short form of the mandate.
    pub mandate_short: String,
    /// The named human the mandate chain terminates at (§03 §5) — "on whose authority".
    pub human_root: String,
    /// The policy version that classified it.
    pub policy_version: String,
    /// When the component asked.
    pub requested_at: String,
    /// When the request stops being answerable.
    pub not_after: String,
    /// How long until that moment, in human units. An approver reading a queue is deciding what to
    /// answer first, and "in 12m" answers that where a second ISO 8601 string does not.
    pub expires_in: String,
    /// Whether that moment has passed. A timed-out gate is a block, never an allow (§06 §4.6).
    pub expired: bool,
    /// How many channels delivered an approver ping.
    pub notified: String,
    /// How many failed.
    pub notify_failures: String,
    /// Why the last one failed, if one did.
    pub notify_failure: String,
    /// The exact request object, rendered so an approver reads what they would be signing over.
    pub request_json: String,
    /// This caller's CSRF token for this request.
    pub csrf: String,
    /// `approve` or `deny`, once a human has answered.
    pub verdict: String,
    /// Their stated reason, for a denial.
    pub reason: String,
    /// The key that signed the answer.
    pub decided_by: String,
    /// When.
    pub decided_at: String,
    /// The chained envelope the answer was recorded as (§06 §5).
    pub decision_envelope: String,
    /// Short form of that envelope id.
    pub decision_short: String,
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
    /// Rows this page drew.
    shown: String,
    /// Rows the filters match, which is a different number and is stated as one.
    matched: String,
    /// Whether the two differ, so the page can say so rather than leave it to be noticed.
    truncated: bool,
    /// The closed vocabularies the three enumerated filters range over, offered rather than recalled.
    classes: &'static [&'static str],
    kinds: &'static [&'static str],
    outcomes: &'static [&'static str],
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
    channels: String,
    parked: Vec<PendingRow>,
    answered: Vec<PendingRow>,
    rows: Vec<Row>,
    denied: Vec<Row>,
    /// §09 §7: a spike is surfaced as a finding, not as a longer queue.
    spikes: Vec<SpikeRow>,
    spike_window: String,
    spike_cap: String,
    /// The envelope a decision this caller just recorded became, if they arrived from the form.
    recorded: String,
    /// Short form of it, for the link text.
    recorded_short: String,
    /// The verdict that was recorded — `approve` or `deny`, and named rather than implied.
    recorded_verdict: String,
}

/// One subject parking gate requests fast enough to be worth naming.
struct SpikeRow {
    subject: String,
    parked: String,
    latest: String,
    /// Whether this subject is at or over the cap, and therefore being refused right now.
    refused: bool,
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
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
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
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
        return response;
    }
    let filters = Filters::from_params(&params);
    let store = kernel.ingest.store();
    let records = match store.query(&filters.query()).await {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    // Matched and shown are different numbers and the page says both. Rendering only the second as
    // "N record(s)" made a filter that matched five thousand look like one that matched two hundred.
    let matched = match store.query_count(&filters.query()).await {
        Ok(matched) => matched,
        Err(e) => return unavailable(&e),
    };
    render(&AuditPage {
        title: "Audit explorer",
        query: filters.to_export_query_string(),
        shown: records.len().to_string(),
        matched: matched.to_string(),
        truncated: matched > records.len() as u64,
        classes: &stozher_core::envelope::CLASSES,
        kinds: &stozher_core::envelope::KINDS,
        outcomes: &stozher_core::envelope::OUTCOMES,
        rows: records.iter().map(row).collect(),
        f: filters,
    })
}

/// The regulator's copy: newline-delimited canonical envelopes, exactly as signed.
///
/// Not CSV. A spreadsheet cannot carry a signature, and an export a regulator cannot re-verify is
/// an assertion rather than evidence. Each line is the stored `JCS(envelope)`, so `id()` and the
/// Ed25519 signature reproduce from the file alone.
///
/// # The export is complete, and that is the whole point
///
/// It used to inherit the audit page's `limit` — 200 by default — and say nothing about it, while
/// `Content-Disposition` presented the result as a finished file. For a product sold on provable
/// auditability, an export that quietly drops evidence is the worst defect available: a regulator
/// cannot tell a complete file from a truncated one, and neither can the operator who sent it.
///
/// So `limit` is not read here at all, not even when a caller supplies one by hand. The filtered set
/// is paged out of the store in whole batches until it is exhausted. Nothing is added to the body to
/// say so, because nothing needs to be: every line is an envelope, which is what the audit page
/// promises a regulator, and a marker line would break the parser that promise is for.
async fn export(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
        return response;
    }
    let filters = Filters::from_params(&params);
    let store = kernel.ingest.store();
    let mut body = String::new();
    let mut exported: u64 = 0;
    loop {
        let mut page = filters.query();
        page.limit = EXPORT_PAGE_ROWS;
        page.offset = i64::try_from(exported).unwrap_or(i64::MAX);
        let records = match store.query(&page).await {
            Ok(records) => records,
            Err(e) => return unavailable(&e),
        };
        if records.is_empty() {
            break;
        }
        for record in &records {
            match stozher_core::jcs::canonicalize(record) {
                Ok(line) => {
                    body.push_str(&line);
                    body.push('\n');
                }
                Err(e) => return unavailable(&e),
            }
        }
        exported += records.len() as u64;
        if i64::try_from(records.len()).unwrap_or(i64::MAX) < EXPORT_PAGE_ROWS {
            break;
        }
    }
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/x-ndjson; charset=utf-8".to_owned(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"stozher-audit-export.ndjson\"".to_owned(),
            ),
            // Not the record of truth — the body is — but it lets a caller assert completeness
            // without counting lines, and it costs nothing.
            (
                axum::http::HeaderName::from_static("x-stozher-export-records"),
                exported.to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

async fn attempts(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
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

/// The daily driver (`docs/design/console.md` §1): everything waiting on a named human.
///
/// Three sections, and the distinction between them is the point. **Parked** requests are the
/// kernel-native queue (§06 §4.3) — questions nobody has answered. **Answered** requests carry a
/// human's signature, including the denials, with the reason they gave. **Blocked** effect envelopes
/// are the older surface: actions that did not reach the world and whose emitting component holds
/// the park itself. A page that merged them would tell an approver that something needs them when
/// it is already decided, or the reverse.
async fn pending(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let subject = match console_caller(&kernel, &headers) {
        Caller::Subject(subject) => subject,
        Caller::Refused(response) => return response,
    };
    let store = kernel.ingest.store();
    let now = kernel.ingest.clock().now();
    let parked = match store.gate_queue(false, &now, 1_000).await {
        Ok(rows) => rows,
        Err(e) => return unavailable(&e),
    };
    let answered = match store.gate_queue(true, &now, 1_000).await {
        Ok(rows) => rows,
        Err(e) => return unavailable(&e),
    };
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
    // §09 §7 requires a spike to be surfaced *as a finding*. Half the cap is the threshold worth
    // naming: by the time a subject is being refused, an approver has already had a queue's worth
    // of attention spent on it, and the point of the finding is to arrive before that.
    let limit = kernel.config.gate_rate_limit;
    let watch_from = match crate::clock::shift(&now, -limit.window_seconds) {
        Ok(since) => since,
        Err(e) => return unavailable(&e),
    };
    let threshold = (limit.per_subject / 2).max(1);
    let spikes = match store.gate_request_spikes(&watch_from, threshold).await {
        Ok(spikes) => spikes,
        Err(e) => return unavailable(&e),
    };

    // The confirmation the decide route redirects back with. Both members are checked against their
    // own vocabulary rather than rendered as given: a banner is the one part of this page a link
    // could otherwise choose the wording of.
    let recorded = params
        .get("recorded")
        .filter(|id| stozher_core::crypto::is_digest_hex(id))
        .cloned()
        .unwrap_or_default();
    let recorded_verdict = params
        .get("verdict")
        .filter(|v| ["approve", "deny"].contains(&v.as_str()))
        .cloned()
        .unwrap_or_default();

    render(&PendingPage {
        title: "Pending approvals",
        recorded_short: short(&recorded),
        recorded: if recorded_verdict.is_empty() {
            String::new()
        } else {
            recorded
        },
        recorded_verdict,
        channels: kernel.notifier.channel_count().to_string(),
        spike_window: limit.window_seconds.to_string(),
        spike_cap: limit.per_subject.to_string(),
        spikes: spikes
            .iter()
            .map(|s| SpikeRow {
                subject: s["subject"].as_str().unwrap_or_default().to_owned(),
                parked: s["parked"].to_string(),
                latest: s["latest"].as_str().unwrap_or("-").to_owned(),
                refused: s["parked"].as_u64().unwrap_or(0) >= u64::from(limit.per_subject),
            })
            .collect(),
        parked: pending_rows(&parked, &kernel, &subject, &now).await,
        answered: pending_rows(&answered, &kernel, &subject, &now).await,
        rows: blocked.iter().map(row).collect(),
        denied: denied.iter().map(row).collect(),
    })
}

/// Record a named human's answer to a parked request — the console's only mutating capability.
///
/// # What this route does and does not do
///
/// It **does not decide anything**. It receives a `gate-decision` object that a human already signed
/// with a key this kernel has never held, checks it against §06 §1.2 and against the request it
/// claims to answer, and then submits a `gate-decision` envelope through the ordinary ingest
/// pipeline so the answer is chained and checkpointed like every other fact (§06 §5).
///
/// The envelope's own signature is the **kernel's**, and it attests only receipt and chain position
/// — exactly what the kernel's signature on a rejection record attests. The *authority* is the inner
/// object, and [`crate::ingest`] re-verifies that independently, so a kernel-signed envelope wrapping
/// a forged decision is refused by the same code path that would refuse it from anyone else.
async fn decide(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(request_hash): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let subject = match console_caller(&kernel, &headers) {
        Caller::Subject(subject) => subject,
        Caller::Refused(response) => return response,
    };
    let form = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
    let (csrf, decision) = match submitted_decision(&body, form) {
        Ok(parts) => parts,
        Err(e) => return decision_refusal(form, StatusCode::BAD_REQUEST, e.code(), e.detail()),
    };

    // CSRF before anything is read from the store, so a forged cross-site post cannot even probe
    // which request hashes exist.
    if !kernel.csrf_ok(&subject, &request_hash, &csrf) {
        return decision_refusal(
            form,
            StatusCode::FORBIDDEN,
            "console-csrf-invalid",
            "this form was not issued to this caller by this kernel for this request",
        );
    }

    let store = kernel.ingest.store();
    let request = match store.gate_request(&request_hash).await {
        Ok(Some((request, _))) => request,
        Ok(None) => {
            return decision_refusal(
                form,
                StatusCode::NOT_FOUND,
                "not-found",
                "no such parked request",
            );
        }
        Err(e) => return unavailable(&e),
    };
    let now = kernel.ingest.clock().now();
    let requested_at = request["requested-at"].as_str().unwrap_or(&now).to_owned();
    let queued = match crate::gatequeue::validate(&request, &requested_at) {
        Ok(queued) => queued,
        Err(e) => return unavailable(&e),
    };
    let checked = match crate::gatequeue::check_decision(&decision, &queued) {
        Ok(checked) => checked,
        Err(e) => {
            return decision_refusal(form, StatusCode::UNPROCESSABLE_ENTITY, e.code(), e.detail());
        }
    };

    // §06 §5, the approver set — resolved by ingest, so the console cannot hold a second opinion.
    let approvers = match kernel
        .ingest
        .approvers_for(&queued.classification, &queued.action, &checked.decided_at)
        .await
    {
        Ok(approvers) => approvers,
        Err(e) => return unavailable(&e),
    };
    let Some(approver) = approvers.iter().find(|a| a.key == checked.decided_by) else {
        return decision_refusal(
            form,
            StatusCode::FORBIDDEN,
            "gate-approver-not-permitted",
            &format!("{} may not answer this request", checked.decided_by),
        );
    };
    // §06 §5 again, over the *subject*: a human holding a second key is still the same human, and
    // self-approval is prohibited for the person, not the keypair. The subject comes from the
    // approver resolution itself, so both kinds §06 §5 names — an enrolled root and a human holding
    // a mandate — are covered; reading the root set alone would see only the first.
    if approver.subject.as_deref() == Some(queued.subject.as_str()) {
        return decision_refusal(
            form,
            StatusCode::FORBIDDEN,
            "gate-self-approval",
            "a subject may not answer its own request",
        );
    }

    match submit_decision(&kernel, &request_hash, &checked.decision).await {
        Ok(envelope_id) => {
            if form {
                // A browser gets a redirect so a refresh cannot repost the decision. The signature
                // is single-use at ingest anyway; this is politeness, not the defence. The verdict
                // and the envelope it became travel in the location, so the page it lands on can
                // say what was recorded — a bare 303 left the human to infer it from a queue that
                // is one row shorter.
                return (
                    StatusCode::SEE_OTHER,
                    [(
                        axum::http::header::LOCATION,
                        format!(
                            "/console/pending?recorded={envelope_id}&verdict={}",
                            percent_encode(&checked.verdict)
                        ),
                    )],
                )
                    .into_response();
            }
            json_response(
                StatusCode::CREATED,
                &serde_json::json!({
                    "stozher": stozher_core::VERSION,
                    "result": "recorded",
                    "request-hash": request_hash,
                    "decision": checked.verdict,
                    "decided-by": checked.decided_by.as_str(),
                    "envelope-id": envelope_id
                }),
            )
        }
        Err((code, _)) if code == crate::codes::STORE_UNAVAILABLE => unavailable(
            &stozher_core::error::Error::new(crate::codes::STORE_UNAVAILABLE, "recording refused"),
        ),
        Err((code, detail)) => {
            decision_refusal(form, StatusCode::UNPROCESSABLE_ENTITY, &code, &detail)
        }
    }
}

/// Build, sign and submit the `gate-decision` envelope (§06 §5).
///
/// The kernel's core stream is written by more than this route — genesis, root changes, policy
/// publication — so the chain position is taken under contention and retried a bounded number of
/// times. A retry re-signs, because `seq` and `prev-hash` are inside the signed bytes.
async fn submit_decision(
    kernel: &Kernel,
    request_hash: &str,
    decision: &Value,
) -> std::result::Result<String, (String, String)> {
    const ATTEMPTS: usize = 8;
    let unavailable = |e: stozher_core::error::Error| (e.code().to_owned(), e.detail().to_owned());
    let stream = kernel.config.kernel_core_stream.clone();
    let mut last = None;
    for _ in 0..ATTEMPTS {
        let head = kernel
            .ingest
            .store()
            .stream_head(&stream)
            .await
            .map_err(unavailable)?;
        let (seq, prev) = match head {
            Some((head_seq, head_id)) => (head_seq + 1, Some(head_id)),
            None => (0, None),
        };
        let key = kernel.ingest.kernel_key();
        let envelope = key
            .sign(&serde_json::json!({
                "v": stozher_core::VERSION,
                "kind": "gate-decision",
                "emitted-at": kernel.ingest.clock().now(),
                "stream": stream,
                "seq": seq,
                "prev-hash": prev,
                "identity": {
                    "subject": "agent:kernel",
                    "key": key.id().as_str(),
                    "component": "kernel"
                },
                "decision-of": request_hash,
                "decision": decision
            }))
            .map_err(unavailable)?;
        let request = serde_json::json!({ "envelope": envelope, "payloads": [] });
        let raw = stozher_core::jcs::canonicalize(&request).map_err(unavailable)?;
        match kernel
            .ingest
            .submit(raw.as_bytes(), Some("agent:kernel"))
            .await
        {
            crate::Outcome::Accepted(appended) => return Ok(appended.id),
            crate::Outcome::Rejected { reason, detail, .. }
                if reason == "chain-seq-duplicate" || reason == "chain-prev-hash-mismatch" =>
            {
                last = Some((reason, detail));
            }
            crate::Outcome::Rejected { reason, detail, .. } => return Err((reason, detail)),
            crate::Outcome::Unavailable(detail) => {
                return Err((crate::codes::STORE_UNAVAILABLE.to_owned(), detail));
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        (
            crate::codes::STORE_UNAVAILABLE.to_owned(),
            "the kernel's core stream is too contended to record the decision".to_owned(),
        )
    }))
}

/// Pull `(csrf, decision)` out of a JSON or form-encoded submission.
fn submitted_decision(body: &[u8], form: bool) -> stozher_core::error::Result<(String, Value)> {
    use stozher_core::error::Error;

    let text = std::str::from_utf8(body)
        .map_err(|e| Error::new("jcs-malformed-json", format!("body is not UTF-8: {e}")))?;
    let (csrf, decision) = if form {
        let mut csrf = String::new();
        let mut decision = String::new();
        for pair in text.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            match name {
                "csrf" => csrf = form_decode(value),
                "decision" => decision = form_decode(value),
                _ => {}
            }
        }
        (csrf, stozher_core::jcs::parse(&decision)?)
    } else {
        let body = stozher_core::jcs::parse(text)?;
        (
            body["csrf"].as_str().unwrap_or_default().to_owned(),
            body.get("decision")
                .cloned()
                .ok_or_else(|| Error::new("schema-missing-member", "decision"))?,
        )
    };
    if csrf.is_empty() {
        return Err(Error::new("schema-missing-member", "csrf"));
    }
    Ok((csrf, decision))
}

/// `application/x-www-form-urlencoded` value decoding.
fn form_decode(value: &str) -> String {
    let octets = value.as_bytes();
    let mut out = Vec::with_capacity(octets.len());
    let mut index = 0;
    while index < octets.len() {
        match octets[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < octets.len() => {
                match u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decision_refusal(form: bool, status: StatusCode, code: &str, reason: &str) -> Response {
    if form {
        return notice(
            status,
            "The decision was refused",
            &format!("{code}: {reason}"),
        );
    }
    json_response(
        status,
        &serde_json::json!({
            "stozher": stozher_core::VERSION,
            "result": "rejected",
            "reason-code": code,
            "reason": reason,
            "retryable": false
        }),
    )
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    (status, axum::Json(value.clone())).into_response()
}

async fn mandates(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
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
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
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
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
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
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
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
    if let Caller::Refused(response) = console_caller(&kernel, &headers) {
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
        let now = kernel.ingest.clock().now();
        Ok(Self {
            envelopes: usize::try_from(store.envelope_count().await?).unwrap_or(usize::MAX),
            attempts: count(Some("attempted"), false).await?,
            violations: count(None, true).await?,
            // What actually needs a human: unanswered parked requests plus effects that did not
            // reach the world and are waiting. Counting only the second undercounted the queue by
            // exactly the amount ADR-0008 §A said the kernel could not see.
            pending: store.gate_queue(false, &now, 10_000).await?.len()
                + count(Some("blocked"), false).await?,
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
        decided_by: short_key(&text(&envelope["authorization"]["decision"]["sig"]["key"])),
    }
}

async fn pending_rows(
    records: &[Value],
    kernel: &Kernel,
    caller_subject: &str,
    now: &str,
) -> Vec<PendingRow> {
    let mut rows = Vec::with_capacity(records.len());
    for record in records {
        rows.push(pending_row(record, kernel, caller_subject, now).await);
    }
    rows
}

async fn pending_row(
    record: &Value,
    kernel: &Kernel,
    caller_subject: &str,
    now: &str,
) -> PendingRow {
    let request_hash = text(&record["request-hash"]);
    let mandate_ref = text(&record["mandate-ref"]);
    let decision_envelope = record["decision-envelope-id"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let not_after = text(&record["not-after"]);
    PendingRow {
        short: short(&request_hash),
        // The request is shown in full, canonicalized, because an approver signs over its hash and
        // is owed the bytes that hash covers — a summary would be a different object.
        request_json: stozher_core::jcs::canonicalize(&record["request"])
            .unwrap_or_else(|_| "—".to_owned()),
        csrf: kernel.csrf_token(caller_subject, &request_hash),
        request_hash,
        subject: text(&record["subject"]),
        subject_key: text(&record["subject-key"]),
        submitted_by: text(&record["submitted-by"]),
        component: text(&record["component"]),
        class: text(&record["classification"]),
        action: text(&record["action"]),
        target: text(&record["target"]),
        args_hash: short(&text(&record["args-hash"])),
        mandate_short: short(&mandate_ref),
        human_root: human_root_of(kernel.ingest.store(), &mandate_ref).await,
        mandate_ref,
        policy_version: text(&record["policy-version"]),
        requested_at: text(&record["requested-at"]),
        expires_in: age_seconds(now, &not_after).map_or_else(|| "—".to_owned(), humanize),
        not_after,
        expired: record["expired"].as_bool().unwrap_or(false),
        notified: text(&record["notified"]),
        notify_failures: text(&record["notify-failures"]),
        notify_failure: record["last-notify-failure"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        verdict: record["verdict"].as_str().unwrap_or("").to_owned(),
        reason: text(&record["reason"]),
        decided_by: short_key(&text(&record["decided-by"])),
        decided_at: text(&record["decided-at"]),
        decision_short: short(&decision_envelope),
        decision_envelope,
    }
}

/// The named human a mandate chain terminates at (§03 §5) — the answer to "on whose authority".
///
/// A parked request has no envelope yet, so the chain the *blocked* table renders from a stored
/// envelope has to be walked from the `mandate-ref` itself. An unresolvable chain renders as an em
/// dash rather than as a plausible-looking name: this is the field an approver decides on.
async fn human_root_of(store: &Store, mandate_ref: &str) -> String {
    if mandate_ref.is_empty() || mandate_ref == "—" {
        return "—".to_owned();
    }
    let Ok(ancestry) = store
        .mandate_ancestry(mandate_ref, MANDATE_CHAIN_LINKS)
        .await
    else {
        return "—".to_owned();
    };
    let mut cursor = mandate_ref.to_owned();
    for _ in 0..=MANDATE_CHAIN_LINKS {
        let Some(mandate) = ancestry.get(&cursor) else {
            return "—".to_owned();
        };
        match mandate["parent"].as_str().filter(|p| !p.is_empty()) {
            Some(parent) => cursor = parent.to_owned(),
            None => return text(&mandate["grantor"]["subject"]),
        }
    }
    "—".to_owned()
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
        expires_in: age_seconds(now, &not_after).map_or_else(
            || "—".to_owned(),
            |left| {
                if left < 0 {
                    format!("{} ago", humanize(-left))
                } else {
                    format!("in {}", humanize(left))
                }
            },
        ),
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
        signer: short_key(&text(&record["sig"]["key"])),
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
            offset: 0,
        }
    }

    /// The filter query string for the regulator export.
    ///
    /// `limit` is deliberately absent. It is the page's row cap and has nothing to do with what a
    /// regulator asked for; carrying it into the export is what made the export silently drop
    /// evidence while `Content-Disposition` presented the result as a finished file.
    fn to_export_query_string(&self) -> String {
        self.to_query_string()
            .split('&')
            .filter(|part| !part.starts_with("limit="))
            .collect::<Vec<_>>()
            .join("&")
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

/// A key identifier at the same width as every other identifier on these pages.
///
/// A full `ed25519:` key is 72 characters in a `white-space: nowrap` cell, which pushed the columns
/// after it off the right edge of the page — including the denial *reason*, which is the one thing a
/// reader of the answered queue most needs. The algorithm prefix stays because it is the part that
/// is not a hash.
fn short_key(key: &str) -> String {
    match key.split_once(':') {
        Some((algorithm, material)) => format!("{algorithm}:{}", short(material)),
        None => short(key),
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
        "{}\n… truncated for display; the whole payload is served by GET /v1/payloads/<hash>",
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

/// Authenticate a console request, answering a refusal in the console's own voice.
///
/// The rule is [`crate::http::caller_subject`]'s and only that one — §05 §2.2 applies to these pages
/// exactly as it applies to `/v1/*`, and a console-only login would be a second credential path to
/// hold correct. What changes is the answer. A person who opens `/console` in a browser without a
/// credential used to receive a raw JSON error body and no `WWW-Authenticate` header at all, which
/// tells them nothing and gives the browser nothing to act on. The 404 page is the model.
fn console_caller(kernel: &Kernel, headers: &HeaderMap) -> Caller {
    match crate::http::caller_subject(kernel, headers) {
        Ok(subject) => Caller::Subject(subject),
        Err(detail) => Caller::Refused(unauthenticated(&detail)),
    }
}

fn unauthenticated(detail: &str) -> Response {
    let page = NoticePage {
        title: "This console needs a credential".to_owned(),
        detail: format!(
            "{detail}. Every console page reads the audit trail, so every console page requires \
             the same Bearer credential as the API (spec/05 §2.2) — one readable by anyone who \
             could reach the port would be a different product. Send \
             `Authorization: Bearer <token>`; the tokens a deployment accepts are the `callers` \
             entries of its configuration."
        ),
    };
    let headers = [(
        axum::http::header::WWW_AUTHENTICATE,
        "Bearer realm=\"stozher console\"",
    )];
    match page.render() {
        Ok(body) => (StatusCode::UNAUTHORIZED, headers, Html(body)).into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            headers,
            Html("<h1>this console needs a credential</h1>"),
        )
            .into_response(),
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

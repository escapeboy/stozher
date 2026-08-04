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
use crate::store::{self, EnvelopeQuery, OwnedCursor, Store};
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
/// Every filter the regulator export accepts. Anything else is refused rather than ignored — see
/// `export`. Kept beside `Filters::from_params`, which reads exactly these names.
const EXPORT_FILTERS: [&str; 17] = [
    "subject",
    "mandate-ref",
    "mandate-subtree-of",
    "classification",
    "kind",
    "action",
    "component",
    "stream",
    "outcome",
    "human-root",
    "commitment-id",
    "correlation-ref",
    "emitted-from",
    "emitted-to",
    "limit",
    "violations-only",
    // Accepted and deliberately ignored, which is the opposite of the bug above rather than an
    // instance of it. The console links to this export from a paged view, so the page cursor rides
    // along in the query string; honouring it would silently *drop* every record before page two.
    // `the_export_carries_every_envelope_once_and_ignores_the_page_cursor` pins that.
    "after",
];
/// The renderings the export offers. `ndjson` is the record; `html` is a reading of it.
///
/// Not a filter — it changes how the matched set is presented, never which records match — so it is
/// permitted beside the filters rather than added to them, and an unrecognised *value* is refused
/// for the same reason an unrecognised filter is: a silent fallback hands back a file that looks
/// like the answer to the question that was asked.
const EXPORT_FORMATS: [&str; 2] = ["ndjson", "html"];
/// The route serving what an envelope's `evidence.payload-hash` commits to.
const PAYLOAD_ROUTE: &str = "/v1/payloads/{payload-hash}";
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
    /// `evidence.payload-hash` in full, empty when the envelope commits to no payload.
    ///
    /// The whole hash and not `short()`'s twelve digits, because this one is a route and not a
    /// label: `GET /v1/payloads/<hash>` serves the payload the envelope commits to, and for an
    /// effect that payload holds the call's arguments. An incident responder read an export, found
    /// `args-hash` and nothing else, and reported that applied effects retain no arguments — they
    /// are retained, and nothing on the way from the export to them said where.
    pub payload_hash: String,
    /// The approver, when the envelope carries a decision.
    pub decided_by: String,
    /// `approve` or `deny`, when the envelope carries a decision.
    pub decision: String,
    /// The reason a decision gave, which for a denial is the whole content of the record.
    ///
    /// A compliance officer exported six human decisions and got six identical blank rows: the
    /// table was built from `execution.*`, which a `gate-decision` does not have, and the denial
    /// reason — *"no DBA sign-off on the lock estimate; re-file with an EXPLAIN"* — existed only
    /// in the NDJSON. An export that drops the sentence a human wrote is not an audit artefact.
    pub decision_reason: String,
}

/// One stream, with the quiet-stream finding already computed.
#[derive(Clone)]
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
    /// `healthy` | `quiet` | `refused` (§09 §4.2).
    pub status: String,
    /// Whether the most recent submission on this stream was rejected. **Not** the same finding as
    /// `quiet`, and it fires immediately rather than after the quiet interval.
    pub refused: bool,
    /// The reason code the kernel gave, when `refused`.
    pub refusal_reason: String,
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
    /// `object-hash` of the call's arguments — what the approval pins. Shown in full, because it is
    /// the digest an approver recomputes from the arguments below (§06 §4.4 rule 5); a short form
    /// would be a hash nobody can check.
    pub args_hash: String,
    /// The argument values, canonical, as submitted with the request (§06 §4.4). Empty when none
    /// are being shown — which [`Self::arguments_supplied`] distinguishes from a call that took no
    /// arguments, since the second is the two characters `{}` and the first is nothing at all.
    pub arguments: String,
    /// Whether there are values to show. False covers both "the component supplied none" and "the
    /// request has expired, so they are no longer served" (§06 §4.4 rules 7 and 8).
    pub arguments_supplied: bool,
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
    /// Resume position, as [`stozher_kernel_cursor`] writes it.
    ///
    /// [`stozher_kernel_cursor`]: crate::store::Cursor::encode
    pub after: String,
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
    refused_count: String,
    quiet_after: String,
    rows: Vec<Row>,
    expiring: Vec<MandateRow>,
    quiet: Vec<StreamRow>,
    refused: Vec<StreamRow>,
}

/// The export as a document a person reads, rather than a file a verifier parses.
///
/// A compliance officer produced the cover memo for their auditor by hand, because the product
/// emits NDJSON and NDJSON is not a document. This is the missing artefact — and it is deliberately
/// not the artefact of record. It carries no signatures and re-derives nothing; a reader who wants
/// to check the claim goes to the NDJSON, which this document says in its own text. A rendering
/// that let itself be mistaken for evidence would be worse than no rendering.
#[derive(Template)]
#[template(path = "export.html")]
struct ExportDocument {
    title: &'static str,
    /// The filters that produced this set, restated so the document says which question it answers.
    query: String,
    /// How many records matched.
    records: String,
    /// Where the values behind `args-hash` are served.
    payload_route: &'static str,
    rows: Vec<Row>,
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
    /// Parameters in the address that name no filter, so the page can say they were dropped.
    ///
    /// Not an error page: a typo while browsing should not be one, which is why `export` refuses
    /// and this does not. But the count beside it reads "N record(s) match these filters", and an
    /// incident responder who typed `?class=consequential` — the field is `classification` — was
    /// handed every record under that sentence. Widening silently while asserting the filter held
    /// is the defect; saying so costs a line.
    ignored: Vec<String>,
    /// Whether the two differ, so the page can say so rather than leave it to be noticed.
    truncated: bool,
    /// Whether this is a later page, so "showing N" cannot be misread as "there are N".
    paged: bool,
    /// The link to the next page, absent when this one is the last.
    next: Option<String>,
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
    /// Whether the verified range begins at the origin of the stream.
    ///
    /// `ChainResult::anchored` — `first_seq == 0 || expected_first_prev.is_some()` — which is a
    /// statement about the *range*, not about a checkpoint. The page rendered it under the caption
    /// "Anchored to a signed checkpoint", so a stream verified from seq 0 with no checkpoint at all
    /// reported yes. A compliance evaluator read that as external attestation, which is the one
    /// thing it has never meant.
    rooted: bool,
    /// Whether a signed checkpoint attests this stream's head. A different question, now asked
    /// separately, because these two can and do disagree.
    attested: bool,
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
    /// §06 §4.4 rule 9, surfaced the way §09 §7 surfaces its own cap: as a finding, not as a
    /// longer list. ADR-0032 §5 named the absence of this.
    mismatches: Vec<MismatchRow>,
    mismatch_window: String,
    mismatch_cap: String,
}

/// A caller that has submitted arguments its own requests do not commit to, often enough to name.
struct MismatchRow {
    submitted_by: String,
    recorded: String,
    latest: String,
    /// At or over the cap, so further mismatches from this caller are refused *without* a record.
    /// Worth saying out loud: past this point the finding stops growing, and the reason it stops is
    /// not that the component stopped.
    capped: bool,
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
    let rows_by_status: Vec<StreamRow> = stream_rows
        .iter()
        .map(|s| stream_row(s, &now, quiet_after))
        .collect();
    // Refused first, and above the quiet list rather than inside it. They were the same list until
    // §09 §4.2 gained its third requirement, which meant a stream the kernel was actively rejecting
    // reached this page only once it had *also* been silent for the checkpoint interval — the weaker
    // fact, an hour later, in a row that said nothing about a refusal.
    let refused: Vec<StreamRow> = rows_by_status
        .iter()
        .filter(|s| s.refused)
        .cloned()
        .collect();
    let quiet: Vec<StreamRow> = rows_by_status.into_iter().filter(|s| s.quiet).collect();

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
        refused_count: refused.len().to_string(),
        refused,
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
    // Named, not refused. `export` refuses because that artefact leaves the building; this page is
    // browsed, and a typo in the address bar should not be an error. What it must not do is drop
    // the parameter and still say "N record(s) match these filters".
    let mut ignored: Vec<String> = params
        .keys()
        .filter(|name| !EXPORT_FILTERS.contains(&name.as_str()))
        .cloned()
        .collect();
    ignored.sort_unstable();
    let Ok(resume) = filters.cursor() else {
        // A malformed cursor is refused rather than ignored. Silently starting over would answer a
        // request for a later page with the first one, and an auditor reading rows they had already
        // read has no way to tell that from rows they had not.
        return notice(
            StatusCode::BAD_REQUEST,
            "That page cursor is not one this console wrote",
            "`after` must name a row this console handed out. Follow the paging links rather than \
             editing the parameter, or drop it to start from the newest record.",
        );
    };
    let store = kernel.ingest.store();
    let query = filters.query_from(resume.as_ref());
    let records = match store.query(&query).await {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    // Matched and shown are different numbers and the page says both. Rendering only the second as
    // "N record(s)" made a filter that matched five thousand look like one that matched two hundred.
    // `matched` is the whole filtered set, not the remainder after the cursor: a count that shrank
    // as the reader paged would make page three of five read like the end.
    let matched = match store.query_count(&filters.query()).await {
        Ok(matched) => matched,
        Err(e) => return unavailable(&e),
    };
    // A full page is the signal that there may be more. It can be one page early — a set whose size
    // is an exact multiple of the cap offers a link to an empty page — and that is the direction to
    // be wrong in: an auditor who follows it sees "no further records", whereas the reverse hides
    // evidence behind a link that was never drawn.
    let next = if i64::try_from(records.len()).unwrap_or(i64::MAX) == query.limit.clamp(1, 10_000) {
        store::cursor_after(&records).map(|cursor| {
            let filters = filters.to_query_string();
            let after = percent_encode(&cursor.encode());
            if filters.is_empty() {
                format!("/console/audit?after={after}")
            } else {
                format!("/console/audit?{filters}&after={after}")
            }
        })
    } else {
        None
    };
    render(&AuditPage {
        title: "Audit explorer",
        query: filters.to_export_query_string(),
        shown: records.len().to_string(),
        matched: matched.to_string(),
        truncated: matched > records.len() as u64,
        paged: resume.is_some(),
        next,
        classes: &stozher_core::envelope::CLASSES,
        kinds: &stozher_core::envelope::KINDS,
        outcomes: &stozher_core::envelope::OUTCOMES,
        rows: records.iter().map(row).collect(),
        ignored,
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
    // An unrecognised filter is refused *here* and nowhere else. `Filters::from_params` reads the
    // names it knows and ignores the rest, which is right for a page an operator is browsing — a
    // typo in the address bar should not be an error page. It is wrong for the artefact that leaves
    // the building: an auditor who asked for `?class=consequential` — the field is `classification`
    // — was handed all 29 records with a header saying 29 and nothing saying the filter had been
    // dropped. A regulator-facing export that silently widens is worse than one that refuses,
    // because the file looks like the answer to the question that was asked.
    let unknown: Vec<&str> = params
        .keys()
        .map(String::as_str)
        .filter(|name| !EXPORT_FILTERS.contains(name) && *name != "format")
        .collect();
    if !unknown.is_empty() {
        let mut names: Vec<&str> = unknown;
        names.sort_unstable();
        return notice(
            StatusCode::BAD_REQUEST,
            "That filter does not exist, so the export was refused",
            &format!(
                "No such filter: {}. Nothing was exported. An unrecognised filter would otherwise \
                 be ignored and you would receive every record — a file that looks like the answer \
                 to the question you asked. The filters this export accepts are: {}.",
                names.join(", "),
                EXPORT_FILTERS.join(", ")
            ),
        );
    }
    let format = params.get("format").map_or("ndjson", String::as_str);
    if !EXPORT_FORMATS.contains(&format) {
        return notice(
            StatusCode::BAD_REQUEST,
            "That export format does not exist, so the export was refused",
            &format!(
                "No such format: {format}. Nothing was exported. The formats this export accepts \
                 are: {}. `ndjson` is the record — canonical envelopes exactly as signed; `html` is \
                 a reading of that record and says so in its own text.",
                EXPORT_FORMATS.join(", ")
            ),
        );
    }
    let filters = Filters::from_params(&params);
    let store = kernel.ingest.store();
    let mut body = String::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut exported: u64 = 0;
    let mut resume: Option<store::OwnedCursor> = None;
    loop {
        let mut page = filters.query_from(resume.as_ref());
        page.limit = EXPORT_PAGE_ROWS;
        let records = match store.query(&page).await {
            Ok(records) => records,
            Err(e) => return unavailable(&e),
        };
        if records.is_empty() {
            break;
        }
        // Keyset, not `OFFSET`. The log has a live writer and `emitted-at` is the emitter's clock,
        // so a record can land ahead of a batch this loop has already walked past; under `OFFSET`
        // every later row shifted down and the next batch began one row early, putting the same
        // signed envelope in the file twice. The store is append-only, so nothing was ever *lost* —
        // but a regulator cannot tell a paging artefact from a genuine repeat without re-deriving
        // `id()` across the whole file, and this export exists so they do not have to.
        resume = store::cursor_after(&records);
        for record in &records {
            match stozher_core::jcs::canonicalize(record) {
                Ok(line) => {
                    body.push_str(&line);
                    body.push('\n');
                }
                Err(e) => return unavailable(&e),
            }
        }
        // Both renderings walk the same paged set once. The canonical body is built either way so
        // that `html` cannot become a second, cheaper query answering a different question than the
        // file it claims to be a reading of.
        if format == "html" {
            rows.extend(records.iter().map(row));
        }
        exported += records.len() as u64;
        if i64::try_from(records.len()).unwrap_or(i64::MAX) < EXPORT_PAGE_ROWS {
            break;
        }
    }
    if format == "html" {
        return render(&ExportDocument {
            title: "Stozher audit export",
            query: filters.to_export_query_string(),
            records: exported.to_string(),
            payload_route: PAYLOAD_ROUTE,
            rows,
        });
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
            // Where the values behind `execution.args-hash` are. They are retained — an effect's
            // payload is `{server, tool, arguments}` — and until this header existed nothing on the
            // path from the export to them said so, so a reader who grepped the file for an amount
            // and found none concluded the arguments had never been recorded. A header and not a
            // body line: every line of the body is an envelope a verifier re-derives `id()` over,
            // and a marker line would break the parser that promise is for.
            (
                axum::http::HeaderName::from_static("x-stozher-payload-route"),
                PAYLOAD_ROUTE.to_owned(),
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
/// The wrapping, the contention retry and the refusal mapping live in
/// [`crate::Ingest::append_as_kernel`], which the revocation route (§03 §7) uses for the same
/// reason: an object a human signed offline cannot carry its own chain position.
async fn submit_decision(
    kernel: &Kernel,
    request_hash: &str,
    decision: &Value,
) -> std::result::Result<String, (String, String)> {
    let mut members = serde_json::Map::new();
    members.insert("decision-of".to_owned(), Value::from(request_hash));
    members.insert("decision".to_owned(), decision.clone());
    kernel
        .ingest
        .append_as_kernel("gate-decision", members, "the decision")
        .await
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
        rooted: false,
        attested: false,
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
            page.rooted = report["anchored"].as_bool().unwrap_or(false);
            let attested = &report["last-checkpoint"];
            page.attested = !attested.is_null();
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
    // The same window and the same cap that bound the record path (§06 §4.4 rule 9), so the finding
    // and the refusal cannot drift apart, and the same half-cap threshold as the gate spike: the
    // point of a finding is to arrive before the thing it warns about, not with it.
    let limit = kernel.config.gate_rate_limit;
    let now = kernel.ingest.clock().now();
    let watch_from = match crate::clock::shift(&now, -limit.window_seconds) {
        Ok(since) => since,
        Err(e) => return unavailable(&e),
    };
    let mismatches = match store
        .argument_mismatch_spikes(&watch_from, (limit.per_subject / 2).max(1))
        .await
    {
        Ok(mismatches) => mismatches,
        Err(e) => return unavailable(&e),
    };
    render(&RejectionsPage {
        title: "Refused submissions",
        chain_valid: verified.is_ok(),
        count: listed.len().to_string(),
        head_hash: verified.ok().flatten().unwrap_or_else(|| "—".to_owned()),
        rows: listed.iter().map(rejection_row).collect(),
        mismatch_window: limit.window_seconds.to_string(),
        mismatch_cap: limit.per_subject.to_string(),
        mismatches: mismatches
            .iter()
            .map(|m| MismatchRow {
                submitted_by: m["submitted-by"].as_str().unwrap_or_default().to_owned(),
                recorded: m["recorded"].to_string(),
                latest: m["latest"].as_str().unwrap_or("-").to_owned(),
                capped: m["recorded"].as_u64().unwrap_or(0) >= u64::from(limit.per_subject),
            })
            .collect(),
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
        payload_hash: evidence["payload-hash"].as_str().unwrap_or("").to_owned(),
        decided_by: short_key(&text(&envelope["authorization"]["decision"]["sig"]["key"])),
        decision: envelope["authorization"]["decision"]["decision"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        decision_reason: envelope["authorization"]["decision"]["reason"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
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
        args_hash: text(&record["args-hash"]),
        // Canonicalized here for the same reason `request_json` is: the approver is being asked to
        // hash exactly these bytes and compare the result with `args_hash`, so what the page renders
        // has to *be* the preimage, not a pretty-printed cousin of it (§06 §4.4 rule 5).
        arguments: stozher_core::jcs::canonicalize(&record["arguments"]).unwrap_or_default(),
        arguments_supplied: record["arguments-supplied"].as_bool().unwrap_or(false),
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
    // The predicate is `stozher_core::sync`'s, not this function's: the same one
    // `spec/vectors/stream-status.json` asks of every implementation. What a console renders is its
    // own business; what counts as refused is not.
    let status = stozher_core::sync::stream_status(
        record["last-appended-at"].as_str(),
        record["last-refused-at"].as_str(),
        silent,
        quiet_after,
    );
    StreamRow {
        stream: text(&record["stream"]),
        stream_kind: text(&record["stream-kind"]),
        head_seq: text(&record["head-seq"]),
        head_short: short(&text(&record["head-hash"])),
        first_seen_at: text(&record["first-seen-at"]),
        last_appended_at: last,
        silent_for: silent.map(humanize).unwrap_or_else(|| "—".to_owned()),
        quiet: status == stozher_core::sync::StreamStatus::Quiet,
        status: status.as_str().to_owned(),
        refused: status == stozher_core::sync::StreamStatus::Refused,
        refusal_reason: text(&record["last-refusal-reason"]),
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
            after: get("after"),
        }
    }

    /// The resume position, or `None` when this is the first page.
    ///
    /// `Err` when the parameter is present and does not parse. That distinction is the point: a
    /// console that fell back to "no cursor" would answer a request for page four with page one and
    /// look like it had succeeded, which for an audit surface is the same class of defect as a
    /// truncated export.
    fn cursor(&self) -> std::result::Result<Option<OwnedCursor>, ()> {
        if self.after.is_empty() {
            return Ok(None);
        }
        OwnedCursor::decode(&self.after).map(Some).ok_or(())
    }

    fn query(&self) -> EnvelopeQuery<'_> {
        self.query_from(None)
    }

    fn query_from<'a>(&'a self, after: Option<&'a OwnedCursor>) -> EnvelopeQuery<'a> {
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
            after: after.map(OwnedCursor::borrowed),
        }
    }

    /// The filter query string for the regulator export.
    ///
    /// `limit` and `after` are deliberately absent. They are the *page's* position and row cap and
    /// have nothing to do with what a regulator asked for; carrying `limit` into the export is what
    /// made the export silently drop evidence while `Content-Disposition` presented the result as a
    /// finished file, and `after` would do the same thing one page further in — an export taken from
    /// page four would begin at page four and still call itself the audit trail.
    fn to_export_query_string(&self) -> String {
        self.to_query_string()
            .split('&')
            .filter(|part| !part.starts_with("limit=") && !part.starts_with("after="))
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

//! The HTTP surface — `spec/05-policy-distribution.md` §2.2, `spec/04-chain-and-checkpoints.md` §6.
//!
//! # The route table is the security surface
//!
//! There is exactly one route that can cause an envelope to be appended: `POST /v1/ingest`. Every
//! other route reads, or performs an operation that touches no chain-bearing row. In particular
//! there is **no** administrative append, no "trusted component" header, no bypass query parameter,
//! and no way for an authenticated caller to choose its own classification or mandate — everything
//! identity-bearing about an envelope is inside the signed object, and everything policy-bearing is
//! computed from the policy document.
//!
//! `POST /v1/checkpoints` and `POST /v1/maintenance/decay` are the two routes that look
//! administrative. The first submits a checkpoint envelope through `POST /v1/ingest`'s own pipeline,
//! where it is refused unless it is signed by the kernel's checkpoint key and reproduces the stream's
//! real head. The second deletes payload rows and nothing else. Neither can append an effect.
//!
//! `POST /v1/gate/requests` (§06 §4.3, ADR-0008 §A) writes a *question* — a parked action request —
//! to a table with no chain-bearing column. It appends nothing, and a row it writes permits nothing:
//! the answer is a human's signature, which enters through `POST /v1/ingest` like everything else.
//!
//! The console ([`crate::console`]) is merged into this table. It registers `get` routes for every
//! page and exactly one `post` — the decision route — which likewise appends only by submitting a
//! signed envelope through `POST /v1/ingest`'s own pipeline.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;

use crate::codes;
use crate::store::EnvelopeQuery;
use crate::{Kernel, checkpoint, ingest};

/// Build the router.
pub fn router(kernel: Arc<Kernel>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/ingest", post(post_ingest))
        .route("/v1/policy/current", get(get_policy_current))
        .route("/v1/policy/{policy_version}", get(get_policy_version))
        .route("/v1/revocations", get(get_revocations))
        .route(
            "/v1/gate/requests",
            post(post_gate_request).get(get_gate_requests),
        )
        .route("/v1/gate/requests/{request_hash}", get(get_gate_request))
        .route("/v1/envelopes", get(get_envelopes))
        .route("/v1/envelopes/{id}", get(get_envelope))
        .route("/v1/envelopes/{id}/mandate", get(get_envelope_mandate))
        .route("/v1/streams", get(get_streams))
        .route("/v1/streams/{stream}/verify", get(get_stream_verify))
        .route("/v1/rejections", get(get_rejections))
        .route("/v1/rejections/verify", get(get_rejections_verify))
        .route("/v1/payloads/{payload_hash}", get(get_payload))
        .route("/v1/checkpoints", post(post_checkpoints))
        .route("/v1/maintenance/decay", post(post_decay))
        .with_state(Arc::clone(&kernel))
        // The console is `get`-only by construction (see [`crate::console`]), so merging it cannot
        // add a write path to this table.
        .merge(crate::console::router(kernel))
}

/// Liveness only. Deliberately unauthenticated and deliberately says nothing about the store.
async fn health() -> Response {
    json(
        StatusCode::OK,
        &serde_json::json!({ "stozher": stozher_core::VERSION, "result": "ok" }),
    )
}

/// The outcome of authenticating a request.
pub(crate) enum Caller {
    /// The credential resolved to this subject.
    Subject(String),
    /// It did not, and this is the response to send.
    Refused(Response),
}

/// Authenticate a request.
///
/// §05 §2.2: both policy endpoints "MUST require caller authentication". So does everything else
/// here — including every console page ([`crate::console`]): an audit trail readable by anyone who
/// can reach the port is a different product, and a console-only login would be a second credential
/// path to keep correct.
pub(crate) fn caller(kernel: &Kernel, headers: &HeaderMap) -> Caller {
    match caller_subject(kernel, headers) {
        Ok(subject) => Caller::Subject(subject),
        Err(detail) => Caller::Refused(refusal(
            StatusCode::UNAUTHORIZED,
            codes::CALLER_UNAUTHENTICATED,
            &detail,
            None,
        )),
    }
}

/// The authentication decision itself, without the response.
///
/// Split out from [`caller`] so the console can answer a browser in its own voice
/// ([`crate::console`]) without holding a second opinion about what counts as authenticated. The
/// rule is here once; only the rendering differs.
pub(crate) fn caller_subject(
    kernel: &Kernel,
    headers: &HeaderMap,
) -> std::result::Result<String, String> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return Err("a Bearer credential is required".to_owned());
    };
    kernel
        .config
        .authenticate(token)
        .map(str::to_owned)
        .map_err(|e| e.detail().to_owned())
}

async fn post_ingest(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let subject = match caller(&kernel, &headers) {
        Caller::Subject(subject) => subject,
        Caller::Refused(response) => return response,
    };
    match kernel.ingest.submit(&body, Some(&subject)).await {
        ingest::Outcome::Accepted(appended) => json(
            if appended.idempotent {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            &serde_json::json!({
                "stozher": stozher_core::VERSION,
                "result": "accepted",
                "envelope-id": appended.id,
                "stream": appended.stream,
                "seq": appended.seq,
                "idempotent": appended.idempotent
            }),
        ),
        // The refusal is machine-readable and terminal, and it does not suggest another way to get
        // the effect applied (§06 §4.1): refusals are facts, not negotiations.
        ingest::Outcome::Rejected {
            reason,
            detail,
            record,
        } => json(
            StatusCode::UNPROCESSABLE_ENTITY,
            &serde_json::json!({
                "stozher": stozher_core::VERSION,
                "result": "rejected",
                "reason-code": reason,
                "reason": detail,
                "rejection-id": record.as_ref().map(|r| r.id.clone()),
                "rejection-seq": record.as_ref().map(|r| r.seq),
                "retryable": false
            }),
        ),
        ingest::Outcome::Unavailable(detail) => {
            tracing::error!(error = %detail, "ingest could not reach the store");
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                codes::STORE_UNAVAILABLE,
                "the kernel could not answer; retry",
                None,
            )
        }
    }
}

async fn get_policy_current(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    match kernel.ingest.store().current_policy().await {
        Ok(Some(document)) => {
            let version = document["policy-version"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let mut response = json(StatusCode::OK, &document);
            // §05 §2.2: the version is the ETag, so a component can ask "has it changed" cheaply.
            if let Ok(value) = axum::http::HeaderValue::from_str(&format!("\"{version}\"")) {
                response
                    .headers_mut()
                    .insert(axum::http::header::ETAG, value);
            }
            response
        }
        Ok(None) => refusal(
            StatusCode::NOT_FOUND,
            "policy-not-published",
            "no policy version is in force",
            None,
        ),
        Err(e) => unavailable(&e),
    }
}

async fn get_policy_version(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(policy_version): Path<String>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    match kernel.ingest.store().policy_version(&policy_version).await {
        // Every version the kernel has ever published resolves forever, so an envelope's
        // `policy-version` is never a dangling reference (§05 §2.2).
        Ok(Some(document)) => json(StatusCode::OK, &document),
        Ok(None) => refusal(
            StatusCode::NOT_FOUND,
            "policy-not-published",
            "that policy version has never been published here",
            None,
        ),
        Err(e) => unavailable(&e),
    }
}

/// The revocation feed (§03 §7) — the preventive half of revocation.
///
/// Until this endpoint existed a component could only learn that a mandate had been revoked by
/// having an envelope refused at ingest, which is *after* the effect reached the world (ADR-0007
/// §1). It is deliberately shaped like policy pull (§05 §2.2): a component polls it, caches it, and
/// evaluates the cached set locally on its hot path.
///
/// The epoch is the ETag, so a poll that changes nothing costs a conditional request and no rows.
async fn get_revocations(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let (epoch, revocations) = match kernel.ingest.store().revocation_feed().await {
        Ok(feed) => feed,
        Err(e) => return unavailable(&e),
    };
    let etag = format!("\"{epoch}\"");
    if headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|candidate| candidate.trim() == etag))
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        if let Ok(value) = axum::http::HeaderValue::from_str(&etag) {
            response
                .headers_mut()
                .insert(axum::http::header::ETAG, value);
        }
        return response;
    }
    let mut response = json(
        StatusCode::OK,
        &serde_json::json!({
            "stozher": stozher_core::VERSION,
            "revocation-epoch": epoch,
            "count": revocations.len(),
            "revocations": revocations
        }),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&etag) {
        response
            .headers_mut()
            .insert(axum::http::header::ETAG, value);
    }
    response
}

/// Submit a parked request to the kernel-native pending queue — `spec/06 §4.3`, ADR-0008 §A.
///
/// # This is a write route that cannot append an effect
///
/// `spec/06 §1.1` already said the action request "is submitted over an authenticated channel
/// (§10 §1)"; it never named the channel, which is the whole of ADR-0008 §A. This is that channel.
/// It writes one row to `gate_requests`, a table with no chain-bearing column that
/// [`crate::store::Store::append`] never touches, and it appends nothing: the route table's
/// invariant — exactly one route can cause an envelope to be appended — is unchanged.
///
/// A row here **grants nothing**. It is a question. The answer is a human's signature, which enters
/// through `POST /v1/ingest` like everything else, and the effect that eventually consumes it is
/// still checked by all eleven steps of §06 §2.
async fn post_gate_request(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let submitted_by = match caller(&kernel, &headers) {
        Caller::Subject(subject) => subject,
        Caller::Refused(response) => return response,
    };
    let now = kernel.ingest.clock().now();
    let request = match std::str::from_utf8(&body)
        .map_err(|e| {
            stozher_core::error::Error::new("jcs-malformed-json", format!("body is not UTF-8: {e}"))
        })
        .and_then(stozher_core::jcs::parse)
    {
        Ok(request) => request,
        Err(e) => {
            return refusal(StatusCode::UNPROCESSABLE_ENTITY, e.code(), e.detail(), None);
        }
    };
    let queued = match crate::gatequeue::validate(&request, &now) {
        Ok(queued) => queued,
        Err(e) => {
            return refusal(StatusCode::UNPROCESSABLE_ENTITY, e.code(), e.detail(), None);
        }
    };
    // §09 §7: the approver-flood bound. Checked before the insert, and skipped for a request that
    // is already queued — a component retrying after a lost response is behaving correctly and must
    // not be counted twice for it. Refusing the *request* refuses nobody's action: the call it was
    // for is still gated and still blocked. What a flooding subject loses is the ability to keep
    // growing the queue a human has to read, which is the attack the section describes.
    let store = kernel.ingest.store();
    let already_queued = match store.gate_request(&queued.request_hash).await {
        Ok(existing) => existing.is_some(),
        Err(e) => return unavailable(&e),
    };
    if !already_queued {
        let limit = kernel.config.gate_rate_limit;
        let since = match crate::clock::shift(&now, -limit.window_seconds) {
            Ok(since) => since,
            Err(e) => return unavailable(&e),
        };
        let parked = match store.gate_requests_since(&queued.subject, &since).await {
            Ok(parked) => parked,
            Err(e) => return unavailable(&e),
        };
        if parked >= limit.per_subject {
            tracing::warn!(
                subject = %queued.subject,
                parked,
                window_seconds = limit.window_seconds,
                "gate requests refused: the per-subject rate limit was reached"
            );
            return refusal(
                StatusCode::TOO_MANY_REQUESTS,
                crate::codes::GATE_RATE_LIMITED,
                &format!(
                    "{} has parked {parked} requests in the last {} seconds, at or above the \
                     configured cap of {}. The console shows this as a spike.",
                    queued.subject, limit.window_seconds, limit.per_subject
                ),
                None,
            );
        }
    }

    let fresh = match store.queue_gate_request(&queued, &submitted_by, &now).await {
        Ok(fresh) => fresh,
        Err(e) => return unavailable(&e),
    };

    // The park is durable before any channel is touched, so a notification adapter that is down
    // costs an approver a ping and never costs the queue a request (§06 §4.3). Delivery runs off
    // the response path because a slow webhook must not hold the component that parked — which for
    // the gateway is a sync MCP handler (`docs/gateway-integration-constraints.md` §2).
    if fresh {
        let ping = crate::notify::Ping {
            request_hash: queued.request_hash.clone(),
            subject: queued.subject.clone(),
            component: queued.component.clone(),
            action: queued.action.clone(),
            target: queued.target.clone(),
            classification: queued.classification.clone(),
            not_after: queued.not_after.clone(),
            console_url: kernel.config.console_base_url.clone(),
        };
        let kernel = Arc::clone(&kernel);
        let notifying = Arc::clone(&kernel);
        let request_hash = queued.request_hash.clone();
        tokio::spawn(async move {
            let attempts =
                match tokio::task::spawn_blocking(move || notifying.notifier.notify(&ping)).await {
                    Ok(attempts) => attempts,
                    Err(e) => {
                        tracing::error!(error = %e, "the notification worker panicked");
                        return;
                    }
                };
            let at = kernel.ingest.clock().now();
            if let Err(e) = kernel
                .ingest
                .store()
                .record_notifications(&request_hash, &attempts, &at)
                .await
            {
                tracing::error!(error = %e, "a notification outcome could not be recorded");
            }
        });
    }

    json(
        if fresh {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        &serde_json::json!({
            "stozher": stozher_core::VERSION,
            "result": "queued",
            "request-hash": queued.request_hash,
            "not-after": queued.not_after,
            "idempotent": !fresh,
            "channels": kernel.notifier.channel_count()
        }),
    )
}

/// The queue, for the console and for an operator's own tooling.
async fn get_gate_requests(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let answered = params.get("answered").map(String::as_str) == Some("true");
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(200);
    let now = kernel.ingest.clock().now();
    match kernel
        .ingest
        .store()
        .gate_queue(answered, &now, limit)
        .await
    {
        Ok(rows) => json(
            StatusCode::OK,
            &serde_json::json!({ "count": rows.len(), "requests": rows }),
        ),
        Err(e) => unavailable(&e),
    }
}

/// One request and, when a human has answered it, the signed decision.
///
/// The decision is returned **verbatim**. A component polling this must run §06 §2 over it itself
/// before acting: a kernel that handed back a verdict a component trusted on sight would be the
/// ambient approval §06 §2 exists to make unrepresentable, moved one process to the left.
async fn get_gate_request(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(request_hash): Path<String>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let (request, submitted_by) = match store.gate_request(&request_hash).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            return refusal(
                StatusCode::NOT_FOUND,
                "not-found",
                "no such parked request",
                None,
            );
        }
        Err(e) => return unavailable(&e),
    };
    let decision = match store.gate_decision(&request_hash).await {
        Ok(decision) => decision,
        Err(e) => return unavailable(&e),
    };
    json(
        StatusCode::OK,
        &serde_json::json!({
            "stozher": stozher_core::VERSION,
            "request-hash": request_hash,
            "request": request,
            "submitted-by": submitted_by,
            "decision": decision
        }),
    )
}

async fn get_envelopes(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let get = |name: &str| params.get(name).map(String::as_str);
    let filter = EnvelopeQuery {
        subject: get("subject"),
        mandate_ref: get("mandate-ref"),
        mandate_subtree_of: get("mandate-subtree-of"),
        classification: get("classification"),
        kind: get("kind"),
        action: get("action"),
        component: get("component"),
        stream: get("stream"),
        emitted_from: get("emitted-from"),
        emitted_to: get("emitted-to"),
        correlation_ref: get("correlation-ref"),
        correlation_prefix: get("correlation-prefix"),
        commitment_id: get("commitment-id"),
        outcome: get("outcome"),
        human_root: get("human-root"),
        violations_only: get("violations-only") == Some("true"),
        limit: get("limit").and_then(|l| l.parse().ok()).unwrap_or(100),
        offset: get("offset").and_then(|o| o.parse().ok()).unwrap_or(0),
    };
    match kernel.ingest.store().query(&filter).await {
        Ok(records) => json(
            StatusCode::OK,
            &serde_json::json!({ "count": records.len(), "records": records }),
        ),
        Err(e) => unavailable(&e),
    }
}

async fn get_envelope(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    match kernel.ingest.store().envelope_by_id(&id).await {
        Ok(Some(stored)) => match stored.envelope() {
            Ok(envelope) => json(
                StatusCode::OK,
                &serde_json::json!({
                    "id": stored.id,
                    "received-at": stored.received_at,
                    "human-root": stored.human_root,
                    "effective-class": stored.effective_class,
                    "policy-violation": stored.policy_violation,
                    "envelope": envelope
                }),
            ),
            Err(e) => unavailable(&e),
        },
        Ok(None) => refusal(StatusCode::NOT_FOUND, "not-found", "no such envelope", None),
        Err(e) => unavailable(&e),
    }
}

/// The mandate walk for one envelope, returning the human root (§04 §6).
async fn get_envelope_mandate(
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
        Ok(None) => return refusal(StatusCode::NOT_FOUND, "not-found", "no such envelope", None),
        Err(e) => return unavailable(&e),
    };
    let envelope = match stored.envelope() {
        Ok(envelope) => envelope,
        Err(e) => return unavailable(&e),
    };
    let Some(mandate_ref) = envelope["mandate-ref"].as_str() else {
        return json(
            StatusCode::OK,
            &serde_json::json!({ "id": id, "mandate-ref": Value::Null, "chain": [] }),
        );
    };
    match store.mandate_ancestry(mandate_ref, 16).await {
        Ok(ancestry) => {
            let mut chain = Vec::new();
            let mut cursor = Some(mandate_ref.to_owned());
            while let Some(current) = cursor.take() {
                let Some(mandate) = ancestry.get(&current) else {
                    break;
                };
                chain.push(serde_json::json!({
                    "mandate-id": current,
                    "mandate-kind": mandate["mandate-kind"],
                    "grantor": mandate["grantor"],
                    "grantee": mandate["grantee"],
                    "not-before": mandate["not-before"],
                    "not-after": mandate["not-after"],
                    "scope": mandate["scope"]
                }));
                cursor = mandate["parent"].as_str().map(str::to_owned);
            }
            json(
                StatusCode::OK,
                &serde_json::json!({
                    "id": id,
                    "mandate-ref": mandate_ref,
                    "human-root": stored.human_root,
                    "chain": chain
                }),
            )
        }
        Err(e) => unavailable(&e),
    }
}

async fn get_streams(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    match kernel.ingest.store().streams().await {
        // A stream that has gone quiet is a finding, not a null result (§09 §4.2), so the last
        // append time is part of the answer rather than something a caller has to derive.
        Ok(streams) => json(
            StatusCode::OK,
            &serde_json::json!({ "count": streams.len(), "streams": streams }),
        ),
        Err(e) => unavailable(&e),
    }
}

async fn get_stream_verify(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(stream): Path<String>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    match checkpoint::verify_stream(&kernel.ingest, &stream).await {
        Ok(report) => json(StatusCode::OK, &report),
        Err(e) if e.code() == codes::STORE_UNAVAILABLE => unavailable(&e),
        Err(e) => json(
            StatusCode::OK,
            &serde_json::json!({
                "stream": stream,
                "valid": false,
                "reason-code": e.code(),
                "reason": e.detail(),
                "failed-at-seq": e.seq()
            }),
        ),
    }
}

async fn get_rejections(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let reason = params.get("reason").map(String::as_str);
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    match kernel.ingest.store().rejections(reason, limit).await {
        Ok(records) => json(
            StatusCode::OK,
            &serde_json::json!({ "count": records.len(), "rejections": records }),
        ),
        Err(e) => unavailable(&e),
    }
}

async fn get_rejections_verify(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let store = kernel.ingest.store();
    let records = match store.rejection_chain().await {
        Ok(records) => records,
        Err(e) => return unavailable(&e),
    };
    match crate::store::verify_rejection_chain(&records, store.rejection_stream()) {
        Ok(head) => json(
            StatusCode::OK,
            &serde_json::json!({
                "stream": store.rejection_stream(),
                "count": records.len(),
                "head-hash": head,
                "valid": true,
                "reasons": crate::store::reason_histogram(&records)
            }),
        ),
        Err(e) => json(
            StatusCode::OK,
            &serde_json::json!({
                "stream": store.rejection_stream(),
                "count": records.len(),
                "valid": false,
                "reason-code": e.code(),
                "reason": e.detail()
            }),
        ),
    }
}

async fn get_payload(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Path(payload_hash): Path<String>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    match kernel.ingest.store().payload(&payload_hash).await {
        Ok(Some((_media_type, bytes))) => {
            // The declared `media-type` is emitter-controlled and is deliberately *not* reflected
            // here. Ingest allowlists it (`payload::ALLOWED_MEDIA_TYPES`), but this origin also
            // serves the console, and `deploy/bin/stozher-console` proxies browser GETs to it with
            // the kernel credential attached — so a payload the browser renders is script running
            // as the console. A payload is bytes an auditor downloads; served as an opaque
            // attachment it cannot become a document, including the payloads written before the
            // allowlist existed. The declared type stays queryable on the envelope's `evidence`,
            // where it describes the bytes without instructing a browser about them.
            let mut response = (StatusCode::OK, bytes).into_response();
            let headers = response.headers_mut();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(
                "x-content-type-options",
                axum::http::HeaderValue::from_static("nosniff"),
            );
            // The filename is checked to be 64 lowercase hex rather than assumed to be: it comes
            // from the request path, and a quote in it would end the quoted-string early. A hash
            // that reached a stored row is hex in practice, but "in practice" is not a check.
            let disposition = if stozher_core::crypto::is_digest_hex(&payload_hash) {
                format!("attachment; filename=\"{payload_hash}.bin\"")
            } else {
                "attachment".to_owned()
            };
            if let Ok(value) = axum::http::HeaderValue::from_str(&disposition) {
                headers.insert(axum::http::header::CONTENT_DISPOSITION, value);
            }
            response
        }
        // §04 §5.4: after deletion the evidence is reported as `decayed`, with the hash still
        // present and resolvable as a commitment. An auditor who independently holds the content can
        // still prove it is the content that was recorded.
        Ok(None) => json(
            StatusCode::GONE,
            &serde_json::json!({
                "stozher": stozher_core::VERSION,
                "result": "decayed",
                "payload-hash": payload_hash,
                "reason": "the payload has decayed; the hash remains the commitment"
            }),
        ),
        Err(e) => unavailable(&e),
    }
}

/// Emit checkpoints. Submits envelopes through the ingest pipeline; appends nothing directly.
async fn post_checkpoints(
    State(kernel): State<Arc<Kernel>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let checkpoint_stream = kernel.config.checkpoint_stream.clone();
    let result = match params.get("stream") {
        Some(stream) => checkpoint::emit(&kernel.ingest, stream, &checkpoint_stream)
            .await
            .map(|appended| {
                serde_json::json!({ "checkpointed": [ { "stream": stream, "seq": appended.map(|a| a.seq) } ] })
            }),
        None => checkpoint::emit_all(&kernel.ingest, &checkpoint_stream)
            .await
            .map(|results| {
                let rendered: Vec<Value> = results
                    .into_iter()
                    .map(|(stream, outcome)| match outcome {
                        Ok(seq) => serde_json::json!({ "stream": stream, "seq": seq }),
                        Err(reason) => serde_json::json!({ "stream": stream, "error": reason }),
                    })
                    .collect();
                serde_json::json!({ "checkpointed": rendered })
            }),
    };
    match result {
        Ok(report) => json(StatusCode::OK, &report),
        Err(e) if e.code() == codes::STORE_UNAVAILABLE => unavailable(&e),
        Err(e) => refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            e.code(),
            e.detail(),
            e.seq(),
        ),
    }
}

/// Payload decay. Deletes from `payloads` and nothing else, after checkpointing every stream a
/// deletion would touch (§04 §4.6). No envelope row is written, read or altered.
async fn post_decay(State(kernel): State<Arc<Kernel>>, headers: HeaderMap) -> Response {
    if let Caller::Refused(response) = caller(&kernel, &headers) {
        return response;
    }
    let checkpoint_stream = kernel.config.checkpoint_stream.clone();
    match checkpoint::decay_with_checkpoints(&kernel.ingest, &checkpoint_stream).await {
        Ok(report) => json(
            StatusCode::OK,
            &serde_json::json!({
                "at": report.at,
                "streams-checkpointed": report.streams_checkpointed,
                "payloads-deleted": report.payloads_deleted,
                "decayed-hashes": report.deleted_hashes
            }),
        ),
        Err(e) if e.code() == codes::STORE_UNAVAILABLE => unavailable(&e),
        Err(e) => refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            e.code(),
            e.detail(),
            e.seq(),
        ),
    }
}

fn json(status: StatusCode, value: &Value) -> Response {
    (status, axum::Json(value.clone())).into_response()
}

fn refusal(status: StatusCode, code: &str, reason: &str, seq: Option<u64>) -> Response {
    json(
        status,
        &serde_json::json!({
            "stozher": stozher_core::VERSION,
            "result": "rejected",
            "reason-code": code,
            "reason": reason,
            "failed-at-seq": seq,
            "retryable": status == StatusCode::SERVICE_UNAVAILABLE
        }),
    )
}

fn unavailable(error: &stozher_core::error::Error) -> Response {
    tracing::error!(error = %error, "the store could not answer");
    refusal(
        StatusCode::SERVICE_UNAVAILABLE,
        codes::STORE_UNAVAILABLE,
        "the kernel could not answer; retry",
        None,
    )
}

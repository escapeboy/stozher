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
        .with_state(kernel)
}

/// Liveness only. Deliberately unauthenticated and deliberately says nothing about the store.
async fn health() -> Response {
    json(
        StatusCode::OK,
        &serde_json::json!({ "stozher": stozher_core::VERSION, "result": "ok" }),
    )
}

/// The outcome of authenticating a request.
enum Caller {
    /// The credential resolved to this subject.
    Subject(String),
    /// It did not, and this is the response to send.
    Refused(Response),
}

/// Authenticate a request.
///
/// §05 §2.2: both policy endpoints "MUST require caller authentication". So does everything else
/// here: an audit trail readable by anyone who can reach the port is a different product.
fn caller(kernel: &Kernel, headers: &HeaderMap) -> Caller {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        return Caller::Refused(refusal(
            StatusCode::UNAUTHORIZED,
            codes::CALLER_UNAUTHENTICATED,
            "a Bearer credential is required",
            None,
        ));
    };
    match kernel.config.authenticate(token) {
        Ok(subject) => Caller::Subject(subject.to_owned()),
        Err(e) => Caller::Refused(refusal(
            StatusCode::UNAUTHORIZED,
            codes::CALLER_UNAUTHENTICATED,
            e.detail(),
            None,
        )),
    }
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
        Ok(Some((media_type, bytes))) => {
            let mut response = (StatusCode::OK, bytes).into_response();
            if let Ok(value) = axum::http::HeaderValue::from_str(&media_type) {
                response
                    .headers_mut()
                    .insert(axum::http::header::CONTENT_TYPE, value);
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

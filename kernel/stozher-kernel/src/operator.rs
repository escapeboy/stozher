//! The operator's HTTP side: submitting documents that are already signed.
//!
//! Everything here carries objects **someone else already signed** over an authenticated channel.
//! No function in this module reads key material, derives a key or produces a signature, and that
//! separation is deliberate rather than incidental: ADR-0009 records that `decide` does no network
//! I/O so that "the kernel cannot manufacture an approval" is a structural fact. Keeping the
//! network in a module with no access to a seed is the other half of the same property — signing has
//! no socket, and the socket has no key.
//!
//! It exists so that a clean install needs the one binary and nothing else. An install path that
//! required `curl` and a JSON processor would be three tools to have present, three to keep in the
//! container image, and three answers on a security questionnaire (ADR-0003).

use std::time::Duration;

use stozher_core::error::{Error, Result};

/// A short bound. Every call here is to the operator's own kernel, on a LAN or on localhost; a
/// minute of waiting is a hung install, not a slow one.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A response, reduced to what an operator needs to see.
#[derive(Debug)]
pub struct Answer {
    /// HTTP status.
    pub status: u16,
    /// Body, as received.
    pub body: String,
}

impl Answer {
    /// Whether the kernel accepted what was sent.
    #[must_use]
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into()
}

/// `POST /v1/ingest` with an already-signed ingest request body.
///
/// The body is passed through verbatim. It was canonicalized when it was signed, and re-encoding it
/// here would risk changing the bytes the signature covers.
///
/// # Errors
///
/// `kernel-unreachable` when the request cannot be completed.
pub fn ingest(base_url: &str, token: &str, body: &[u8]) -> Result<Answer> {
    send(
        agent()
            .post(format!("{}/v1/ingest", base_url.trim_end_matches('/')))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}")),
        body.to_vec(),
    )
}

/// Hand a signed gate decision to the console, the way a browser does.
///
/// The console's decision route is CSRF-protected with a token bound to (process, caller, request),
/// rendered into the form on the pending page. This fetches that page, takes the token for exactly
/// this request, and posts the decision with it — the same two steps a human with a browser
/// performs, and the reason the protection cannot be satisfied by a page the caller never fetched.
///
/// # Errors
///
/// `kernel-unreachable`, or `console-csrf-invalid` when the pending page carries no form for this
/// request — which is what an already-answered or expired request looks like.
pub fn decide(base_url: &str, token: &str, request_hash: &str, decision: &str) -> Result<Answer> {
    let base = base_url.trim_end_matches('/');
    let page = send_get(
        agent()
            .get(format!("{base}/console/pending"))
            .header("authorization", format!("Bearer {token}")),
    )?;
    if !page.ok() {
        return Ok(page);
    }
    let Some(csrf) = csrf_for(&page.body, request_hash) else {
        return Err(Error::new(
            "console-csrf-invalid",
            format!(
                "the pending page shows no decision form for {request_hash}: it is already \
                 answered, expired, or was never queued"
            ),
        ));
    };
    let decision = stozher_core::jcs::parse(decision)?;
    let body = serde_json::to_vec(&serde_json::json!({ "csrf": csrf, "decision": decision }))
        .map_err(|e| Error::new("jcs-malformed-json", e.to_string()))?;
    send(
        agent()
            .post(format!("{base}/console/pending/{request_hash}/decide"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}")),
        body,
    )
}

/// `GET /health`, for waiting on a kernel that is still starting.
///
/// # Errors
///
/// `kernel-unreachable`.
pub fn health(base_url: &str) -> Result<Answer> {
    send_get(agent().get(format!("{}/health", base_url.trim_end_matches('/'))))
}

/// Take the CSRF token out of the decision form for one request.
///
/// Deliberately narrow: it finds the form whose `action` names *this* request hash and reads the
/// token inside that form. A looser search would happily pick up the token belonging to a different
/// pending request, which the kernel would then refuse — with a message about CSRF rather than
/// about the mix-up that caused it.
#[must_use]
pub fn csrf_for(page: &str, request_hash: &str) -> Option<String> {
    let marker = format!("action=\"/console/pending/{request_hash}/decide\"");
    let start = page.find(&marker)? + marker.len();
    let end = page[start..]
        .find("</form>")
        .map_or(page.len(), |o| start + o);
    let form = &page[start..end];
    let field = form.find("name=\"csrf\" value=\"")? + "name=\"csrf\" value=\"".len();
    let token = &form[field..];
    let close = token.find('"')?;
    let token = &token[..close];
    (token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())).then(|| token.to_owned())
}

fn send(request: ureq::RequestBuilder<ureq::typestate::WithBody>, body: Vec<u8>) -> Result<Answer> {
    let mut response = request
        .send(&body[..])
        .map_err(|e| Error::new("kernel-unreachable", e.to_string()))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::new("kernel-unreachable", e.to_string()))?;
    Ok(Answer { status, body })
}

/// `GET` carries no body, and ureq types that difference, so the two shapes need two calls.
fn send_get(request: ureq::RequestBuilder<ureq::typestate::WithoutBody>) -> Result<Answer> {
    let mut response = request
        .call()
        .map_err(|e| Error::new("kernel-unreachable", e.to_string()))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::new("kernel-unreachable", e.to_string()))?;
    Ok(Answer { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "ab12";

    fn page(hash: &str, token: &str) -> String {
        format!(
            "<h2>Parked</h2>\
             <form method=\"post\" action=\"/console/pending/{hash}/decide\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{token}\">\
             </form>"
        )
    }

    #[test]
    fn the_token_is_read_out_of_the_form_for_that_request() {
        let token = "9".repeat(64);
        assert_eq!(csrf_for(&page(HASH, &token), HASH), Some(token));
    }

    #[test]
    fn a_request_with_no_form_yields_no_token() {
        let token = "9".repeat(64);
        assert_eq!(csrf_for(&page(HASH, &token), "cd34"), None);
    }

    #[test]
    fn a_token_belonging_to_another_request_is_never_returned() {
        // Two parked requests on one page. Reading the wrong form's token would produce a refusal
        // that blames CSRF for what is really a mix-up, so the search is anchored on the action.
        let mine = "a".repeat(64);
        let theirs = "b".repeat(64);
        let both = format!("{}{}", page("cd34", &theirs), page(HASH, &mine));
        assert_eq!(csrf_for(&both, HASH), Some(mine));
        assert_eq!(csrf_for(&both, "cd34"), Some(theirs));
    }

    #[test]
    fn a_malformed_token_is_not_returned() {
        assert_eq!(csrf_for(&page(HASH, "not-hex"), HASH), None);
        assert_eq!(csrf_for(&page(HASH, &"a".repeat(63)), HASH), None);
    }
}

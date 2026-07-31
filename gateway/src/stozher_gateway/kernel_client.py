"""The kernel HTTP client.

`urllib.request`, not `httpx`: Harbormaster's base dependencies are deliberately two, and the
in-tree precedent for a small HTTP call is `dispatcher_cli.py:154-167`. Adding a client library to
the base install would be a dependency taken for the gateway's convenience and paid by every
Harbormaster user.

Every call carries a hard, short timeout. The hot path must be O(ms) and must not block on the
kernel (§10 §2); a request that hangs here stalls the MCP server's loop, because sync tool handlers
run on it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, NamedTuple

from .canonical import canonicalize_bytes

__all__ = ["KernelClient", "KernelResponse", "KernelUnreachableError"]


class KernelUnreachableError(RuntimeError):
    """The kernel could not be reached or did not answer in time."""


class KernelResponse(NamedTuple):
    """One kernel answer: HTTP status, the decoded body, and the `ETag` when one was sent."""

    status: int
    body: dict[str, Any]
    etag: str | None = None

    @property
    def accepted(self) -> bool:
        return self.status in (200, 201) and self.body.get("result") in (None, "ok", "accepted")

    @property
    def reason_code(self) -> str | None:
        code = self.body.get("reason-code")
        return str(code) if code is not None else None


class KernelClient:
    """A thin, timeout-bounded client for the kernel's route table."""

    def __init__(self, url: str, token: str | None, timeout: float) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def _request(
        self, method: str, path: str, body: Any = None, if_none_match: str | None = None
    ) -> KernelResponse:
        data = canonicalize_bytes(body) if body is not None else None
        request = urllib.request.Request(f"{self.url}{path}", data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if if_none_match is not None:
            request.add_header("If-None-Match", if_none_match)
        if self._token:
            request.add_header("Authorization", f"Bearer {self._token}")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                payload = response.read()
                return KernelResponse(
                    response.status, _decode(payload), response.headers.get("ETag")
                )
        except urllib.error.HTTPError as e:
            # A refusal is an answer, not a transport failure: the kernel's reason code is the most
            # useful thing the gateway can log or surface, so it is never flattened into "error".
            # 304 arrives here too, and it is the *cheap* answer, not a problem.
            return KernelResponse(e.code, _decode(e.read()), e.headers.get("ETag"))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise KernelUnreachableError(f"{method} {path}: {e}") from e

    def health(self) -> KernelResponse:
        return self._request("GET", "/health")

    def current_policy(self) -> KernelResponse:
        return self._request("GET", "/v1/policy/current")

    def policy_version(self, version: str) -> KernelResponse:
        return self._request("GET", f"/v1/policy/{version}")

    def mandate_budget(self, mandate_ref: str) -> KernelResponse:
        """A mandate chain's caps and accrued spend (§03 §4.3), for the pre-spend check."""
        return self._request("GET", f"/v1/mandates/{mandate_ref}/budget")

    def manifests(self) -> KernelResponse:
        """Every registered component's current manifest — tier-A classification (§08, §10 §3)."""
        return self._request("GET", "/v1/manifests")

    def revocations(self, if_none_match: str | None = None) -> KernelResponse:
        """The revocation feed (§03 §7). `304` means the epoch has not moved and nothing was read."""
        return self._request("GET", "/v1/revocations", if_none_match=if_none_match)

    def ingest(self, envelope: dict[str, Any], payloads: list[dict[str, Any]]) -> KernelResponse:
        return self._request("POST", "/v1/ingest", {"envelope": envelope, "payloads": payloads})

    def park_gate_request(self, request: dict[str, Any]) -> KernelResponse:
        """Put a parked request into the kernel's pending queue (§06 §4.3).

        This is the route ADR-0008 §A asked for and `spec/06 §1.1` already implied: the action
        request is submitted over the authenticated channel, not signed and not an envelope. It
        appends nothing and it authorizes nothing — it is how a human comes to *see* the park.
        """
        return self._request("POST", "/v1/gate/requests", request)

    def gate_request(self, request_hash: str) -> KernelResponse:
        """The parked request and, once a human has answered, the signed decision.

        The decision comes back verbatim and is trusted by nothing here: it goes through all of
        §06 §2 in :mod:`stozher_gateway.gate` before any call is forwarded. Fetching an approval and
        believing it would be the ambient approval this whole design exists to make impossible.
        """
        return self._request("GET", f"/v1/gate/requests/{request_hash}")

    def envelopes(self, **filters: str) -> KernelResponse:
        query = "&".join(f"{name}={value}" for name, value in filters.items())
        return self._request("GET", f"/v1/envelopes{'?' + query if query else ''}")

    def verify_stream(self, stream: str) -> KernelResponse:
        return self._request("GET", f"/v1/streams/{stream}/verify")


def _decode(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {}
    try:
        decoded = json.loads(payload)
    except ValueError:
        return {"result": "unparseable", "reason": payload[:200].decode("utf-8", "replace")}
    return decoded if isinstance(decoded, dict) else {"result": decoded}

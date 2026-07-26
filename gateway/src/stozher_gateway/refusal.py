"""The structured refusal returned to the calling agent (§06 §4.1, §10 §6).

Being refused legibly is a feature. An agent that receives a clear terminal refusal reports it to its
human and stops; an agent that receives a vague error retries, and a retry loop against a human's
decision is a load-generating attack on the approver (§09 §7).

So a refusal never suggests a workaround, an alternative tool, or a way to proceed without approval,
never carries the approver's key material or other pending requests, and is never dressed up as a
success — the gateway raises it, which is what marks the MCP result as an error.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["RESULTS", "RefusalError", "refusal"]

RESULTS = ("denied", "blocked", "parked", "prohibited")


class RefusalError(Exception):
    """A terminal refusal. `str()` is the §06 §4.1 object, so it survives any transport."""

    def __init__(self, document: dict[str, Any]) -> None:
        super().__init__(json.dumps(document, sort_keys=True))
        self.document = document

    @property
    def result(self) -> str:
        return str(self.document["result"])

    @property
    def reason_code(self) -> str:
        return str(self.document["reason-code"])


def refusal(
    result: str,
    reason_code: str,
    reason: str,
    *,
    action: str,
    classification: str | None = None,
    classification_tier: str | None = None,
    request_hash: str | None = None,
    envelope_id: str | None = None,
    decided_by: str | None = None,
    decided_at: str | None = None,
    hint: str | None = None,
) -> RefusalError:
    """Build a refusal. `retryable` is false for everything terminal, which is everything here."""
    if result not in RESULTS:
        raise ValueError(f"{result!r} is not one of {RESULTS}")
    document: dict[str, Any] = {
        "stozher": "stozher/0.1",
        "result": result,
        "reason-code": reason_code,
        "reason": reason,
        "action": action,
        "classification": classification,
        "classification-tier": classification_tier,
        "request-hash": request_hash,
        "envelope-id": envelope_id,
        # A refusal that invites an immediate retry teaches agents to loop against a human's
        # decision. `blocked` is the only state a later call could legitimately resolve, and even
        # there the answer is "the operator fixes something", not "call again now".
        "retryable": False,
    }
    if decided_by is not None:
        document["decided-by"] = decided_by
    if decided_at is not None:
        document["decided-at"] = decided_at
    if hint is not None:
        document["hint"] = hint
    return RefusalError(document)

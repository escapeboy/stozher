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
    retry_after_seconds: int | None = None,
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
        # False for every result, including `parked`, and that is not the over-strictness it looks
        # like. §06 §4.1 mandates it only for `denied` and `prohibited` — but the same section ends
        # "Being refused legibly is a feature: the agent can report accurately to its user instead
        # of retrying blind", and §4.2 makes parking a *terminal answer*. The flag is addressed to
        # the agent, and what the agent should do with a park is stop and tell its user. The human
        # is the one who makes the call again, after approving it.
        #
        # This was briefly changed to `result == "parked"` on the reasoning that an approval binds a
        # later identical request, so a retry is the protocol rather than a loop. The tests here
        # refused it, and they were right: a caller that retried on the flag would hammer the gate,
        # which is precisely how a user's ordinary loop filled the per-subject cap and dead-ended.
        # DEF-18 qualifies this, and does not overturn it. `gate-rate-limited` is the one condition
        # here that is *transient by definition* — the cap is a window — and a design partner
        # measured what calling it permanent costs: 66 of 93 gated calls in one simulated morning
        # refused as unretryable, which is work dropped and not deferred. The refund never happens.
        #
        # The paragraph above is still right about the hazard, so the flag is only ever raised
        # together with `retry-after-seconds`. A caller told "yes, in 300 seconds" schedules; a
        # caller told only "yes" hammers, which is exactly how the cap filled in the first place.
        # No `retry-after`, no `retryable` — the two travel together or neither does.
        "retryable": retry_after_seconds is not None,
    }
    if retry_after_seconds is not None:
        document["retry-after-seconds"] = retry_after_seconds
    if decided_by is not None:
        document["decided-by"] = decided_by
    if decided_at is not None:
        document["decided-at"] = decided_at
    if hint is not None:
        document["hint"] = hint
    return RefusalError(document)

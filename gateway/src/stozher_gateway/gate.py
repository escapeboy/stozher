"""Gate authorization, per `spec/06-gates.md` §1 and §2.

*"Approved" is not a boolean anywhere in this system.* There is no argument to any function here
that means "allowed"; the only thing that can permit a gated action is an Ed25519 signature by a
named human over the hash of that specific action, and every one of the eleven steps below closes a
bypass someone has actually shipped (ADR-0002).

§06 §2 makes steps (2)-(10) mandatory for a component that enforces locally, which the gateway does:
it must not forward a call on the strength of an approval it has not itself checked. Step (11),
replay, is authoritative at the kernel; the gateway additionally tracks it locally.
"""

from __future__ import annotations

import secrets
from typing import Any, NamedTuple

from .canonical import object_hash
from .signing import verify_signed_object

__all__ = ["ActionRequest", "AuthorizationOk", "GateRefusedError", "action_request", "verify_authorization"]


class GateRefusedError(ValueError):
    """A gate refusal carrying its normative reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class AuthorizationOk(NamedTuple):
    """A verified approval."""

    request_hash: str
    decided_by: str
    single_use: bool


class ActionRequest(NamedTuple):
    """The inputs an action request commits to (§06 §1.1)."""

    subject: str
    key: str
    component: str
    mandate_ref: str
    policy_version: str
    classification: str
    action: str
    target: str
    args_hash: str


def action_request(ask: ActionRequest, requested_at: str, not_after: str) -> dict[str, Any]:
    """Build the action request whose hash an approver signs.

    `nonce` is 128 bits of fresh entropy so that two otherwise identical requests are distinct
    objects: an approval of one is not an approval of the other.
    """
    return {
        "v": "stozher/0.1",
        "kind": "action-request",
        "requested-at": requested_at,
        "subject": ask.subject,
        "key": ask.key,
        "component": ask.component,
        "mandate-ref": ask.mandate_ref,
        "policy-version": ask.policy_version,
        "classification": ask.classification,
        "action": ask.action,
        "target": ask.target,
        "args-hash": ask.args_hash,
        "nonce": secrets.token_hex(16),
        "not-after": not_after,
    }


def verify_authorization(
    envelope: dict[str, Any],
    requires_gate: bool,
    approvers: list[str],
    seen_request_hashes: set[str],
    at: str | None = None,
) -> AuthorizationOk | None:
    """The eleven steps of §06 §2, in order, with the specification's reason codes."""
    authorization = envelope.get("authorization")
    if requires_gate and authorization is None:
        raise GateRefusedError("gate-authorization-missing", "a gate rule applies and no approval is present")
    if authorization is None:
        return None

    request = authorization.get("request")
    decision = authorization.get("decision")
    if not isinstance(request, dict) or not isinstance(decision, dict):
        raise GateRefusedError("schema-type-mismatch", "authorization needs a request and a decision")
    when = at or envelope.get("emitted-at", "")

    request_hash = object_hash(request)
    if request_hash != decision.get("request-hash"):
        raise GateRefusedError("gate-authorization-request-hash-mismatch", request_hash)
    if verify_signed_object(decision) is None:
        raise GateRefusedError("gate-decision-sig-invalid", "the approver's signature does not verify")
    approver_key = decision["sig"]["key"]
    if approver_key == request.get("key"):
        raise GateRefusedError("gate-self-approval", approver_key)
    if approver_key not in approvers:
        raise GateRefusedError("gate-approver-not-permitted", approver_key)
    verdict = decision.get("decision")
    if verdict not in ("approve", "deny"):
        raise GateRefusedError("gate-decision-unknown", repr(verdict))
    if verdict == "deny":
        reason = decision.get("reason")
        if not isinstance(reason, str) or not reason:
            raise GateRefusedError("gate-denial-without-reason", "a denial must say why")
        raise GateRefusedError("gate-denied", reason)
    if decision.get("decided-at", "") > request.get("not-after", ""):
        raise GateRefusedError("gate-request-expired", str(request.get("not-after")))
    if not decision.get("decided-at", "") <= when <= decision.get("not-after", ""):
        raise GateRefusedError("gate-approval-expired", str(decision.get("not-after")))

    execution = envelope.get("execution") or {}
    mismatch = (
        request.get("subject") != envelope.get("identity", {}).get("subject")
        or request.get("key") != envelope.get("identity", {}).get("key")
        or request.get("component") != envelope.get("identity", {}).get("component")
        or request.get("mandate-ref") != envelope.get("mandate-ref")
        or request.get("policy-version") != envelope.get("policy-version")
        or request.get("classification") != envelope.get("classification")
        or request.get("action") != execution.get("action")
        or request.get("target") != execution.get("target")
        or request.get("args-hash") != execution.get("args-hash")
    )
    if mismatch:
        # (10) carrying a valid approval for action A while executing action B.
        raise GateRefusedError("gate-authorization-action-mismatch", str(request.get("action")))

    single_use = bool(decision.get("single-use", True))
    if single_use and request_hash in seen_request_hashes:
        raise GateRefusedError("gate-authorization-replayed", request_hash)
    return AuthorizationOk(request_hash, approver_key, single_use)

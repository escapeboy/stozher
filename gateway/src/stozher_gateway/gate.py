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
from .envelope import is_timestamp
from .signing import verify_signed_object

__all__ = [
    "ActionRequest",
    "Approver",
    "AuthorizationOk",
    "GateRefusedError",
    "action_request",
    "verify_authorization",
]


class GateRefusedError(ValueError):
    """A gate refusal carrying its normative reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class Approver(NamedTuple):
    """A key permitted to approve a scope, and the subject it signs as.

    §06 §5 states self-approval as two conjoined MUSTs — `decision.sig.key` MUST NOT equal
    `request.key`, **and** the approver subject MUST NOT be the requesting subject. The second is
    checkable only if the verifier can name the human behind the key, so the key alone is not
    enough: a human holding a second key is still one human, and a second keypair is the cheapest
    thing in the protocol to mint. A caller that resolved these keys resolved them *from* subjects
    (§06 §5: "entries name subjects; the permitted keys are those subjects' enrolled keys"), so it
    already holds the answer and carrying it here costs nothing.

    `subject` is None where the deployment lists a key as permitted but cannot say whose it is. The
    subject MUST is then unevaluable and the verdict rests on the key check and on the key being
    explicitly permitted — a verifier MUST NOT infer a subject it was not given, and MUST NOT read
    "unknown" as "the requester".
    """

    key: str
    subject: str | None = None


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
    approvers: list[Approver],
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

    request_hash = object_hash(request)
    if request_hash != decision.get("request-hash"):
        raise GateRefusedError("gate-authorization-request-hash-mismatch", request_hash)
    if verify_signed_object(decision) is None:
        raise GateRefusedError("gate-decision-sig-invalid", "the approver's signature does not verify")

    # (4) nobody approves their own action — §06 §5 states this over the key *and* the subject.
    approver_key = decision["sig"]["key"]
    requester_key = request.get("key")
    if not isinstance(requester_key, str):
        raise GateRefusedError("schema-missing-member", "authorization.request.key")
    if approver_key == requester_key:
        raise GateRefusedError("gate-self-approval", approver_key)
    approver = next((candidate for candidate in approvers if candidate.key == approver_key), None)
    acting_as = approver.subject if approver is not None else None
    requested_by = request.get("subject")
    if isinstance(acting_as, str) and isinstance(requested_by, str) and acting_as == requested_by:
        # The keypair comparison above is satisfied by any second key, so on its own it stops
        # nobody. An approver whose subject the caller could not name falls to step (5), which is
        # where a key nobody can place is refused anyway.
        raise GateRefusedError(
            "gate-self-approval", f"{approver_key} acts as {acting_as}, which requested the action"
        )

    # (5) the approver is permitted to approve this scope
    if approver is None:
        raise GateRefusedError("gate-approver-not-permitted", approver_key)
    verdict = decision.get("decision")
    if verdict not in ("approve", "deny"):
        raise GateRefusedError("gate-decision-unknown", repr(verdict))
    if verdict == "deny":
        reason = decision.get("reason")
        if not isinstance(reason, str) or not reason:
            raise GateRefusedError("gate-denial-without-reason", "a denial must say why")
        raise GateRefusedError("gate-denied", reason)

    decided_at = _present(decision.get("decided-at"), "authorization.decision.decided-at")
    decision_not_after = _present(decision.get("not-after"), "authorization.decision.not-after")
    request_not_after = _present(request.get("not-after"), "authorization.request.not-after")
    when = _present(at if at is not None else envelope.get("emitted-at"), "emitted-at")
    # Steps (8) and (9) compare timestamps as strings, which is exact for §01 §2.3's fixed-width
    # form and meaningless for anything else: `"z"` sorts above every real timestamp, so an approval
    # bounded by it is bounded by nothing and step (9) becomes vacuous. Nothing upstream is entitled
    # to have checked these — `envelope.validate` does not descend into `authorization` — so the
    # comparison validates its own operands rather than assuming someone else did.
    for what, value in (
        ("authorization.decision.decided-at", decided_at),
        ("authorization.decision.not-after", decision_not_after),
        ("authorization.request.not-after", request_not_after),
        ("emitted-at", when),
    ):
        if not is_timestamp(value):
            raise GateRefusedError("encoding-bad-timestamp", f"{what} = {value!r}")

    # (8) the request had not already timed out when it was decided
    if decided_at > request_not_after:
        raise GateRefusedError("gate-request-expired", request_not_after)
    # (9) the effect happened inside the approval's window, inclusive at both ends
    if when < decided_at or when > decision_not_after:
        raise GateRefusedError("gate-approval-expired", decision_not_after)

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

    # (11) single use. §06 §1.2 makes `single-use` a boolean, and `false` is permitted only where
    # policy explicitly allows it. A value outside the type is therefore not the permission to
    # reuse — it is a malformed decision, and the safe reading of a malformed decision is the
    # restrictive one. `bool(...)` reads `0` and `[]` as "reusable", which is the unsafe direction.
    claimed = decision.get("single-use", True)
    single_use = claimed if isinstance(claimed, bool) else True
    if single_use and request_hash in seen_request_hashes:
        raise GateRefusedError("gate-authorization-replayed", request_hash)
    return AuthorizationOk(request_hash, approver_key, single_use)


def _present(value: Any, what: str) -> str:
    """The string at `what`, or the refusal §06 §2 owes a caller that omitted a required member."""
    if not isinstance(value, str):
        raise GateRefusedError("schema-missing-member", what)
    return value

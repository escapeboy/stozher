"""Mandate chain verification, per `spec/03-mandate.md` §5.

"Walk the chain to a named human" is this function. The loop can only return ACCEPT from the
`interactive`/`standing` branch, which requires an enrolled human root key — termination at a human
is therefore structural, not a convention a later refactor could drop.

The gateway runs it locally so a call is refused *before* it reaches the upstream server. The kernel
runs it again at ingest; neither trusts the other's answer.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from . import money
from .signing import object_id, verify_signed_object

__all__ = ["MandateRefusedError", "MandateRequest", "MandateOk", "verify_mandate_chain", "scope_permits"]


class MandateRequest(NamedTuple):
    """The tuple a mandate's scope is checked against (§03 §4.2)."""

    component: str
    action: str
    classification: str
    resource: str


class MandateOk(NamedTuple):
    """An accepted walk."""

    human_root: str
    root_key: str
    depth: int


class MandateRefusedError(ValueError):
    """A mandate refusal carrying its normative reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def verify_mandate_chain(
    mandates: dict[str, Any],
    mandate_ref: str,
    request: MandateRequest | None,
    *,
    at: str,
    subject_key: str,
    roots: list[str],
    revocations: list[dict[str, Any]],
    max_depth: int = 3,
) -> MandateOk:
    """Run §03 §5. `request` of ``None`` skips `scope_permits` only (the cognition entry point)."""
    mandate = mandates.get(mandate_ref)
    if mandate is None:
        raise MandateRefusedError("mandate-unresolved", mandate_ref)
    if mandate.get("grantee", {}).get("key") != subject_key:
        raise MandateRefusedError("mandate-grantee-key-mismatch", subject_key)
    revoked_at = _revocation_instants(revocations)
    depth = 0
    while True:
        _verify_link(mandate, at, revoked_at, request)
        kind = mandate.get("mandate-kind")
        if kind in ("interactive", "standing"):
            if mandate.get("parent") is not None:
                raise MandateRefusedError("mandate-root-has-parent", str(mandate.get("parent")))
            grantor = mandate["grantor"]
            if grantor.get("role") != "human":
                raise MandateRefusedError("mandate-root-grantor-not-human", str(grantor.get("role")))
            if grantor["key"] not in roots:
                raise MandateRefusedError("mandate-root-not-enrolled", grantor["key"])
            return MandateOk(grantor["subject"], grantor["key"], depth)

        if kind != "delegated":
            raise MandateRefusedError("mandate-kind-unknown", str(kind))
        parent_ref = mandate.get("parent")
        if parent_ref is None:
            raise MandateRefusedError("mandate-delegated-without-parent", object_id(mandate))
        if mandate["grantor"].get("role") != "agent":
            raise MandateRefusedError("mandate-delegated-grantor-not-agent", str(parent_ref))
        parent = mandates.get(parent_ref)
        if parent is None:
            raise MandateRefusedError("mandate-unresolved", str(parent_ref))
        if mandate["grantor"]["key"] != parent["grantee"]["key"]:
            raise MandateRefusedError("mandate-delegation-not-held", mandate["grantor"]["key"])
        if int(parent.get("max-depth", 0)) < 1:
            raise MandateRefusedError("mandate-delegation-depth-exceeded", "parent max-depth is 0")
        if int(mandate.get("max-depth", 0)) > int(parent["max-depth"]) - 1:
            raise MandateRefusedError("mandate-delegation-depth-exceeded", "hop budget did not decrease")
        _require_subset(mandate["scope"], parent["scope"])
        if not (parent["not-before"] <= mandate["not-before"] and mandate["not-after"] <= parent["not-after"]):
            raise MandateRefusedError("mandate-window-outside-parent", object_id(mandate))
        _require_budget_within(mandate.get("budget"), parent.get("budget"))
        depth += 1
        if depth > max_depth:
            raise MandateRefusedError("mandate-delegation-depth-exceeded", f"depth {depth}")
        mandate = parent


def _verify_link(
    mandate: dict[str, Any],
    at: str,
    revoked_at: dict[str, str],
    request: MandateRequest | None,
) -> None:
    if verify_signed_object(mandate) is None:
        raise MandateRefusedError("sig-invalid", "the mandate signature does not verify")
    if mandate["sig"]["key"] != mandate["grantor"]["key"]:
        raise MandateRefusedError("mandate-signer-not-grantor", mandate["sig"]["key"])
    if mandate["grantor"]["key"] == mandate["grantee"]["key"]:
        raise MandateRefusedError("mandate-self-grant", mandate["grantor"]["key"])
    if not mandate.get("not-after"):
        raise MandateRefusedError("mandate-missing-expiry", object_id(mandate))
    if at < mandate["not-before"]:
        raise MandateRefusedError("mandate-not-yet-valid", mandate["not-before"])
    if at > mandate["not-after"]:
        raise MandateRefusedError("mandate-expired", mandate["not-after"])
    revoked = revoked_at.get(object_id(mandate))
    if revoked is not None and revoked <= at:
        raise MandateRefusedError("mandate-revoked", revoked)
    if request is not None and not scope_permits(mandate["scope"], request):
        raise MandateRefusedError("mandate-scope-not-permitted", request.action)


def _revocation_instants(revocations: list[dict[str, Any]]) -> dict[str, str]:
    """Earliest valid revocation per mandate — a second revocation never moves the instant (§03 §7)."""
    instants: dict[str, str] = {}
    for revocation in revocations:
        if verify_signed_object(revocation) is None:
            continue
        target = revocation.get("revokes")
        at = revocation.get("revoked-at")
        if not isinstance(target, str) or not isinstance(at, str):
            continue
        if target not in instants or at < instants[target]:
            instants[target] = at
    return instants


def scope_permits(scope: dict[str, Any], request: MandateRequest) -> bool:
    """`scope_permits` of §03 §4.2: every dimension matches at least one pattern."""
    return (
        _matches(scope.get("components", []), request.component)
        and _matches(scope.get("actions", []), request.action)
        and _matches(scope.get("classes", []), request.classification)
        and _matches(scope.get("resources", []), request.resource)
    )


def _matches(patterns: list[str], value: str) -> bool:
    return any(_pattern_matches(pattern, value) for pattern in patterns)


def _pattern_matches(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        # Prefix matching applies to dot-separated segments only: `github.*` matches
        # `github.create_issue`, not `github` itself and not `githubx.foo`.
        return value.startswith(pattern[:-1])
    return pattern == value


def _require_subset(child: dict[str, Any], parent: dict[str, Any]) -> None:
    for dimension in ("components", "actions", "classes", "resources"):
        for pattern in child.get(dimension, []):
            if not any(_covers(wider, pattern) for wider in parent.get(dimension, [])):
                raise MandateRefusedError("mandate-scope-widened", f"{dimension}: {pattern}")


def _covers(wider: str, narrower: str) -> bool:
    """True when `wider` permits everything `narrower` does. Scope may only narrow (§03 §5)."""
    if wider == "*":
        return True
    if narrower == "*":
        return False
    if wider.endswith(".*"):
        return narrower.startswith(wider[:-1])
    return wider == narrower


def _require_budget_within(child: dict[str, Any] | None, parent: dict[str, Any] | None) -> None:
    if not child or not parent:
        return
    for dimension, cap in parent.items():
        if dimension not in child:
            continue
        value = child[dimension]
        if isinstance(cap, str) or isinstance(value, str):
            # Exactly, never through a float. `float(s)` here reintroduced the representation §01
            # §2.5 removed, at the one place it decides whether authority narrows — and it read a
            # different set of strings than Rust's `parse::<f64>()` did, so the same mandate could be
            # valid through one implementation and refused by the other. See `money`.
            #
            # The condition is `or`, not `and`: a child that answers a monetary cap with a JSON
            # number is a type error, and `int(value) > int(cap)` would have compared it happily.
            try:
                exceeded = not money.at_most(value, cap)
            except money.MoneyFormatError as e:
                raise MandateRefusedError("schema-type-mismatch", f"budget.{dimension}: {e}") from e
        else:
            # §01 §2.5 bounds every protocol number to an integer, so a non-integer here is a type
            # error rather than something to round.
            if not isinstance(value, int) or not isinstance(cap, int) or isinstance(value, bool):
                raise MandateRefusedError(
                    "schema-type-mismatch",
                    f"budget.{dimension} must be an integer or a decimal string",
                )
            exceeded = value > cap
        if exceeded:
            raise MandateRefusedError("mandate-budget-exceeds-parent", dimension)

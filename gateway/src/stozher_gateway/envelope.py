"""Envelope structural validation, per `spec/02-envelope.md` §9.

The gateway validates every envelope it builds before it durably chains it. Emitting an envelope the
kernel will refuse is not a transport error — it is an effect that happened in the world and did not
reach the audit, which is the one failure mode the product exists to prevent. Refusing locally, with
the same reason code the kernel would use, keeps the bug where it can still be seen.

Error-code precedence is not arbitrary. `cognition`/`signal` carrying an effect field is reported as
`cognition-envelope-has-effect-fields` rather than `schema-unknown-member`, because the point of that
rule is that there is *nowhere* for a prompt or a tool argument to live in a cognition envelope —
naming it "unknown member" would describe an oversight instead of a prohibition.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

__all__ = ["CLASSES", "EnvelopeError", "is_timestamp", "validate"]

CLASSES = ("read", "benign", "consequential", "prohibited")
_OUTCOMES = ("applied", "failed", "denied", "blocked", "attempted")
_MAX_SAFE_INTEGER = 2**53 - 1
#: The most distinct actions one `aggregate` window may fold (§02 §9.1, `aggregate-cardinality`).
_AGGREGATE_MAX_ACTIONS = 1024

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"\Aed25519:[0-9a-f]{64}\Z")
_STREAM = re.compile(r"\A[A-Za-z0-9._:-]{1,128}\Z")
_MONEY = re.compile(r"\Amoney-[a-z]{3}\Z")

_COMMON = ("v", "kind", "emitted-at", "stream", "seq", "prev-hash", "identity", "sig")
#: Members every kind MAY carry (§02 §2.1). Both are stored and never interpreted, and neither
#: carries authority, so there is no kind they can be wrong on. `trigger` is deliberately not here:
#: §07 §4 makes it a link from an effect to the signal that caused it, and a mandate grant or a
#: checkpoint has no effect to link.
_COMMON_OPTIONAL = ("memory-ref", "correlation-ref")

#: `kind` → (additional required members, additional optional members).
_KINDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "effect": (
        ("mandate-ref", "policy-version", "classification", "execution"),
        ("evidence", "authorization", "trigger", "commitment-ref"),
    ),
    "cognition": (("mandate-ref", "resource", "cost"), ()),
    "aggregate": (
        ("mandate-ref", "policy-version", "classification", "window", "counts", "sample-hashes"),
        (),
    ),
    "mandate": (("mandate",), ()),
    # §03 §7: the revoker signs the object under `revocation`; the envelope's own `sig` is the
    # emitter's and attests receipt, not authority. The other three are a projection of it,
    # kept so a store can index a revocation without opening it, and checked for agreement.
    "revocation": (("revocation", "revokes", "revoked-at"), ("reason",)),
    "policy-change": (
        ("mandate-ref", "policy-version", "classification", "execution", "authorization"),
        # Not `commitment-ref`: §02 §8 makes it a durable-object transition, and publishing a
        # policy is not one (§02 §2.1).
        ("evidence",),
    ),
    "gate-decision": (("decision-of",), ("decision",)),
    "signal": (("signal",), ()),
    "checkpoint": (("checkpoint",), ()),
}

#: Members a `cognition` envelope must not carry, and members a `signal` must not carry (§02 §9.1).
_COGNITION_FORBIDDEN = ("execution", "evidence", "classification", "authorization", "commitment-ref")
_SIGNAL_FORBIDDEN = (
    "mandate-ref",
    "classification",
    "execution",
    "evidence",
    "authorization",
    "commitment-ref",
)

#: The strict member sets of §02 §9.1's nested objects.
_NESTED: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "identity": (("subject", "key", "component"), ()),
    "execution": (
        ("action", "target", "args-hash", "outcome", "started-at", "finished-at"),
        (),
    ),
    "evidence": (("schema", "media-type", "payload-hash", "retain-until"), ()),
    # §07 §4. Absent here for the whole of v0.1, so a `trigger` was permitted on an effect and its
    # members were never looked at — the one implementation checked them, this one accepted anything.
    "trigger": (("signal-ref", "standing-mandate-ref"), ("rule",)),
    # §03 §7. The nested object the revoker signed. `v` and `kind` are optional here because
    # they are the object's own, not the envelope's, and an implementation that omitted them
    # would still have signed the same three facts.
    "revocation": (("revokes", "revoked-at", "sig"), ("v", "kind", "reason")),
    # §07 §2. Absent here since v0.1, so a `signal` envelope's one required member was never looked
    # at: the other implementation checks it, this one accepted `"signal": {}` and any member inside
    # it — including one an implementation might read as an instruction (§07 §3).
    "signal": (
        ("source", "received-at", "media-type", "payload-hash", "sender-verified"),
        ("source-ref", "retain-until", "sender-verification"),
    ),
    # §02 §8. Likewise: the member was permitted on an effect and its shape never checked.
    "commitment-ref": (("object-type", "object-id", "transition"), ()),
    "authorization": (("request", "decision"), ()),
    "sig": (("alg", "key", "value"), ()),
    "resource": (("kind", "name"), ()),
    "window": (("from", "to"), ()),
    "counts": (("total", "by-action"), ()),
}

_COST_MEMBERS = (
    "tokens",
    "tokens-in",
    "tokens-out",
    "requests",
    "wall-clock-ms",
    "wall-clock-seconds",
)


class EnvelopeError(ValueError):
    """A structural refusal carrying its normative reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def validate(envelope: Any) -> None:
    """Raise :class:`EnvelopeError` unless `envelope` is structurally valid (§02 §9)."""
    if not isinstance(envelope, dict):
        raise EnvelopeError("schema-type-mismatch", "an envelope must be an object")
    # §02 §9.1 gives `envelope-version-unsupported` for "`v` is not stozher/0.1" and
    # `schema-missing-member` for an absent REQUIRED member: absence and a wrong *value* are two
    # conditions with two codes, and collapsing them here made an envelope with no `v` at all report
    # a version this implementation does not support. The same for `kind`.
    if "v" not in envelope:
        raise EnvelopeError("schema-missing-member", "v")
    if not isinstance(envelope["v"], str):
        raise EnvelopeError("schema-type-mismatch", "v must be a string")
    if envelope["v"] != "stozher/0.1":
        raise EnvelopeError("envelope-version-unsupported", repr(envelope["v"]))
    if "kind" not in envelope:
        raise EnvelopeError("schema-missing-member", "kind")
    kind = envelope["kind"]
    if not isinstance(kind, str):
        raise EnvelopeError("schema-type-mismatch", "kind must be a string")
    if kind not in _KINDS:
        raise EnvelopeError("envelope-unknown-kind", repr(kind))

    if kind == "cognition":
        _forbid(envelope, _COGNITION_FORBIDDEN, "cognition-envelope-has-effect-fields")
    if kind == "signal":
        _forbid(envelope, _SIGNAL_FORBIDDEN, "signal-envelope-has-effect-fields")

    required, optional = _KINDS[kind]
    permitted = set(_COMMON) | set(_COMMON_OPTIONAL) | set(required) | set(optional)
    for name in envelope:
        if name not in permitted:
            raise EnvelopeError("schema-unknown-member", f"{kind}.{name}")
    for name in (*_COMMON, *required):
        if name not in envelope:
            raise EnvelopeError("schema-missing-member", f"{kind}.{name}")

    _strings(envelope, ("emitted-at", "stream", "v", "kind"))
    _timestamp(envelope["emitted-at"], "emitted-at")
    if not _STREAM.match(str(envelope["stream"])):
        raise EnvelopeError("stream-id-malformed", str(envelope["stream"]))
    if isinstance(envelope["seq"], bool) or (
        isinstance(envelope["seq"], int) and envelope["seq"] < 0
    ):
        # §04 §2: a position in a stream starts at 0 and increases by one. A negative `seq` is not a
        # position, and it satisfies neither genesis rule below — so it was accepted here and
        # refused by the kernel, which reads the member as an unsigned integer or not at all.
        raise EnvelopeError("schema-type-mismatch", "seq must be a non-negative integer")
    seq = _integer(envelope["seq"], "seq")

    prev = envelope["prev-hash"]
    if seq == 0 and prev is not None:
        raise EnvelopeError("chain-genesis-prev-not-null", "seq 0 must carry a null prev-hash")
    if seq > 0 and prev is None:
        raise EnvelopeError("chain-prev-hash-missing", f"seq {seq} must carry a prev-hash")
    if prev is not None:
        _hash(prev, "prev-hash")

    for name, value in envelope.items():
        _nested(name, value)

    if envelope["identity"]["key"] != envelope["sig"]["key"]:
        raise EnvelopeError("identity-key-sig-mismatch", "identity.key must equal sig.key")
    # §01 §4: a key identifier is `ed25519:` and 64 lowercase hex. Unchecked here, an envelope whose
    # subject is named by a string that identifies no key passed this validator and was refused by
    # the kernel — the one failure mode this module exists to prevent.
    if not _KEY_ID.match(str(envelope["identity"]["key"])):
        raise EnvelopeError("key-id-malformed", str(envelope["identity"]["key"]))

    for name in ("mandate-ref", "revokes", "decision-of"):
        if name in envelope:
            _hash(envelope[name], name)

    classification = envelope.get("classification")
    if classification is not None and classification not in CLASSES:
        raise EnvelopeError("envelope-classification-unknown", repr(classification))

    if "execution" in envelope:
        _execution(envelope["execution"])
    if "evidence" in envelope:
        _evidence(envelope["evidence"])
    if "trigger" in envelope:
        _trigger(envelope["trigger"])
    if "signal" in envelope:
        _signal(envelope["signal"])
    if kind == "revocation":
        _revocation(envelope)
    if kind == "aggregate":
        _aggregate(envelope)
    if kind == "cognition":
        _cost(envelope["cost"])
    if "correlation-ref" in envelope:
        reference = envelope["correlation-ref"]
        if not isinstance(reference, str):
            raise EnvelopeError("schema-type-mismatch", "correlation-ref must be a string")
        if len(reference.encode("utf-8")) > 512:
            raise EnvelopeError("correlation-ref-too-long", f"{len(reference)} characters")


def _forbid(envelope: dict[str, Any], members: tuple[str, ...], code: str) -> None:
    for name in members:
        if name in envelope:
            raise EnvelopeError(code, name)


def _strings(obj: dict[str, Any], names: tuple[str, ...]) -> None:
    for name in names:
        if not isinstance(obj.get(name), str):
            raise EnvelopeError("schema-type-mismatch", f"{name} must be a string")


def _nested(name: str, value: Any) -> None:
    spec = _NESTED.get(name)
    if spec is None:
        return
    if not isinstance(value, dict):
        raise EnvelopeError("schema-type-mismatch", f"{name} must be an object")
    required, optional = spec
    for member in value:
        if member not in required and member not in optional:
            raise EnvelopeError("schema-unknown-member", f"{name}.{member}")
    for member in required:
        if member not in value:
            raise EnvelopeError("schema-missing-member", f"{name}.{member}")


def _execution(execution: dict[str, Any]) -> None:
    _strings(execution, ("action", "target", "outcome", "started-at", "finished-at"))
    _hash(execution["args-hash"], "execution.args-hash")
    if execution["outcome"] not in _OUTCOMES:
        raise EnvelopeError("envelope-outcome-unknown", repr(execution["outcome"]))
    started, finished = execution["started-at"], execution["finished-at"]
    _timestamp(started, "execution.started-at")
    _timestamp(finished, "execution.finished-at")
    if finished < started:
        raise EnvelopeError("execution-time-inverted", f"{finished} precedes {started}")


def _trigger(trigger: dict[str, Any]) -> None:
    """§07 §4: both references are envelope ids, so both are digests."""
    _hash(trigger["signal-ref"], "trigger.signal-ref")
    _hash(trigger["standing-mandate-ref"], "trigger.standing-mandate-ref")
    if "rule" in trigger and not isinstance(trigger["rule"], str):
        raise EnvelopeError("schema-type-mismatch", "trigger.rule must be a string")


def _revocation(envelope: dict[str, Any]) -> None:
    """§03 §7: the top-level members are a projection of the signed object and must agree with it.

    `revokes`, `revoked-at` and `reason` are duplicated out of `revocation` so a store can index a
    revocation without opening it — the same shape `decision-of` has beside `decision`. Duplication
    is only safe while the two cannot disagree: otherwise an emitter picks which reader agrees with
    it, and a revocation is the last record in this system that may be ambiguous.
    """
    object_ = envelope["revocation"]
    if not isinstance(object_, dict):
        raise EnvelopeError("schema-type-mismatch", "revocation must be an object")
    _hash(object_["revokes"], "revocation.revokes")
    _timestamp(object_["revoked-at"], "revocation.revoked-at")
    for name in ("revokes", "revoked-at", "reason"):
        if envelope.get(name) != object_.get(name):
            raise EnvelopeError(
                "revocation-object-mismatch",
                f"the envelope's {name} does not match the signed revocation object",
            )


def _signal(signal: dict[str, Any]) -> None:
    """§07 §2: the receipt record's own members, checked like `evidence`'s."""
    _hash(signal["payload-hash"], "signal.payload-hash")
    _timestamp(signal["received-at"], "signal.received-at")
    if "retain-until" in signal:
        _timestamp(signal["retain-until"], "signal.retain-until")


def _evidence(evidence: dict[str, Any]) -> None:
    _strings(evidence, ("schema", "media-type", "retain-until"))
    _hash(evidence["payload-hash"], "evidence.payload-hash")
    _timestamp(evidence["retain-until"], "evidence.retain-until")


def _aggregate(envelope: dict[str, Any]) -> None:
    if envelope["classification"] != "read":
        raise EnvelopeError("aggregate-class-not-read", repr(envelope["classification"]))
    counts = envelope["counts"]
    by_action = counts.get("by-action")
    if not isinstance(by_action, dict):
        raise EnvelopeError("schema-type-mismatch", "counts.by-action must be an object")
    total = _integer(counts["total"], "counts.total")
    # §02 §9.1 tabulates both of these and this implementation had neither: without the sign rule
    # §7.3's sum is satisfiable by cancellation (one entry of 1000000 and one of -999999 sum to 1),
    # and without the bound one envelope is unbounded work for every consumer that iterates it.
    if total < 0:
        raise EnvelopeError("aggregate-count-negative", f"counts.total is {total}")
    if len(by_action) > _AGGREGATE_MAX_ACTIONS:
        raise EnvelopeError("aggregate-cardinality", f"{len(by_action)} distinct actions")
    folded = 0
    for action, count in by_action.items():
        value = _integer(count, f"counts.by-action.{action}")
        if value < 0:
            raise EnvelopeError("aggregate-count-negative", f"counts.by-action.{action} is {value}")
        folded += value
    if total != folded:
        raise EnvelopeError("aggregate-count-mismatch", f"{total} != {folded}")
    samples = envelope["sample-hashes"]
    if not isinstance(samples, list) or not 1 <= len(samples) <= 16:
        raise EnvelopeError("aggregate-sample-bounds", f"{len(samples)} samples")
    for sample in samples:
        _hash(sample, "sample-hashes[]")
    window = envelope["window"]
    _timestamp(window["from"], "window.from")
    _timestamp(window["to"], "window.to")


def _cost(cost: Any) -> None:
    if not isinstance(cost, dict):
        raise EnvelopeError("schema-type-mismatch", "cost must be an object")
    for name, value in cost.items():
        if _MONEY.match(name):
            if not isinstance(value, str):
                raise EnvelopeError("schema-type-mismatch", f"cost.{name} must be a string")
        elif name in _COST_MEMBERS:
            _integer(value, f"cost.{name}")
        else:
            raise EnvelopeError("schema-unknown-member", f"cost.{name}")


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EnvelopeError("encoding-non-integer-number", f"{name} must be an integer")
    if abs(value) > _MAX_SAFE_INTEGER:
        raise EnvelopeError("encoding-integer-out-of-range", f"{name} = {value}")
    return value


def _hash(value: Any, name: str) -> None:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise EnvelopeError("encoding-not-lowercase-hex", f"{name} must be 64 lowercase hex")


def is_timestamp(value: Any) -> bool:
    """Whether `value` is §01 §2.3's fixed 24-byte form, and denotes a real instant.

    Public because the gate's step (8) and (9) comparisons need it: those compare timestamps as
    strings, which is exact for this form and meaningless for anything else, and nothing upstream
    validates the members of `authorization` (§06 §2, `gate.py`).
    """
    if not isinstance(value, str) or not _TIMESTAMP.match(value):
        return False
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _timestamp(value: Any, name: str) -> None:
    if not is_timestamp(value):
        raise EnvelopeError("encoding-bad-timestamp", f"{name} = {value!r}")

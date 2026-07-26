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

__all__ = ["CLASSES", "EnvelopeError", "validate"]

CLASSES = ("read", "benign", "consequential", "prohibited")
_OUTCOMES = ("applied", "failed", "denied", "blocked", "attempted")
_MAX_SAFE_INTEGER = 2**53 - 1

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_STREAM = re.compile(r"\A[A-Za-z0-9._:-]{1,128}\Z")
_MONEY = re.compile(r"\Amoney-[a-z]{3}\Z")

_COMMON = ("v", "kind", "emitted-at", "stream", "seq", "prev-hash", "identity", "sig")
_COMMON_OPTIONAL = ("memory-ref", "correlation-ref", "trigger")

#: `kind` → (additional required members, additional optional members).
_KINDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "effect": (
        ("mandate-ref", "policy-version", "classification", "execution"),
        ("evidence", "authorization", "commitment-ref"),
    ),
    "cognition": (("mandate-ref", "resource", "cost"), ()),
    "aggregate": (
        ("mandate-ref", "policy-version", "classification", "window", "counts", "sample-hashes"),
        (),
    ),
    "mandate": (("mandate",), ()),
    "revocation": (("revokes", "revoked-at"), ("reason",)),
    "policy-change": (
        ("mandate-ref", "policy-version", "classification", "execution", "authorization"),
        ("evidence", "commitment-ref"),
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
    if envelope.get("v") != "stozher/0.1":
        raise EnvelopeError("envelope-version-unsupported", repr(envelope.get("v")))
    kind = envelope.get("kind")
    if not isinstance(kind, str) or kind not in _KINDS:
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
    folded = 0
    for action, count in by_action.items():
        folded += _integer(count, f"counts.by-action.{action}")
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


def _timestamp(value: Any, name: str) -> None:
    if not isinstance(value, str) or not _TIMESTAMP.match(value):
        raise EnvelopeError("encoding-bad-timestamp", f"{name} = {value!r}")
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as e:
        raise EnvelopeError("encoding-bad-timestamp", f"{name} = {value!r}") from e

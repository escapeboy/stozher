"""Evidence payload binding, per `spec/04-chain-and-checkpoints.md` §5.2.

The envelope never contains the payload; it commits to a hash. The gateway checks the binding before
it submits, for the same reason the kernel checks it after: the payload store must be reachable only
through an envelope that commits to what it holds, or it becomes unaudited storage.
"""

from __future__ import annotations

from typing import Any

from .canonical import object_hash, sha256_hex

__all__ = ["PayloadError", "referenced_hashes", "verify_ingest"]


class PayloadError(ValueError):
    """A payload-binding refusal carrying its normative reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def referenced_hashes(envelope: dict[str, Any]) -> set[str]:
    """Every `payload-hash` the envelope commits to."""
    hashes = set()
    for member in ("evidence", "signal"):
        section = envelope.get(member)
        if isinstance(section, dict) and isinstance(section.get("payload-hash"), str):
            hashes.add(section["payload-hash"])
    return hashes


def verify_ingest(envelope: dict[str, Any], payloads: list[dict[str, Any]]) -> bool:
    """Return True when every submitted payload hashes to a value the envelope references.

    An empty `payloads` array is always valid — a missing payload is never an error at ingest, and
    the same envelope with and without it has the identical hash. That is decay, expressed as a
    property rather than a promise.
    """
    referenced = referenced_hashes(envelope)
    for payload in payloads:
        declared = payload.get("payload-hash")
        media_type = payload.get("media-type")
        body = payload.get("payload")
        if not isinstance(declared, str) or not isinstance(media_type, str):
            raise PayloadError("schema-missing-member", "payload-hash and media-type are required")
        if media_type == "application/json":
            computed = object_hash(body)
        else:
            if not isinstance(body, str):
                raise PayloadError("schema-type-mismatch", "an opaque payload is hex-encoded")
            try:
                computed = sha256_hex(bytes.fromhex(body))
            except ValueError as e:
                raise PayloadError("encoding-not-lowercase-hex", "payload") from e
        if computed != declared:
            raise PayloadError("payload-hash-mismatch", declared)
        if declared not in referenced:
            raise PayloadError("payload-not-referenced", declared)
    return bool(referenced) and not payloads

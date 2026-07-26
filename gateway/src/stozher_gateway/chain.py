"""Local hash-chain construction and verification, per `spec/04-chain-and-checkpoints.md` §2.

The gateway is an emitter with its own streams: it chains locally with the same rule the kernel
applies and syncs later, so the kernel's acceptance never renumbers anything (§04 §3). Verification
here never reads an evidence payload — that independence is the GDPR property, and it is a property
of the *verifier*, not only of the store.
"""

from __future__ import annotations

from typing import Any

from .envelope import EnvelopeError, validate
from .signing import object_id, verify_signed_object

__all__ = ["ChainError", "ChainReport", "verify_chain"]


class ChainError(ValueError):
    """A chain refusal, naming the `seq` at which verification stopped."""

    def __init__(self, code: str, detail: str, seq: int | None) -> None:
        super().__init__(f"{code} at seq {seq}: {detail}")
        self.code = code
        self.detail = detail
        self.seq = seq


class ChainReport:
    """The result of verifying a contiguous range of one stream."""

    def __init__(self, head_hash: str, count: int, anchored: bool) -> None:
        self.head_hash = head_hash
        self.count = count
        #: False when the range does not start at seq 0 and no expected prev-hash was supplied: an
        #: unanchored range proves internal consistency only (§04 §2.1).
        self.anchored = anchored


def verify_chain(
    records: list[dict[str, Any]], stream: str, expected_prev: str | None = None
) -> ChainReport:
    """Verify signatures, schema, `seq` continuity, `prev-hash` linkage and stream identity."""
    if not records:
        raise ChainError("chain-empty-range", "a range must hold at least one envelope", None)
    anchored = records[0].get("seq") == 0 or expected_prev is not None
    previous_id = expected_prev
    previous_seq: int | None = None
    for record in records:
        seq = record.get("seq") if isinstance(record.get("seq"), int) else None
        if verify_signed_object(record) is None:
            raise ChainError("sig-invalid", "the signature does not verify", seq)
        try:
            validate(record)
        except EnvelopeError as e:
            raise ChainError(e.code, e.detail, seq) from e
        if record["stream"] != stream:
            raise ChainError("chain-stream-mismatch", record["stream"], seq)
        seq = int(record["seq"])
        if previous_seq is not None:
            if seq == previous_seq:
                raise ChainError("chain-seq-duplicate", f"seq {seq} appears twice", seq)
            if seq != previous_seq + 1:
                raise ChainError("chain-seq-gap", f"{previous_seq} then {seq}", seq)
        if seq > 0 and previous_id is not None and record["prev-hash"] != previous_id:
            raise ChainError("chain-prev-hash-mismatch", str(record["prev-hash"]), seq)
        previous_seq = seq
        previous_id = object_id(record)
    assert previous_id is not None
    return ChainReport(previous_id, len(records), anchored)

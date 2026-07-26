"""The signed-object pattern of `spec/01-canonicalization-and-crypto.md` §5.

One pattern for every signed object in the system — envelope, mandate, policy document, gate
decision. `sig` is the only member removed to form the signing input; `id()` covers `sig`, which is
why a chain over `id` values commits to its predecessors' signatures and not merely to their bodies.
"""

from __future__ import annotations

from typing import Any

from . import crypto
from .canonical import canonicalize_bytes, object_hash

__all__ = ["SigningKey", "object_id", "signing_input", "verify_signed_object"]


def signing_input(obj: dict[str, Any]) -> bytes:
    """``JCS(S without "sig")`` — the bytes that are signed, over which Ed25519 is pure."""
    return canonicalize_bytes({name: value for name, value in obj.items() if name != "sig"})


def object_id(obj: Any) -> str:
    """``id(S) = object-hash(S)`` over the complete object, `sig` included."""
    return object_hash(obj)


def verify_signed_object(obj: Any) -> str | None:
    """Return the signing key identifier if `obj` verifies strictly, else ``None`` (§01 §5.5)."""
    if not isinstance(obj, dict):
        return None
    sig = obj.get("sig")
    if not isinstance(sig, dict):
        return None
    key, value, alg = sig.get("key"), sig.get("value"), sig.get("alg")
    if alg != "ed25519" or not isinstance(key, str) or not isinstance(value, str):
        return None
    if not crypto.verify(key, signing_input(obj), value):
        return None
    return key


class SigningKey:
    """A key the gateway holds: a derived subject key, or a test approver's key."""

    def __init__(self, secret: bytes, subject: str) -> None:
        self._secret = secret
        self.subject = subject
        self.id = crypto.key_id(crypto.public_key_of(secret))

    @classmethod
    def derived(cls, seed: bytes, role: int, index: int, subject: str) -> SigningKey:
        """A key at ``m/1054'/<role>'/<index>'`` (§01 §6)."""
        return cls(crypto.derive(seed, role, index), subject)

    def sign(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Return `obj` with a `sig` member over its signing input."""
        body = {name: value for name, value in obj.items() if name != "sig"}
        signature = crypto.sign(self._secret, canonicalize_bytes(body))
        body["sig"] = {"alg": "ed25519", "key": self.id, "value": signature.hex()}
        return body

"""Ed25519 and SLIP-0010, per `spec/01-canonicalization-and-crypto.md` §1, §4 and §6.

The Ed25519 dependency is **optional** (ADR-0005 / the integration brief §6): Harbormaster's base
install carries no crypto library, and an unconditional import here would mean a bare Harbormaster
fails to start with the plugin allow-listed. `available()` reports the truth and the gateway refuses
every call rather than proceeding unsigned.

`verify()` is strict in the sense §01 §4 requires: small-order public keys, non-canonically encoded
public keys, and signatures whose scalar `s` is not reduced are rejected before the library is asked.
OpenSSL's Ed25519 does not promise all three, and `spec/vectors/ed25519.json` contains a vector for
each.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

__all__ = [
    "KEY_ID_PATTERN",
    "ROLE_AGENT",
    "ROLE_DEVICE",
    "ROLE_HUMAN_ROOT",
    "ROLE_POLICY",
    "available",
    "derive",
    "derive_path",
    "key_id",
    "public_key_of",
    "require_crypto",
    "sign",
    "verify",
]

KEY_ID_PATTERN = re.compile(r"\Aed25519:[0-9a-f]{64}\Z")

ROLE_HUMAN_ROOT = 0
ROLE_AGENT = 1
ROLE_DEVICE = 2
ROLE_KERNEL_CHECKPOINT = 3
ROLE_POLICY = 4

_PURPOSE = 1054

#: Ed25519 group order. A signature whose `s` is not reduced modulo this is non-canonical.
_ORDER = 2**252 + 27742317777372353535851937790883648493
_FIELD = 2**255 - 19

#: The canonical small-order point encodings (identity, torsion points, and their non-canonical
#: spellings). A public key that is one of these makes every signature verify under a permissive
#: verifier, which is a repudiation attack, not an edge case.
_SMALL_ORDER = frozenset(
    bytes.fromhex(encoding)
    for encoding in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
)


class CryptoUnavailableError(RuntimeError):
    """The optional Ed25519 extra is not installed."""


def _backend() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:  # pragma: no cover - exercised only on a bare install
        raise CryptoUnavailableError(
            "signing needs the optional extra: pip install 'stozher-gateway[crypto]'"
        ) from e
    return ed25519


def available() -> bool:
    """Whether the signing path can run at all."""
    try:
        _backend()
    except CryptoUnavailableError:
        return False
    return True


def require_crypto() -> None:
    """Raise :class:`CryptoUnavailableError` unless Ed25519 is installed."""
    _backend()


def public_key_of(secret: bytes) -> bytes:
    """The 32-byte public key of a 32-byte RFC 8032 seed."""
    ed25519 = _backend()
    private = ed25519.Ed25519PrivateKey.from_private_bytes(secret)
    from cryptography.hazmat.primitives import serialization

    raw: bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return raw


def key_id(public_key: bytes) -> str:
    """``ed25519:<64 hex>`` (§01 §4)."""
    return "ed25519:" + public_key.hex()


def sign(secret: bytes, message: bytes) -> bytes:
    """Pure Ed25519 (never `ph`) over `message`."""
    ed25519 = _backend()
    signature: bytes = ed25519.Ed25519PrivateKey.from_private_bytes(secret).sign(message)
    return signature


def verify(key: str, message: bytes, signature_hex: str) -> bool:
    """Strict verification of a `stozher/0.1` key identifier over `message`."""
    if not KEY_ID_PATTERN.match(key):
        return False
    if len(signature_hex) != 128 or signature_hex != signature_hex.lower():
        return False
    try:
        public = bytes.fromhex(key.removeprefix("ed25519:"))
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if public in _SMALL_ORDER:
        return False
    if int.from_bytes(public, "little") & ((1 << 255) - 1) >= _FIELD:
        return False  # non-canonical y coordinate
    if int.from_bytes(signature[32:], "little") >= _ORDER:
        return False  # non-canonical scalar s
    ed25519 = _backend()
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except Exception:  # noqa: BLE001 - every library failure means "does not verify"
        return False
    return True


def derive_path(seed: bytes, path: str) -> tuple[bytes, bytes]:
    """SLIP-0010 ed25519 derivation along `path`, returning ``(private key, chain code)``.

    Hardened components only: non-hardened derivation is undefined for this curve
    (`slip10-non-hardened-index`), so a path without the apostrophe is a caller error, not a
    fallback.
    """
    if not 16 <= len(seed) <= 64:
        raise ValueError("a SLIP-0010 seed must be 16-64 octets")
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    private, chain = digest[:32], digest[32:]
    components = [component for component in path.split("/")[1:] if component]
    for component in components:
        if not component.endswith("'"):
            raise ValueError(f"slip10-non-hardened-index: {component}")
        index = int(component[:-1])
        if not 0 <= index < 0x80000000:
            raise ValueError(f"derivation index out of range: {component}")
        data = b"\x00" + private + (index + 0x80000000).to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        private, chain = digest[:32], digest[32:]
    return private, chain


def derive(seed: bytes, role: int, index: int) -> bytes:
    """Derive ``m/1054'/<role>'/<index>'`` (§01 §6)."""
    private, _ = derive_path(seed, f"m/{_PURPOSE}'/{role}'/{index}'")
    return private

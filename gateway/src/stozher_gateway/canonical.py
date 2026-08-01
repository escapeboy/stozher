"""JCS (RFC 8785) canonicalization and `object-hash`, per `spec/01-canonicalization-and-crypto.md`.

Written from the specification text rather than ported from `spec/vectors/generate_vectors.py` or
from `kernel/stozher-core/src/jcs.rs`. That independence is the point: a vector suite consumed by a
copy of the generator proves only that a file agrees with itself. The three implementations —
Python generator, Rust kernel, this — meet at `spec/vectors/`.

Two places where a language's defaults are wrong and this module deliberately does not use them:

* member ordering is by **UTF-16 code unit**, not code point, so keys are compared as their
  UTF-16-BE bytes (big-endian byte order *is* code-unit order);
* numbers follow ECMAScript ``Number::toString``, not ``repr``/``str``. ``repr`` supplies the
  shortest round-tripping digit string, which is the same digit string ECMAScript picks; the
  five-branch layout of §01 §3.4 is applied to it here.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

__all__ = [
    "CanonicalizationError",
    "canonicalize",
    "canonicalize_bytes",
    "object_hash",
    "parse",
    "sha256_hex",
]


class CanonicalizationError(ValueError):
    """A canonicalization or parse failure carrying a normative reason code (§01 §3.1)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

_REPR = re.compile(r"\A(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?\Z")


def parse(text: str) -> Any:
    """Parse JSON strictly enough that a canonicalizer never sees an ambiguous document.

    Rejects duplicate member names, the non-JSON literals ``NaN``/``Infinity``, numeric literals
    outside binary64, and unpaired surrogates in escapes.
    """

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for name, _ in items:
            if name in seen:
                raise CanonicalizationError("jcs-duplicate-key", name)
            seen.add(name)
        return dict(items)

    def constant(name: str) -> Any:
        raise CanonicalizationError("jcs-malformed-json", f"{name} is not a JSON literal")

    def number(literal: str) -> float:
        value = float(literal)
        if not math.isfinite(value):
            raise CanonicalizationError(
                "jcs-malformed-json", f"{literal} has no binary64 representation"
            )
        return value

    def integer(literal: str) -> int:
        # §01 §3.1: a numeric literal whose value lies outside the binary64 range has no canonical
        # form and is malformed *input*. Python parses `1` + 400 zeros into an arbitrary-precision
        # `int` and only failed later, in `canonicalize`, reporting `jcs-non-finite-number` — the
        # code §3.1 reserves for the in-memory entry point. The other implementation reports
        # `jcs-malformed-json` here, and the two codes are how a reader tells the entry points apart.
        value = int(literal)
        try:
            representable = math.isfinite(float(value))
        except OverflowError:
            representable = False
        if not representable:
            raise CanonicalizationError(
                "jcs-malformed-json", f"{literal} has no binary64 representation"
            )
        return value

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_float=number,
            parse_int=integer,
        )
    except CanonicalizationError:
        raise
    except ValueError as e:
        raise CanonicalizationError("jcs-malformed-json", str(e)) from e
    except RecursionError as e:
        # `RecursionError` is not a `ValueError`, so it escaped this function while `canonicalize`
        # three lines down had been catching it since v0.1. The docstring promises a reason code a
        # caller can put in a record; an interpreter exception is not one. Not reachable from
        # foreign input today — the proxy path canonicalizes rather than parses — which is why it
        # survived, and exactly why it is worth closing before something starts calling it.
        raise CanonicalizationError(
            "jcs-malformed-json", "nesting exceeds what this parser can represent"
        ) from e
    _reject_lone_surrogates(value)
    return value


def canonicalize(value: Any) -> str:
    """Return ``JCS(value)`` as text.

    Refuses with :class:`CanonicalizationError` and never with a bare interpreter exception: a
    caller that hands this foreign input is entitled to a reason code it can put in a record.
    Nesting deeper than the recursion here can carry is reported as malformed — RFC 8259 §9 leaves
    depth limits to the implementation, and a document past this one's is not one it can represent.
    """
    try:
        _reject_lone_surrogates(value)
        out: list[str] = []
        _write(value, out)
    except RecursionError as e:
        raise CanonicalizationError(
            "jcs-malformed-json", "nesting exceeds what this canonicalizer can represent"
        ) from e
    return "".join(out)


def canonicalize_bytes(value: Any) -> bytes:
    """Return ``JCS(value)`` as the UTF-8 octets that are signed and hashed."""
    return canonicalize(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase-hex SHA-256, the only digest encoding in `stozher/0.1` (§01 §2.1)."""
    return hashlib.sha256(data).hexdigest()


def object_hash(value: Any) -> str:
    """``object-hash(v) = hex(SHA-256(JCS(v)))`` (§01 §3.5)."""
    return sha256_hex(canonicalize_bytes(value))


def _reject_lone_surrogates(value: Any) -> None:
    if isinstance(value, str):
        for character in value:
            if 0xD800 <= ord(character) <= 0xDFFF:
                raise CanonicalizationError(
                    "jcs-lone-surrogate", f"unpaired surrogate U+{ord(character):04X}"
                )
    elif isinstance(value, dict):
        for name, member in value.items():
            _reject_lone_surrogates(name)
            _reject_lone_surrogates(member)
    elif isinstance(value, list):
        for member in value:
            _reject_lone_surrogates(member)


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, int):
        # An integer literal is still a binary64 value in JCS: 9007199254740993 canonicalizes to
        # 9007199254740992 because that is the value the literal denotes. An integer too large to
        # convert at all denotes no binary64 value, which is §01 §3.1's `jcs-non-finite-number` —
        # the code that exists for exactly this entry point, where an already-parsed in-memory value
        # arrives rather than text (`parse` reaches the same condition as `jcs-malformed-json`).
        try:
            number = float(value)
        except OverflowError as e:
            raise CanonicalizationError(
                "jcs-non-finite-number", f"{value} has no binary64 representation"
            ) from e
        _write_number(number, out)
    elif isinstance(value, float):
        _write_number(value, out)
    elif isinstance(value, list):
        out.append("[")
        for index, member in enumerate(value):
            if index:
                out.append(",")
            _write(member, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        # UTF-16 code units, compared as unsigned 16-bit integers: UTF-16-BE bytes sort identically.
        for index, name in enumerate(sorted(value, key=lambda k: str(k).encode("utf-16-be"))):
            if index:
                out.append(",")
            out.append(_string(str(name)))
            out.append(":")
            _write(value[name], out)
        out.append("}")
    else:
        raise CanonicalizationError(
            "jcs-malformed-json", f"{type(value).__name__} is not a JSON value"
        )


def _string(value: str) -> str:
    out = ['"']
    for character in value:
        escape = _ESCAPES.get(character)
        if escape is not None:
            out.append(escape)
        elif ord(character) < 0x20:
            out.append(f"\\u{ord(character):04x}")
        else:
            # U+007F, U+2028 and U+2029 are emitted literally; nothing non-ASCII is \u-escaped.
            out.append(character)
    out.append('"')
    return "".join(out)


def _write_number(value: float, out: list[str]) -> None:
    if not math.isfinite(value):
        raise CanonicalizationError("jcs-non-finite-number", repr(value))
    if value == 0.0:
        out.append("0")  # -0 serializes as 0
        return
    if value < 0:
        out.append("-")
        value = -value
    digits, exponent = _shortest(value)
    k = len(digits)
    n = exponent + k
    if k <= n <= 21:
        out.append(digits + "0" * (n - k))
    elif 0 < n <= 21:
        out.append(digits[:n] + "." + digits[n:])
    elif -6 < n <= 0:
        out.append("0." + "0" * (-n) + digits)
    else:
        power = n - 1
        sign = "+" if power >= 0 else "-"
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        out.append(f"{mantissa}e{sign}{abs(power)}")


def _shortest(value: float) -> tuple[str, int]:
    """Shortest round-tripping digits ``s`` and ``e`` such that ``value == int(s) * 10**e``."""
    match = _REPR.match(repr(value))
    if match is None:  # pragma: no cover - repr of a finite positive float always matches
        raise CanonicalizationError("jcs-non-finite-number", repr(value))
    integer, fraction, exponent = match.group(1), match.group(2) or "", match.group(3) or "0"
    digits = (integer + fraction).lstrip("0") or "0"
    place = int(exponent) - len(fraction)
    stripped = digits.rstrip("0")
    place += len(digits) - len(stripped)
    return stripped or "0", place

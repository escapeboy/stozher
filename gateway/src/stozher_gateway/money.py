"""Exact comparison of monetary values — `spec/01 §2.5`, `spec/03 §4.3`.

The Python half of `stozher_core::decimal`. Both exist because both implementations compared
monetary decimal strings by parsing them back into a float — Rust with `s.parse::<f64>()`, Python
with `float(s)` — which reintroduces the representation §01 §2.5 removed, at the one place it decides
whether authority narrows.

Two failure modes, both real:

* **Precision.** `9007199254740993` and `9007199254740992` are one apart and the same binary64, so a
  child budget one unit over its parent's compared equal and the grant was accepted.
* **Divergence.** The two parsers disagree about what a number is. `float(" 25 ")` is 25.0 and
  `" 25 ".parse::<f64>()` is an error; `float("infinity")` is `inf`. So the same mandate was valid
  through one implementation and refused by the other — the class of defect the `parity` vectors
  exist to catch, in a place no vector reached.

The grammar is deliberately narrow — `digits [ "." digits ]` and nothing else — because every form
omitted is one the two languages could read differently, and none of them is a way anybody writes an
amount of money. Validation happens before `Decimal` sees the string: `Decimal` itself accepts
exponents, signs and surrounding whitespace, so handing it the raw value would keep exactly the
disagreement this module removes.
"""

from __future__ import annotations

import re
from decimal import Decimal

__all__ = ["MAX_LEN", "MoneyFormatError", "add", "at_most", "compare", "parse"]

#: The longest monetary string this implementation will compare. Bounded for the reason
#: `counts.by-action` is: an unbounded string is unbounded work for every consumer that compares it.
MAX_LEN = 32

_DECIMAL = re.compile(r"\A[0-9]+(\.[0-9]+)?\Z")


class MoneyFormatError(ValueError):
    """A value that is not a decimal string per §01 §2.5."""


def parse(value: object) -> Decimal:
    """Validate and convert one monetary value.

    Raises:
        MoneyFormatError: if `value` is not a string of the form `digits [ "." digits ]`, or is
            longer than `MAX_LEN`.
    """
    if not isinstance(value, str):
        raise MoneyFormatError(f"a monetary value must be a string, not {type(value).__name__}")
    if not value or len(value) > MAX_LEN:
        raise MoneyFormatError(f"a monetary value must be 1 to {MAX_LEN} characters")
    if _DECIMAL.match(value) is None:
        # `\A...\Z` rather than `^...$`: `$` also matches before a trailing newline, so "25\n" would
        # have passed — which is precisely the kind of near-miss that makes two implementations
        # disagree about one string.
        raise MoneyFormatError(
            f"{value!r} is not a decimal string: the form is digits, optionally a point and more "
            "digits — no sign, no exponent, no whitespace"
        )
    return Decimal(value)


def compare(left: object, right: object) -> int:
    """-1, 0 or 1, comparing two monetary values exactly.

    `"25"`, `"25.0"` and `"025.00"` are one amount written several ways and compare equal; scale
    carries no meaning.

    Raises:
        MoneyFormatError: if either value is not a decimal string.
    """
    a, b = parse(left), parse(right)
    if a == b:
        return 0
    return -1 if a < b else 1


def at_most(left: object, right: object) -> bool:
    """Whether `left` is at most `right`.

    Raises:
        MoneyFormatError: if either value is not a decimal string.
    """
    return compare(left, right) <= 0


def add(left: object, right: object) -> str:
    """Add two monetary values exactly, keeping the wider of the two scales.

    The Python half of `stozher_core::decimal::add`. A running total is what a budget is compared
    against, so doing it in binary64 would make the total drift from the records it was folded from —
    and `0.1 + 0.2` would not be `0.3`.

    Raises:
        MoneyFormatError: if either value is not a decimal string, or if the sum would exceed
            `MAX_LEN`. A total that outgrew the type would otherwise be truncated, and a spend figure
            that silently got smaller is the one direction a budget must never be wrong in.
    """
    a, b = parse(left), parse(right)
    scale = max(-a.as_tuple().exponent, -b.as_tuple().exponent, 0)  # type: ignore[operator]
    total = a + b
    rendered = f"{total:.{scale}f}" if scale else str(total)
    if len(rendered) > MAX_LEN:
        raise MoneyFormatError(f"the sum of {left!r} and {right!r} exceeds {MAX_LEN} characters")
    return rendered

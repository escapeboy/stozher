"""§01 §2.3's form is 24 **bytes** of ASCII, and the gateway was counting characters.

External security review, 2026-08-04, Finding 3 (DEF-13). Python's `\\d` matches any Unicode decimal
digit, and `datetime.strptime` and `int()` accept them too — so **750 distinct non-ASCII code
points** passed as a digit in the year position of a function whose own docstring promised "§01
§2.3's fixed 24-byte form". The kernel's `envelope::is_timestamp` and `clock::parse_timestamp` both
begin with `if b.len() != 24` over bytes and use `is_ascii_digit`, and refuse every one of them.

Over a 3,573-candidate adversarial corpus the reviewer measured **51 accepted by the gateway and
refused by the kernel, and 0 in the other direction**.

# Why the direction is the finding

`enforce.py` states the pipeline order: resolve → normalize → classify → prohibited? → mandate →
gate → forward → emit. **`forward` happens before `emit`.** The gateway decides whether the effect
occurs; the kernel decides whether it is recorded. A divergence in which the gateway is the more
permissive one therefore produces a real-world effect whose envelope the kernel then refuses: the
action happens and the audit record does not, which is the one outcome this system exists to
prevent.

# And six of them never expire

Both implementations' gate steps (8) and (9) compare timestamps as strings — correct for a
fixed-width ASCII form, and both files say so and warn that a value which is not one makes step (9)
vacuous. Six accepted candidates sort *above every representable real timestamp*, because their
first code point is above `'9'`. An approval carrying one has a `not-after` that no comparison can
ever place in the past.
"""

from __future__ import annotations

import pytest

from stozher_gateway.envelope import is_timestamp

#: Real, and the control: without this the test could pass by refusing everything.
VALID = "2026-07-26T09:15:01.300Z"

#: One per script the reviewer found, plus the two that also sort above every real timestamp.
CONFUSABLE = [
    "２026-07-26T09:15:01.300Z",  # U+FF12 FULLWIDTH DIGIT TWO
    "٢026-07-26T09:15:01.300Z",  # U+0662 ARABIC-INDIC DIGIT TWO
    "๒026-07-26T09:15:01.300Z",  # U+0E52 THAI DIGIT TWO
    "\U0001d7da026-07-26T09:15:01.300Z",  # U+1D7DA MATHEMATICAL DOUBLE-STRUCK TWO
    "००००-07-26T09:15:01.300Z",  # DEVANAGARI ZERO throughout the year
]


def test_the_valid_form_is_still_accepted() -> None:
    """The control. A validator that refuses everything passes every test below this one."""
    assert is_timestamp(VALID)


@pytest.mark.parametrize("value", CONFUSABLE)
def test_a_non_ascii_digit_is_not_a_timestamp(value: str) -> None:
    """What the kernel already does, and what the docstring already claimed."""
    assert len(value) == 24, "the fixture must be 24 *characters*, which is the whole trap"
    assert len(value.encode("utf-8")) != 24, "this fixture is not testing the byte/char difference"
    assert not is_timestamp(value), (
        "the gateway accepts a timestamp the kernel refuses. `forward` runs before `emit`, so this "
        "direction means the effect happens and its envelope is refused: the action occurs and the "
        "audit record does not."
    )


def test_a_confusable_year_no_longer_sorts_above_every_real_instant() -> None:
    """The consequence that makes this more than a validation nicety.

    Steps (8) and (9) compare timestamps as strings. `'２026-…' > '9999-12-31T23:59:59.999Z'` is
    `True` in Python, so an approval whose `not-after` carried one could not expire — and the code
    that does the comparing is correct to do it this way *provided* the value is the 24-byte ASCII
    form, which is exactly the guarantee this function is supposed to give it.
    """
    never_expires = "２026-07-26T09:15:01.300Z"
    assert never_expires > "9999-12-31T23:59:59.999Z", "the premise of this test has changed"
    assert not is_timestamp(never_expires), (
        "a value that sorts above every representable instant passed as a timestamp; step (9)'s "
        "expiry check is vacuous for it"
    )

"""Timestamps and durations in the one format `stozher/0.1` accepts (§01 §2.3, §2.4).

Timestamps are compared as strings in indexes and in vectors, so there is exactly one spelling:
RFC 3339, UTC, exactly three fractional digits, literal `Z`. Durations are `P[nD][T[nH][nM][nS]]`;
months and years are not representable because their length is ambiguous and retention windows are
legal commitments.
"""

from __future__ import annotations

import datetime as dt
import re

__all__ = [
    "CLOCK_ADVANCE_ACKNOWLEDGEMENT",
    "AdvancedClock",
    "Clock",
    "FixedClock",
    "from_config",
    "now",
    "parse_duration",
    "shift",
]

#: The sentence a deployment writes in its own configuration to run its clock ahead of the host.
#: Byte-identical to `stozher_kernel::clock::CLOCK_ADVANCE_ACKNOWLEDGEMENT`, because the two
#: components are one deployment and an advance one of them has not been told about is worse than
#: no advance at all.
CLOCK_ADVANCE_ACKNOWLEDGEMENT = (
    "records emitted by this deployment are not evidence of when anything happened"
)

_DURATION = re.compile(
    r"\AP(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?\Z"
)


def now() -> str:
    """The current instant, in the only accepted spelling."""
    return _format(dt.datetime.now(dt.UTC))


def shift(timestamp: str, seconds: float) -> str:
    """`timestamp` moved by `seconds`, in the same spelling."""
    moment = dt.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.UTC
    )
    return _format(moment + dt.timedelta(seconds=seconds))


def parse_duration(duration: str) -> float:
    """Seconds in an ISO 8601 duration restricted to `P[nD][T[nH][nM][nS]]`."""
    match = _DURATION.match(duration)
    if match is None:
        raise ValueError(f"encoding-bad-duration: {duration}")
    parts = {name: int(value or 0) for name, value in match.groupdict().items()}
    return parts["days"] * 86400 + parts["hours"] * 3600 + parts["minutes"] * 60 + parts["seconds"]


def _format(moment: dt.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class Clock:
    """The wall clock. Injected so tests can hold time still."""

    def now(self) -> str:
        return now()


def from_config(config: object) -> Clock:
    """The deployment's clock: the host's, unless its configuration declares an advance.

    Takes the config duck-typed rather than imported, because `config` imports this module.
    """
    section = getattr(config, "clock", None)
    advance = getattr(section, "advance", None)
    return AdvancedClock(advance) if advance else Clock()


class AdvancedClock(Clock):
    """The host's clock, moved forward by a fixed duration (ADR-0023).

    ADR-0023 gave the *kernel* an advance so a reviewer could watch expiry and decay happen, and
    reasoned about the offline CLI as the residual. It did not reason about the gateway, which is
    the component that enforces — and the omission disabled the central control. The gateway stamps
    an action-request's `not-after` from its own clock; against a kernel running ahead, every gated
    call arrived already expired and was refused `gate-request-expired` instead of parking. Three
    independent evaluations hit it, and one of them could not approve anything for the rest of its
    run. So the advance is a property of the deployment, and both of its components read it.

    Forward only, and for the same reason as the kernel: `advance` is an ISO 8601 duration, which
    has no sign, so "move the clock back" is not a sentence this configuration can say.
    """

    def __init__(self, advance: str) -> None:
        self.seconds = parse_duration(advance)
        if self.seconds <= 0:
            raise ValueError(f"clock-advance must be a positive duration: {advance}")
        self.advance = advance

    def now(self) -> str:
        return shift(now(), self.seconds)


class FixedClock(Clock):
    """A clock a test moves by hand."""

    def __init__(self, at: str) -> None:
        self.at = at

    def now(self) -> str:
        return self.at

    def advance(self, seconds: float) -> None:
        self.at = shift(self.at, seconds)

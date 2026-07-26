"""Timestamps and durations in the one format `stozher/0.1` accepts (§01 §2.3, §2.4).

Timestamps are compared as strings in indexes and in vectors, so there is exactly one spelling:
RFC 3339, UTC, exactly three fractional digits, literal `Z`. Durations are `P[nD][T[nH][nM][nS]]`;
months and years are not representable because their length is ambiguous and retention windows are
legal commitments.
"""

from __future__ import annotations

import datetime as dt
import re

__all__ = ["Clock", "FixedClock", "now", "parse_duration", "shift"]

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


class FixedClock(Clock):
    """A clock a test moves by hand."""

    def __init__(self, at: str) -> None:
        self.at = at

    def now(self) -> str:
        return self.at

    def advance(self, seconds: float) -> None:
        self.at = shift(self.at, seconds)

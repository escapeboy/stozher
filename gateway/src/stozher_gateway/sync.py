"""What a component may do when the kernel has answered "no" — `spec/05 §7.1`.

A submission has three outcomes and not two. `accepted` and `unreachable` were the only ones the
specification modelled, and it treated the distance between a local chain and a synced one as
*latency* (§04 §3). A **refusal** is the third state, and it is not a slower second one: the
`offline` map governs a kernel that cannot answer, never one that has answered.

The rule this module holds is the whole of §7.1 clause 4, and its two halves come from opposite
failure modes:

* **the reason decides whether grace exists at all.** Under a `mandate-*` reason or
  `policy-not-published`, no class has any — authority the organization cannot resolve is not
  authority (ADR-0001), and a `read` performed without authority is still an effect;
* **the class decides who may use it when it does.** `read` and `benign` may run out the
  `policy.wedge-grace` window, loudly; `consequential` and `prohibited` stop at once, because grace
  over `consequential` is exactly the window an auditor asks "what else was still permitted" about.

Stopping unilaterally on any refusal would be a denial-of-service weapon — one malformed envelope
halts a fleet — and unbounded grace is an accountability hole. `spec/vectors/sync-outcome.json`
pins both ends, including the vector that fails an implementation which simply refuses everything.
"""

from __future__ import annotations

from typing import NamedTuple

__all__ = [
    "ACCEPTED",
    "REFUSED",
    "UNREACHABLE",
    "WEDGE_GRACE_DEFAULT_SECONDS",
    "SyncDecision",
    "decide",
    "denies_every_class",
]

#: The kernel appended it.
ACCEPTED = "accepted"
#: No answer: transport failure, timeout, no route. §05 §7's `offline` map governs.
UNREACHABLE = "unreachable"
#: The kernel answered with a rejection (§04 §7). §05 §7.1 governs.
REFUSED = "refused"

#: `policy.wedge-grace`, default `PT5M` (§05 §1).
WEDGE_GRACE_DEFAULT_SECONDS = 300.0

#: Reason codes outside the `mandate-*` family that nonetheless leave no grace for any class.
_NO_GRACE_REASONS = frozenset({"policy-not-published"})

#: The classes no grace ever reaches, whatever the reason.
_NO_GRACE_CLASSES = frozenset({"consequential", "prohibited"})


class SyncDecision(NamedTuple):
    """`serve` or `refuse`, the code a refusal carries verbatim, and whether it is a finding."""

    action: str
    reason_code: str | None
    finding: bool


def denies_every_class(reason_code: str) -> bool:
    """Whether this refusal reason leaves no grace for any class (§05 §7.1 clause 4).

    The whole `mandate-*` family, not one code: what the kernel refused was the authority, and a
    component acting under authority its organization will not resolve is acting under none.
    """
    return reason_code.startswith("mandate-") or reason_code in _NO_GRACE_REASONS


def decide(
    *,
    outcome: str,
    reason_code: str | None,
    classification: str,
    elapsed_seconds: float,
    offline: str,
    wedge_grace_seconds: float,
) -> SyncDecision:
    """§05 §7.1 clauses 1, 4 and 5, as a pure function of the state.

    `offline` is the policy's `offline` behaviour **for this class** and is consulted only for an
    `unreachable` kernel. `elapsed_seconds` is measured from the *first* refusal on the stream, so a
    later refusal cannot restart the window.
    """
    if outcome == ACCEPTED:
        return SyncDecision("serve", None, False)
    if outcome == UNREACHABLE:
        if offline == "allow":
            return SyncDecision("serve", None, False)
        return SyncDecision("refuse", "policy-stale-offline", False)
    if outcome != REFUSED:  # pragma: no cover - the vocabulary is closed
        raise ValueError(f"{outcome!r} is not a submission outcome")
    assert reason_code is not None, "a refusal carries the kernel's reason code"
    if denies_every_class(reason_code):
        return SyncDecision("refuse", reason_code, False)
    if classification in _NO_GRACE_CLASSES:
        return SyncDecision("refuse", reason_code, False)
    if elapsed_seconds < wedge_grace_seconds:
        return SyncDecision("serve", None, True)
    return SyncDecision("refuse", reason_code, False)

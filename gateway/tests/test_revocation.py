"""Revocation on the hot path — the gap ADR-0007 §1 left open, and the proof it is closed.

The claim being tested is narrow and it is the whole point: **a revoked mandate stops the call
before the downstream tool is invoked.** Not "the envelope is refused afterwards" — the kernel
already did that at ingest, and doing it there means the effect had already reached the world.
Every test below that matters asserts `harness.forwarded == []`, because the list of tools the
gateway actually called is the only witness that prevention happened rather than detection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.enforce import Enforcer
from stozher_gateway.kernel_client import KernelClient, KernelResponse, KernelUnreachableError
from stozher_gateway.policy import Policy
from stozher_gateway.refusal import RefusalError
from stozher_gateway.revocation import RevocationFeed
from stozher_gateway.signing import SigningKey
from stozher_gateway.store import GatewayStore

from .support import baseline_policy
from .test_enforcement import POLICY_KEY, ROOT, Harness

STRANGER = SigningKey(bytes.fromhex("ee" * 32), "agent:nobody")


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def revocation(signer: SigningKey, target: str, at: str) -> dict[str, Any]:
    """A revocation object as it appears in the feed (§03 §7): the envelope *is* the object."""
    return signer.sign(
        {
            "v": "stozher/0.1",
            "kind": "revocation",
            "revokes": target,
            "revoked-at": at,
            "reason": "laptop lost",
        }
    )


def with_feed(
    harness: Harness, feed: Any | None
) -> None:
    """Rebuild the harness's enforcer around a revocation feed."""
    harness.enforcer = Enforcer(
        harness.config,
        harness.store,
        harness.classifier,
        harness.emitter,
        lambda: (harness.policy, True),
        None,
        feed,
    )


def static_feed(revocations: list[dict[str, Any]], current: bool = True) -> Any:
    def resolve(_policy: Policy) -> tuple[list[dict[str, Any]], bool]:
        return revocations, current

    return resolve


# -- prevention, not detection ------------------------------------------------------------------


def test_a_revoked_mandate_refuses_the_call_before_the_downstream_is_invoked(
    harness: Harness,
) -> None:
    """The one that matters. The tool is never called, and the refusal is recorded."""
    revoked = revocation(ROOT, harness.session.mandate_ref, clock_module.shift(clock_module.now(), -1))
    with_feed(harness, static_feed([revoked]))

    with pytest.raises(RefusalError) as refused:
        harness.call("get_file_contents", path="README.md")

    document = refused.value.document
    assert document["result"] == "blocked"
    assert document["reason-code"] == "mandate-revoked"
    # The witness: the downstream server was never reached. A refusal after the fact would leave
    # this list holding the tool name.
    assert harness.forwarded == [], "the downstream tool must not have been invoked"

    # And the refusal is audited: a blocked effect, chained locally before anything is pushed.
    blocked = [
        envelope
        for envelope in harness.chain()
        if envelope.get("execution", {}).get("outcome") == "blocked"
    ]
    assert len(blocked) == 1, harness.chain()
    assert blocked[0]["execution"]["action"] == "github.get_file_contents"
    assert blocked[0]["mandate-ref"] == harness.session.mandate_ref


def test_the_same_call_proceeds_when_nothing_is_revoked(harness: Harness) -> None:
    """The counterfactual. Without it, the test above would pass on a gateway that refuses
    everything, and would prove nothing about revocation."""
    with_feed(harness, static_feed([]))
    assert "upstream result" in harness.call("get_file_contents", path="README.md")
    assert harness.forwarded == ["get_file_contents"]


def test_a_consequential_call_under_a_revoked_mandate_never_even_parks(harness: Harness) -> None:
    """Revocation is checked before the gate, so a revoked mandate cannot queue work for a human."""
    revoked = revocation(ROOT, harness.session.mandate_ref, clock_module.shift(clock_module.now(), -1))
    with_feed(harness, static_feed([revoked]))

    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "mandate-revoked"
    assert harness.forwarded == []
    assert harness.store.pending() == [], "nothing was parked for a human to approve"


def test_a_revocation_that_takes_effect_later_does_not_block_now(harness: Harness) -> None:
    """§03 §7: a mandate revoked at T is invalid for effects emitted at or after T, and not before.
    Rewriting what was permitted at the time is not a feature."""
    later = revocation(ROOT, harness.session.mandate_ref, clock_module.shift(clock_module.now(), 600))
    with_feed(harness, static_feed([later]))
    assert "upstream result" in harness.call("get_file_contents", path="README.md")
    assert harness.forwarded == ["get_file_contents"]


def test_an_unsigned_revocation_is_dropped_rather_than_enforced(harness: Harness) -> None:
    """A forged revocation is a denial-of-service on someone else's authority. It must not verify.

    Dropping is the safe direction here and only here: a dropped revocation costs prevention and
    the kernel still refuses the envelope at ingest, whereas an *accepted* forgery would let anyone
    who can reach the feed halt an organization's agents.
    """
    forged = revocation(ROOT, harness.session.mandate_ref, clock_module.shift(clock_module.now(), -1))
    forged["revoked-at"] = clock_module.now()  # tampered after signing
    with_feed(harness, static_feed([forged]))
    assert "upstream result" in harness.call("get_file_contents", path="README.md")


def test_a_feed_that_cannot_be_resolved_blocks_consequential_and_still_allows_reads(
    harness: Harness,
) -> None:
    """§05 §6–§7: unable to re-pull means offline for that class, never "proceed anyway"."""

    def broken(_policy: Policy) -> tuple[list[dict[str, Any]], bool]:
        raise KernelUnreachableError("the kernel is not there")

    with_feed(harness, broken)
    assert "upstream result" in harness.call("get_file_contents", path="README.md")
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "policy-stale-offline"
    assert harness.forwarded == ["get_file_contents"]


def test_an_enforcer_built_without_a_feed_is_the_s2_behaviour(harness: Harness) -> None:
    """Named rather than hidden: with no feed the gateway is back to detective-only revocation.

    `runtime.Gateway` always wires one; this asserts that the *default* is the old behaviour so
    that a future construction site which forgets is a visible regression, not a silent one.
    """
    revoked = revocation(ROOT, harness.session.mandate_ref, clock_module.shift(clock_module.now(), -1))
    with_feed(harness, None)
    assert "upstream result" in harness.call("get_file_contents", path="README.md")
    assert harness.forwarded == ["get_file_contents"]
    # The revocation exists; it simply was not consulted, which is precisely ADR-0007 §1.
    assert revoked["revokes"] == harness.session.mandate_ref


# -- the feed itself ---------------------------------------------------------------------------


class FakeKernel(KernelClient):
    """A kernel that answers the revocation feed, countably and controllably."""

    def __init__(self, documents: list[dict[str, Any]], epoch: str = '"e1"') -> None:
        super().__init__("http://127.0.0.1:9", None, 0.1)
        self.documents = documents
        self.epoch = epoch
        self.calls: list[str | None] = []
        self.reachable = True

    def revocations(self, if_none_match: str | None = None) -> KernelResponse:
        self.calls.append(if_none_match)
        if not self.reachable:
            raise KernelUnreachableError("GET /v1/revocations: refused")
        if if_none_match == self.epoch:
            return KernelResponse(304, {}, self.epoch)
        return KernelResponse(
            200,
            {"revocation-epoch": self.epoch, "count": len(self.documents), "revocations": self.documents},
            self.epoch,
        )


def policy_document(revoke_cached: bool, version: str = "2026.07.1") -> Policy:
    document = baseline_policy(version, clock_module.now(), ROOT.subject)
    document["revoke-cached"] = revoke_cached
    return Policy.verified(POLICY_KEY.sign(document), POLICY_KEY.id)


def test_the_feed_polls_conditionally_and_serves_from_memory_in_between(tmp_path: Path) -> None:
    """The hot path performs no I/O between polls, and a poll that changes nothing is a 304."""
    revoked = revocation(ROOT, "a" * 64, clock_module.now())
    kernel = FakeKernel([revoked])
    feed = RevocationFeed(kernel, GatewayStore(tmp_path / "gw.db"), refresh_seconds=3600)
    policy = policy_document(revoke_cached=False)

    first, current = feed.current(policy)
    assert current is True
    assert [item["revokes"] for item in first] == ["a" * 64]
    assert kernel.calls == [None], "the first pull has no epoch to be conditional on"

    for _ in range(5):
        feed.current(policy)
    assert kernel.calls == [None], "inside the interval the feed answers from memory"

    # Outside the interval the poll carries the epoch, so the kernel can answer 304.
    stale = RevocationFeed(kernel, GatewayStore(tmp_path / "gw.db"), refresh_seconds=0)
    stale.current(policy)
    stale.current(policy)
    assert kernel.calls[-1] == '"e1"'


def test_the_cached_set_is_enforced_while_the_kernel_is_unreachable(tmp_path: Path) -> None:
    """Maxim 5: offline means "keep enforcing the last verified copy", never "enforce nothing"."""
    revoked = revocation(ROOT, "b" * 64, clock_module.now())
    kernel = FakeKernel([revoked])
    database = tmp_path / "gw.db"
    warm = RevocationFeed(kernel, GatewayStore(database), refresh_seconds=0)
    policy = policy_document(revoke_cached=False)
    warm.current(policy)

    # A fresh process, a dead kernel: the set survives because it was cached persistently.
    kernel.reachable = False
    cold = RevocationFeed(kernel, GatewayStore(database), refresh_seconds=0)
    held, current = cold.current(policy)
    assert [item["revokes"] for item in held] == ["b" * 64]
    assert current is True, "a failed *interval* poll is not a revoke-cached failure"


def test_revoke_cached_forces_a_repull_inside_the_interval(tmp_path: Path) -> None:
    """§05 §6: `revoke-cached` re-pulls regardless of interval, and exactly once per version."""
    kernel = FakeKernel([])
    feed = RevocationFeed(kernel, GatewayStore(tmp_path / "gw.db"), refresh_seconds=86_400)
    tightened = policy_document(revoke_cached=True)

    feed.current(tightened)
    assert len(kernel.calls) == 1
    feed.current(tightened)
    feed.current(tightened)
    assert len(kernel.calls) == 1, "the obligation is discharged, not repeated on every call"

    # A newer version that still tightens is a new obligation.
    feed.current(policy_document(revoke_cached=True, version="2026.07.2"))
    assert len(kernel.calls) == 2


def test_revoke_cached_that_cannot_repull_reports_the_feed_as_not_current(tmp_path: Path) -> None:
    """"A component that cannot re-pull MUST treat consequential as offline-blocked" (§05 §6)."""
    kernel = FakeKernel([])
    feed = RevocationFeed(kernel, GatewayStore(tmp_path / "gw.db"), refresh_seconds=86_400)
    kernel.reachable = False

    held, current = feed.current(policy_document(revoke_cached=True))
    assert held == []
    assert current is False


def test_the_feed_drops_a_revocation_it_cannot_verify(tmp_path: Path) -> None:
    """The gateway checks the signature itself rather than trusting the kernel's word for it."""
    good = revocation(ROOT, "c" * 64, clock_module.now())
    tampered = revocation(STRANGER, "d" * 64, clock_module.now())
    tampered["revokes"] = "e" * 64
    kernel = FakeKernel([good, tampered, {"revokes": "f" * 64}])
    feed = RevocationFeed(kernel, GatewayStore(tmp_path / "gw.db"), refresh_seconds=0)

    held, _ = feed.current(policy_document(revoke_cached=False))
    assert [item["revokes"] for item in held] == ["c" * 64]

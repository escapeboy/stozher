"""The revocation feed, pulled and evaluated on the hot path — `spec/03-mandate.md` §7.

ADR-0007 §1 recorded this as the one **open security gap** of S2: the gateway called
`verify_mandate_chain` with an empty revocation set, so a revoked mandate was caught by the kernel
at ingest — that is, *after the effect had already been applied to the world*. Revocation was
detective, not preventive, on the exact path that governs foreign agents.

This module is the preventive half. It is deliberately shaped like `PolicyProvider`
(`spec/05 §2`): components pull, the kernel does not push; the last verified set is cached
persistently and enforced while offline; and a set the gateway cannot verify is not enforced as if
it were empty — an unverifiable revocation is dropped and logged, which is safe because dropping a
*revocation* can only ever cause a refusal to be missed, never an escalation, and the kernel still
refuses the envelope at ingest as the backstop it always was.

Two properties make it cheap enough to sit in front of every call:

* the set is pulled on an interval and answered from memory in between, so the hot path performs no
  I/O (§10 §2 requires the hot path to be O(ms) and never block on the kernel);
* the poll itself is conditional on the feed's epoch, so a poll that changes nothing costs one
  round trip and reads no documents.

`revoke-cached` (§05 §6) is honoured here as well as in the policy provider: when the policy in
force carries it, the feed MUST re-pull before the next `consequential` action, regardless of the
interval. If it cannot, it says so, and the caller treats the class as offline-blocked rather than
proceeding on a set that may be one revocation out of date.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from . import clock as clock_module
from .kernel_client import KernelClient, KernelUnreachableError
from .policy import Policy
from .signing import verify_signed_object
from .store import GatewayStore

__all__ = ["RevocationFeed"]

logger = logging.getLogger(__name__)


class RevocationFeed:
    """A verified, cached, pollable set of revocations."""

    def __init__(
        self,
        kernel: KernelClient,
        store: GatewayStore,
        refresh_seconds: int,
        clock: clock_module.Clock | None = None,
    ) -> None:
        self._kernel = kernel
        self._store = store
        self._refresh_seconds = refresh_seconds
        self._clock = clock or clock_module.Clock()
        self._lock = threading.Lock()
        self._loaded = False
        self._revocations: list[dict[str, Any]] = []
        self._epoch: str | None = None
        self._checked_at: str | None = None
        #: The policy version whose `revoke-cached` obligation has already been discharged.
        self._repulled_for: str | None = None

    def current(self, policy: Policy) -> tuple[list[dict[str, Any]], bool]:
        """The revocations to evaluate, and whether the feed is current enough to act on.

        `False` does not mean "use nothing" — the cached set is returned and MUST still be
        enforced (maxim 5). It means the caller may not treat a `consequential` action as if the
        gateway were online, which is what `spec/05 §6`–§7 require of a component that cannot
        re-pull.
        """
        with self._lock:
            if not self._loaded:
                self._load_cache()
            owed = self._owes_repull(policy)
            if owed or self._interval_elapsed():
                pulled = self._pull()
                if pulled and owed:
                    # The obligation is discharged by *reaching* the kernel, not by the answer
                    # changing: `304 Not Modified` is a re-pull that confirms the held set.
                    self._repulled_for = policy.version
                if not pulled and owed:
                    return list(self._revocations), False
            return list(self._revocations), True

    @property
    def epoch(self) -> str | None:
        """The epoch of the held set, for logging and for tests. `None` before the first pull."""
        return self._epoch

    # -- internals ---------------------------------------------------------------------------

    def _owes_repull(self, policy: Policy) -> bool:
        """§05 §6: a policy that tightens demands a re-pull before the next consequential action."""
        return policy.revoke_cached() and self._repulled_for != policy.version

    def _interval_elapsed(self) -> bool:
        if self._checked_at is None:
            return True
        return self._clock.now() >= clock_module.shift(self._checked_at, self._refresh_seconds)

    def _pull(self) -> bool:
        """Refresh from the kernel. Returns whether the kernel answered."""
        try:
            response = self._kernel.revocations(self._epoch)
        except KernelUnreachableError as e:
            # Degrading to the last verified set is the offline behaviour maxim 5 requires. It is
            # not a fallback to "no revocations": the cached set is enforced exactly as pulled.
            logger.warning("the revocation feed could not be pulled, enforcing the cached set: %s", e)
            return False
        self._checked_at = self._clock.now()
        if response.status == 304:
            return True
        if response.status != 200:
            logger.warning("the kernel did not serve the revocation feed: %s", response.reason_code)
            return False
        listed = response.body.get("revocations")
        if not isinstance(listed, list):
            logger.error("the revocation feed did not carry a list of revocations")
            return False
        verified = [item for item in listed if _is_verifiable(item)]
        self._revocations = verified
        self._epoch = response.etag
        self._store.cache_revocations(
            response.etag or "", verified, self._checked_at
        )
        return True

    def _load_cache(self) -> None:
        self._loaded = True
        cached = self._store.cached_revocations()
        if cached is None:
            return
        epoch, documents, _ = cached
        self._revocations = documents
        self._epoch = epoch or None


def _is_verifiable(document: Any) -> bool:
    """A revocation the gateway can check for itself, rather than one the kernel vouched for."""
    if not isinstance(document, dict):
        return False
    if verify_signed_object(document) is None:
        logger.error("dropping a revocation whose signature does not verify")
        return False
    if not isinstance(document.get("revokes"), str) or not isinstance(
        document.get("revoked-at"), str
    ):
        logger.error("dropping a revocation missing revokes or revoked-at")
        return False
    return True

"""Tier-A classification input: the manifests components have registered (§08, §10 §3).

`Classifier` has supported tier A since S2 — a manifest's own `actions[].class` is the first thing
its `classify` consults — and nothing ever loaded one, so every third-party tool fell through to the
shipped table, the org's seeded catalogue, or the shape heuristic. That is the tier the four-class
taxonomy is least confident about, and it is the one a component we did not write always landed in.

The feed is deliberately thinner than `RevocationFeed`. A revocation is a *withdrawal of authority*
and §05 §6 obliges a component that cannot re-pull one to stop treating itself as online; a manifest
is a declaration of what a component's actions are, and a stale one costs precision rather than
safety — the kernel still classifies independently at ingest, and policy still decides. So this
caches, refreshes on an interval, and on failure keeps what it has and says so in a log line rather
than degrading anything.

**A manifest is not authority.** Nothing here can widen what a caller may do: the class a manifest
declares is a *proposal* that policy may override (§05 §3), the gate rules are policy's, and the
kernel recomputes the class for the envelope it stores whatever the gateway sent.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from . import clock as clock_module
from .kernel_client import KernelClient, KernelUnreachableError

logger = logging.getLogger(__name__)

__all__ = ["ManifestFeed"]


class ManifestFeed:
    """A cached, pollable map of component name → manifest document."""

    def __init__(
        self,
        kernel: KernelClient,
        refresh_seconds: int,
        clock: clock_module.Clock | None = None,
    ) -> None:
        self._kernel = kernel
        self._refresh_seconds = refresh_seconds
        self._clock = clock or clock_module.Clock()
        self._lock = threading.Lock()
        self._manifests: dict[str, dict[str, Any]] = {}
        self._checked_at: str | None = None

    def current(self) -> dict[str, dict[str, Any]]:
        """The manifests to classify against, refreshed if the interval has elapsed."""
        with self._lock:
            if self._checked_at is None or self._interval_elapsed():
                self._pull()
            return dict(self._manifests)

    def _interval_elapsed(self) -> bool:
        if self._checked_at is None:
            return True
        return self._clock.now() >= clock_module.shift(self._checked_at, self._refresh_seconds)

    def _pull(self) -> None:
        try:
            response = self._kernel.manifests()
        except KernelUnreachableError as e:
            # Keep what we have. A component must go on enforcing while the kernel is unreachable
            # (maxim 5), and classification is not the thing that would become unsafe here.
            logger.warning("could not refresh manifests: %s", e)
            return
        if response.status != 200:
            logger.warning("the kernel answered %s for manifests", response.status)
            return
        body = response.body
        declared = body.get("manifests") if isinstance(body, dict) else None
        if not isinstance(declared, list):
            # A 200 whose body is not the shape this endpoint promises is an answer we could not
            # read, not an answer of "none". Replacing the cache here would silently demote every
            # governed component to the shape heuristic while every call kept succeeding — quieter
            # than a refusal, and worse.
            logger.warning("the kernel's manifest answer had no readable `manifests` list")
            return
        loaded: dict[str, dict[str, Any]] = {}
        for manifest in declared:
            if not isinstance(manifest, dict):
                continue
            name = manifest.get("name")
            if isinstance(name, str) and name:
                loaded[name] = manifest
        self._manifests = loaded
        self._checked_at = self._clock.now()

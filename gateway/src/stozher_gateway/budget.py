"""Pre-spend budget enforcement — `spec/03 §4.3`.

The emitter's half. §03 §4.3 says an exhausted budget "blocks like an expired mandate:
`outcome: "blocked"`, envelope still emitted", which puts the blocking here rather than in the
kernel: by the time an envelope reaches the kernel the spend has already happened, and all the kernel
can do is record that it did. Without this module a budget is *detection* — an over-budget action is
flagged after the fact — and `docs/product-completion-design.md` §1 names turning prevention into
detection as a product defect rather than a polish item.

**The caps come from the whole mandate chain.** A budget bounds "this mandate and everything
delegated beneath it", so a delegate's own generous cap means nothing when its grantor is exhausted.
The kernel returns the chain; this decides against all of it.

**A cap that cannot be evaluated is not headroom.** A limit this build cannot read — a figure that is
not a decimal string, a total that will not parse — is treated as no room. That is the rule
`stozher_kernel::budget` follows on the other side and for the same reason: a budget check that fails
open is not a budget check, and a typo in a mandate must not become an unlimited budget.

**A cap nobody stated is not a cap.** Budgets are opt-in per dimension, so a dimension no mandate
names is genuinely unbounded, and a mandate the kernel cannot resolve states nothing — it is the
mandate walk's job to refuse an unresolvable chain, and this check duplicating it would make budgets
reject calls for reasons that are not about budgets.

**Never read is decided against what the gateway holds.** When the chain has not been read even once,
the caller falls back to the mandate document the gateway is acting under — which it has locally. A
mandate that declares no budget proceeds; one that does is refused until the figures are readable,
because acting under a cap whose spend is unknown is how a cap silently stops existing. The residue
is stated rather than hidden: an *ancestor's* cap is invisible offline, which is the same residue
every offline decision in this component carries.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from . import clock as clock_module
from . import money
from .kernel_client import KernelClient, KernelUnreachableError

logger = logging.getLogger(__name__)

__all__ = ["BudgetFeed", "exceeded_dimensions"]


def exceeded_dimensions(chain: list[dict[str, Any]], adding: dict[str, str]) -> list[str]:
    """The dimensions on which `adding` has no room anywhere in the chain.

    Empty means there is room in every mandate. A dimension no cap names is unbounded and is not
    reported — the specification's budgets are opt-in per dimension, so silence there is a real
    "no limit" rather than a missing answer.
    """
    exceeded: list[str] = []
    for entry in chain:
        if not entry.get("resolved"):
            # A mandate the kernel cannot resolve states no cap, so it contributes none here.
            #
            # That is not a hole. Refusing on it would be this check doing the mandate walk's job:
            # an envelope citing an unresolvable chain is refused by `_require_mandate`, which runs
            # first, and duplicating it here would make the budget feature reject calls for reasons
            # that have nothing to do with budgets — which is how the first version of this broke
            # every deployment whose mandate the projection had not indexed.
            continue
        caps = entry.get("budget")
        if not isinstance(caps, dict):
            continue
        spent = entry.get("spent")
        spent = spent if isinstance(spent, dict) else {}
        for dimension, cap in caps.items():
            if dimension not in adding:
                continue
            held = spent.get(dimension, "0")
            try:
                total = money.add(str(held), adding[dimension])
                if not money.at_most(total, _as_decimal(cap)):
                    exceeded.append(dimension)
            except money.MoneyFormatError:
                # A cap or a running total this build cannot read. Refusing is the safe direction:
                # treating it as unbounded would turn a typo in a mandate into an unlimited budget.
                exceeded.append(dimension)
    # Stable and deduplicated, so a refusal names each dimension once whatever the chain's depth.
    return sorted(set(exceeded))


def _as_decimal(value: object) -> str:
    """A cap as a decimal string. Integers are decimals of scale zero."""
    if isinstance(value, bool):
        raise money.MoneyFormatError("a budget cap must be an integer or a decimal string")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    raise money.MoneyFormatError("a budget cap must be an integer or a decimal string")


class BudgetFeed:
    """The mandate chain's caps and accrued spend, cached and refreshed on an interval."""

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
        self._chains: dict[str, list[dict[str, Any]]] = {}
        self._checked: dict[str, str] = {}

    def chain(self, mandate_ref: str) -> list[dict[str, Any]] | None:
        """The cached chain for a mandate, refreshed if the interval has elapsed.

        `None` means the gateway has never successfully read it. That is deliberately distinct from
        an empty list: "no caps" and "we could not ask" must not look the same to the caller, because
        one of them is permission to proceed and the other is not.
        """
        with self._lock:
            if self._stale(mandate_ref):
                self._pull(mandate_ref)
            return self._chains.get(mandate_ref)

    def _stale(self, mandate_ref: str) -> bool:
        checked = self._checked.get(mandate_ref)
        if checked is None:
            return True
        return self._clock.now() >= clock_module.shift(checked, self._refresh_seconds)

    def _pull(self, mandate_ref: str) -> None:
        try:
            response = self._kernel.mandate_budget(mandate_ref)
        except KernelUnreachableError as e:
            logger.warning("could not refresh the budget for %s: %s", mandate_ref, e)
            return
        if response.status != 200:
            logger.warning(
                "the kernel answered %s for the budget of %s", response.status, mandate_ref
            )
            return
        body = response.body if isinstance(response.body, dict) else {}
        chain = body.get("chain")
        if not isinstance(chain, list):
            logger.warning("the kernel's budget answer had no readable chain")
            return
        self._chains[mandate_ref] = [entry for entry in chain if isinstance(entry, dict)]
        self._checked[mandate_ref] = self._clock.now()

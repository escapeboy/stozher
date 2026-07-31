"""The emitter's half of budget enforcement — `spec/03 §4.3`.

§03 §4.3 says an exhausted budget "blocks like an expired mandate: `outcome: "blocked"`, envelope
still emitted". That puts the blocking here: by the time an envelope reaches the kernel the spend has
already happened and all the kernel can do is flag it. A budget enforced only there is *detection*,
and `docs/product-completion-design.md` §1 names turning prevention into detection a product defect.

The negatives carry most of the weight. A check that blocked everything would satisfy "an exhausted
budget blocks" and be an outage, and the first version of this module was exactly that — it refused
whenever a mandate did not resolve, which is the mandate walk's job, and it stopped every deployment
whose projection had not indexed the mandate. So each test that shows a refusal is paired with one
that shows the same code proceeding.
"""

from __future__ import annotations

from typing import Any

from stozher_gateway.budget import exceeded_dimensions


def entry(mandate: str, budget: Any, spent: Any = None, resolved: bool = True) -> dict[str, Any]:
    return {
        "mandate": mandate,
        "resolved": resolved,
        "budget": budget,
        "spent": spent if spent is not None else {},
    }


def test_a_dimension_no_mandate_names_is_unbounded() -> None:
    # Budgets are opt-in per dimension, so silence is a real "no limit" rather than a missing answer.
    chain = [entry("m1", {"money-eur": "50.00"})]
    assert exceeded_dimensions(chain, {"requests": "1"}) == []


def test_a_cap_with_room_permits_and_the_boundary_is_at_most() -> None:
    chain = [entry("m1", {"requests": 10}, {"requests": "9"})]
    assert exceeded_dimensions(chain, {"requests": "1"}) == [], "9 + 1 is within a cap of 10"

    chain = [entry("m1", {"requests": 10}, {"requests": "10"})]
    assert exceeded_dimensions(chain, {"requests": "1"}) == ["requests"], "10 + 1 is not"


def test_an_ancestors_exhausted_cap_binds_a_delegate_with_room_of_its_own() -> None:
    """A budget bounds "this mandate and everything delegated beneath it" (§03 §4.3).

    Without walking the whole chain, delegation is a way to mint budget: a delegate hands itself a
    generous cap and the grantor's exhaustion never reaches it.
    """
    chain = [
        entry("child", {"requests": 1000}, {"requests": "1"}),
        entry("parent", {"requests": 10}, {"requests": "10"}),
    ]
    assert exceeded_dimensions(chain, {"requests": "1"}) == ["requests"]


def test_money_is_compared_where_binary64_would_not_notice() -> None:
    chain = [
        entry("m1", {"money-eur": "9007199254740992"}, {"money-eur": "9007199254740992"}),
    ]
    assert exceeded_dimensions(chain, {"money-eur": "1"}) == ["money-eur"]


def test_a_cap_this_build_cannot_read_is_not_headroom() -> None:
    # Fail closed. A typo in a mandate must not become an unlimited budget.
    for cap in ({"requests": "ten"}, {"requests": True}, {"requests": None}):
        assert exceeded_dimensions([entry("m1", cap)], {"requests": "1"}) == ["requests"], cap
    # And a running total that will not parse is the same answer.
    chain = [entry("m1", {"requests": 10}, {"requests": "not-a-number"})]
    assert exceeded_dimensions(chain, {"requests": "1"}) == ["requests"]


def test_an_unresolvable_mandate_states_no_cap_and_does_not_block() -> None:
    """The bug the first version of this module had, kept as a test.

    Refusing here would be the budget check doing the mandate walk's job — an envelope citing an
    unresolvable chain is already refused by `_require_mandate`, which runs first. Duplicating it
    made budgets reject calls for reasons that were not about budgets, and it stopped every
    deployment whose mandate the projection had not indexed under the id the gateway computed.
    """
    chain = [{"mandate": "m1", "resolved": False}]
    assert exceeded_dimensions(chain, {"requests": "1"}) == []


def test_a_refusal_names_each_dimension_once_however_deep_the_chain() -> None:
    chain = [
        entry("child", {"requests": 1}, {"requests": "5"}),
        entry("parent", {"requests": 1}, {"requests": "5"}),
        entry("root", {"requests": 1}, {"requests": "5"}),
    ]
    assert exceeded_dimensions(chain, {"requests": "1"}) == ["requests"]


def test_an_empty_chain_permits_rather_than_refusing() -> None:
    # A deployment with no budgets anywhere must be unaffected by this feature existing. It is most
    # of them, and the alternative is a check whose cost is paid by everybody who never asked for it.
    assert exceeded_dimensions([], {"requests": "1"}) == []

"""A signature that changes nothing must say so. DEF-15.

Found independently by the clinical and SRE design partners on 2026-08-04. An approver signs a
catalog seed classifying a tool — a second, separate signature that §10 §4.3 deliberately asks for —
and `Policy.classify` takes the **stronger** of the seeded class and `default-unknown`, which is
`consequential` in the shipped profile. So a seeded `read` changes nothing.

**The rule is right and is not what this test is about.** Its docstring argues it well: a catalog
that quietly downgraded an action would produce envelopes the kernel refuses
`policy-component-override-attempt`, which is an effect applied in the world and missing from the
audit. Taking the stronger class makes the two evaluations agree by construction.

What was wrong is that nothing said so. One partner described the signature they had just given as
"a silent no-op" and had to read `policy.py` to find out why. An approver whose model of the system
is wrong in this direction will keep signing, which is the expensive kind of wrong.
"""

from __future__ import annotations

import logging

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.policy import Policy

from .test_enforcement import POLICY_KEY, ROOT, baseline_policy


def _policy(default_unknown: str) -> Policy:
    document = baseline_policy("2026.07.9", clock_module.now(), ROOT.subject)
    document["classification"]["default-unknown"] = default_unknown
    return Policy.verified(POLICY_KEY.sign(document), POLICY_KEY.id)


def test_a_seeded_class_weaker_than_the_default_is_announced_not_swallowed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The finding. The class is still the default — and the approver is now told why."""
    policy = _policy("consequential")
    with caplog.at_level(logging.WARNING, logger="stozher_gateway.policy"):
        result = policy.classify(
            "agent:claude-code", "github.echo_note", "mcp:github", catalog_class="read"
        )

    assert result == "consequential", "the stronger-of-the-two rule changed; that is a separate call"
    assert any("had no effect" in record.getMessage() for record in caplog.records), (
        "a signed catalog class was discarded and nothing said so — the approver's signature was a "
        "silent no-op, which is how two design partners lost an afternoon"
    )
    message = " ".join(record.getMessage() for record in caplog.records)
    assert "github.echo_note" in message, "the message does not name the action it is about"
    assert "by-action" in message, "the message does not say what would make the class binding"


def test_a_seeded_class_stronger_than_the_default_still_wins_and_says_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The control, and it is the one that stops this becoming noise.

    When the seed *does* take effect there is nothing to warn about, and a warning on every
    classification would be read as background and then not read at all.
    """
    policy = _policy("read")
    with caplog.at_level(logging.WARNING, logger="stozher_gateway.policy"):
        result = policy.classify(
            "agent:claude-code", "github.unnamed_tool", "mcp:github", catalog_class="consequential"
        )

    assert result == "consequential", "the seeded class did not take effect"
    assert not [r for r in caplog.records if "had no effect" in r.getMessage()], (
        "a seed that did take effect was reported as having none"
    )


def test_a_seed_equal_to_the_default_is_not_reported_either() -> None:
    """Equal is not discarded — it is the same answer arriving twice, and warning about it would
    train the reader to ignore the warning that matters."""
    policy = _policy("consequential")
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[method-assign]
    logger = logging.getLogger("stozher_gateway.policy")
    logger.addHandler(handler)
    try:
        assert (
            policy.classify(
                "agent:claude-code", "github.echo_note", "mcp:github", catalog_class="consequential"
            )
            == "consequential"
        )
    finally:
        logger.removeHandler(handler)
    assert not [r for r in records if "had no effect" in r.getMessage()]

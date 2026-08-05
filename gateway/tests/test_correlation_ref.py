"""The matter dimension existed, was indexed, and nothing wrote it. DEF-21.

The legal design partner asked the question a firm asks first — *"what did the agent do on the Acme
matter?"* — and could not answer it from the stream. Their conclusion was that an envelope has no
matter/case dimension.

**It has one.** `spec/02` carries `correlation-ref`, *"stored and indexed, never interpreted"*, and
the kernel serves `GET /v1/envelopes?correlation-ref=` and `?correlation-prefix=` over it. What was
missing is the half nobody checks for: **the component that emits the envelopes never set it.** So
the dimension was real in the protocol, queryable in the kernel, and unreachable in practice — which
is indistinguishable from absent to the person asking, and they were right to report it as absent.

One gateway process serves one caller on one device, so the configuration grain fits the question: a
matter, a tenant, a case, an incident. Per-call would have to travel inside the tool's own arguments,
which contaminates what the approver reads and what `args-hash` commits to.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from .test_enforcement import ROOT, Harness, _park_and_decide


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_a_configured_correlation_ref_reaches_the_chain(harness: Harness) -> None:
    """The assertion the legal evaluation was owed: the question becomes answerable."""
    harness.config.gateway.correlation_ref = "matter:acme-2026-114"

    _park_and_decide(harness, "create_issue", {"title": "file the motion"}, approver=ROOT)
    harness.call("create_issue", title="file the motion")

    effects = [e for e in harness.chain() if e["kind"] == "effect"]
    assert effects, "the call produced no effect envelope; this test is asserting nothing"
    assert all(e.get("correlation-ref") == "matter:acme-2026-114" for e in effects), (
        "an effect reached the chain with no matter on it — `GET /v1/envelopes?correlation-ref=` "
        "exists and has nothing to find, which is why a firm concluded the dimension did not"
    )


def test_no_correlation_ref_configured_means_the_member_is_absent(harness: Harness) -> None:
    """The control. `correlation-ref` is MAY, and an envelope that carries an empty one is worse
    than one that carries none: it is a matter dimension with a value that means nothing."""
    assert harness.config.gateway.correlation_ref is None, "the default must stay absent"

    _park_and_decide(harness, "create_issue", {"title": "file the motion"}, approver=ROOT)
    harness.call("create_issue", title="file the motion")

    effects = [e for e in harness.chain() if e["kind"] == "effect"]
    assert effects
    assert all("correlation-ref" not in e for e in effects), (
        "an unconfigured gateway stamped a correlation-ref anyway"
    )

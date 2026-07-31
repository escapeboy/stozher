"""A declared-but-unreachable downstream is a record, not a shorter tool list.

`docs/product-completion-design.md` §3 (v0.3): "A declared-but-unreachable MCP server must be
visible to the operator and recorded, not silently absent from `tools/list`."

Before this, a downstream that was down produced exactly one observable: some tools were missing.
An agent cannot tell that from a server nobody configured, and the audit said nothing at all — so a
window in which a governed capability was simply absent left no trace to find afterwards.

`test_cli.py::test_config_check_names_a_downstream_it_cannot_reach` covers the operator-facing half.
This file covers the recorded half: the *shape* of the envelope, because a record that omitted the
`failed` outcome would be filed with the successful ones and never surface.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from stozher_gateway.canonical import sha256_hex
from stozher_gateway.runtime import Gateway


class _Emitter:
    """Records what would have been appended, instead of appending it."""

    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []

    def append(self, key: Any, stream: str, body: dict[str, Any]) -> None:
        self.bodies.append(body)


class _Policy:
    def __init__(self, decision: str) -> None:
        self.version = "2026.07.01"
        self._decision = decision

    def classify(self, subject: str, action: str, target: str, proposed: str) -> str:
        return proposed

    def decision_for(self, classification: str) -> SimpleNamespace:
        return SimpleNamespace(kind=self._decision)


def _runtime(decision: str) -> tuple[Gateway, _Emitter]:
    """An `Gateway` with the collaborators this one method uses, and nothing else.

    The constructor pulls a policy from a live kernel and opens a state database; neither is what is
    under test here, and building both would test the fixture rather than the record.
    """
    emitter = _Emitter()
    runtime = object.__new__(Gateway)
    runtime.config = SimpleNamespace(gateway=SimpleNamespace(component="gateway"))
    runtime._clock = SimpleNamespace(now=lambda: "2026-07-26T09:00:00.000Z")
    runtime.emitter = emitter
    runtime.policy_provider = SimpleNamespace(current=lambda: (_Policy(decision), None))
    return runtime, emitter


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        subject="agent:claude-code/test-mbp",
        key=SimpleNamespace(id="ed25519:" + "11" * 32),
        mandate_ref="sha256:" + "22" * 32,
        stream="gw:test-mbp:claude-code",
    )


def test_an_unreachable_downstream_is_recorded_as_a_failed_effect() -> None:
    runtime, emitter = _runtime("allow")
    runtime._record_downstream_unavailable(_session(), "notes", "No such file or directory")

    assert len(emitter.bodies) == 1, emitter.bodies
    execution = emitter.bodies[0]["execution"]
    assert execution["action"] == "gateway.downstream_unavailable"
    assert execution["target"] == "notes"
    # `failed` is what puts this in the console's failed view and in the `outcome` index. Recorded as
    # `applied` it would be filed with the successes and never surface, which is the same silence the
    # record exists to break.
    assert execution["outcome"] == "failed"
    assert emitter.bodies[0]["kind"] == "effect"


def test_the_record_commits_to_the_server_and_not_to_the_error_text() -> None:
    """`args-hash` is a commitment, and an error message carries paths, ports and sometimes a token.

    Two failures of the same downstream must also commit to the same value, or the audit cannot
    group them.
    """
    runtime, emitter = _runtime("allow")
    runtime._record_downstream_unavailable(_session(), "notes", "connection refused on 127.0.0.1:1")
    runtime._record_downstream_unavailable(_session(), "notes", "No such file or directory")

    hashes = {body["execution"]["args-hash"] for body in emitter.bodies}
    assert len(hashes) == 1, "the same downstream produced two different commitments"
    assert hashes == {sha256_hex(b"notes")}, hashes


def test_a_policy_that_gates_the_report_costs_the_record_and_not_the_gateway() -> None:
    """Deliberately unlike `gateway.session_open`, which refuses to start.

    This path is already the degraded one: an org whose policy gates the *reporting* of a fault
    should not thereby lose the working half of its gateway. Nothing is emitted — an envelope whose
    class requires an approval it does not carry would be refused by the kernel anyway — and the
    method returns rather than raising.
    """
    runtime, emitter = _runtime("gate")
    runtime._record_downstream_unavailable(_session(), "notes", "unreachable")
    assert emitter.bodies == []

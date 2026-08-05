"""The chokepoint's own behaviour, in process: classification, gating, aggregation, refusals.

These run without a kernel — the local chain is the record of truth until the kernel has it, so the
emitter here points at a port nothing is listening on and every assertion is about what the gateway
did *before* anything was pushed. That is deliberate: a component that only behaves when its server
is up has not implemented offline behaviour, it has implemented optimism.
"""

from __future__ import annotations

import json
import logging
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import canonicalize, object_hash
from stozher_gateway.chain import ChainError
from stozher_gateway.classify import Classifier, read_shaped
from stozher_gateway.config import GatewayConfig
from stozher_gateway.emitter import Emitter
from stozher_gateway.enforce import (
    ARGUMENTS_MAX_BYTES,
    Call,
    Enforcer,
    GateArgumentsError,
    Session,
    check_arguments,
)
from stozher_gateway.kernel_client import (
    KernelClient,
    KernelResponse,
    KernelUnreachableError,
)
from stozher_gateway.policy import Policy
from stozher_gateway.refusal import RefusalError
from stozher_gateway.signing import SigningKey
from stozher_gateway.store import GatewayStore

from .support import baseline_policy

ROOT = SigningKey(bytes.fromhex("11" * 32), "human:ivan")
POLICY_KEY = SigningKey(bytes.fromhex("13" * 32), "org:policy")
DEVICE = SigningKey(bytes.fromhex("cc" * 32), "agent:claude-code/test")


class Harness:
    """A gateway chokepoint with a real store, real keys and a kernel that is not there."""

    def __init__(self, tmp_path: Path, park_notify: list[str] | None = None) -> None:
        now = clock_module.now()
        self.store = GatewayStore(tmp_path / "gateway.db")
        self.policy = Policy.verified(
            POLICY_KEY.sign(
                baseline_policy(
                    "2026.07.1",
                    now,
                    ROOT.subject,
                    {
                        "github.get_file_contents": "read",
                        "github.echo_note": "read",
                        "harbormaster.list_projects": "read",
                    },
                )
            ),
            POLICY_KEY.id,
        )
        self.config = GatewayConfig.model_validate(
            {
                "gateway": {
                    "enabled": True,
                    "device": "test",
                    "aggregate_max_events": 100,
                    "park_notify": park_notify or [],
                    "park_notify_timeout_seconds": 2.0,
                },
                "org": {
                    "policy_key": POLICY_KEY.id,
                    "roots": [{"subject": ROOT.subject, "key": ROOT.id}],
                },
                "servers": [{"name": "github", "transport": "stdio", "command": "true"}],
            }
        )
        self.emitter = Emitter(
            self.store, KernelClient("http://127.0.0.1:9", None, 0.2), "gateway", max_events=2
        )
        self.classifier = Classifier(scopes={"github": "github"}, org_seeded=self.store.catalog_entry)
        self.enforcer = Enforcer(
            self.config,
            self.store,
            self.classifier,
            self.emitter,
            lambda: (self.policy, True),
        )
        self.session = Session(
            "claude-code", DEVICE.subject, DEVICE, self._mandate(now), "gw:test:claude-code"
        )
        self.emitter.register_key(DEVICE)
        self.forwarded: list[str] = []

    def _mandate(self, now: str) -> dict[str, Any]:
        mandate: dict[str, Any] = ROOT.sign(
            {
                "v": "stozher/0.1",
                "kind": "mandate",
                "mandate-kind": "standing",
                "grantor": {"subject": ROOT.subject, "key": ROOT.id, "role": "human"},
                "grantee": {"subject": DEVICE.subject, "key": DEVICE.id},
                "issued-at": clock_module.shift(now, -60),
                "not-before": clock_module.shift(now, -60),
                "not-after": clock_module.shift(now, 86400),
                "parent": None,
                "max-depth": 1,
                "scope": {
                    "components": ["gateway"],
                    "actions": ["github.*", "harbormaster.*"],
                    "classes": ["read", "benign", "consequential", "prohibited"],
                    "resources": ["*"],
                },
                "nonce": secrets.token_hex(16),
            }
        )
        return mandate

    def call(self, tool: str, schema: Any = None, **arguments: Any) -> Any:
        def forward() -> str:
            self.forwarded.append(tool)
            return f"upstream result for {tool}"

        return self.enforcer.call(
            self.session,
            Call("github", tool, arguments, schema or {"type": "object", "properties": {}}),
            forward,
        )

    def chain(self) -> list[dict[str, Any]]:
        return [envelope for _, envelope, _ in self.store.unpushed(limit=1000)]


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_a_read_is_forwarded_and_folded_not_emitted_one_by_one(harness: Harness) -> None:
    """Only class `read` may be aggregated, and the kernel never sees the firehose (§02 §7)."""
    assert "upstream result" in harness.call("get_file_contents", path="a")
    assert harness.chain() == [], "a read on its own emits nothing yet"
    harness.call("get_file_contents", path="b")
    envelopes = harness.chain()
    assert [envelope["kind"] for envelope in envelopes] == ["aggregate"]
    aggregate = envelopes[0]
    assert aggregate["classification"] == "read"
    assert aggregate["counts"] == {"total": 2, "by-action": {"github.get_file_contents": 2}}
    assert 1 <= len(aggregate["sample-hashes"]) <= 16
    assert harness.forwarded == ["get_file_contents", "get_file_contents"]


def test_an_open_window_is_flushed_at_shutdown(harness: Harness) -> None:
    """`gateway-must-flush-on-shutdown`: an unflushed window is an unaudited effect."""
    harness.call("get_file_contents", path="only-one")
    assert harness.chain() == []
    harness.emitter.stop(timeout=1.0)
    assert [envelope["kind"] for envelope in harness.chain()] == ["aggregate"]


def test_a_prohibited_action_is_never_forwarded_and_is_recorded_as_attempted(
    harness: Harness,
) -> None:
    """No mandate, no approval and no gate decision can permit it (§05 §3 step 2)."""
    with pytest.raises(RefusalError) as refused:
        harness.call("delete_repo", repo="acme/backend")
    assert refused.value.document["result"] == "prohibited"
    assert harness.forwarded == []
    envelope = harness.chain()[0]
    assert envelope["classification"] == "prohibited"
    assert envelope["execution"]["outcome"] == "attempted"
    assert "evidence" in envelope, "attempts carry full evidence"


def test_a_consequential_action_parks_and_the_call_is_not_forwarded(harness: Harness) -> None:
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    document = refused.value.document
    assert document["result"] == "parked"
    assert document["reason-code"] == "gate-parked"
    assert document["retryable"] is False
    assert "approval" in document["reason"]
    assert harness.forwarded == []
    assert len(harness.store.pending()) == 1


def test_an_unknown_tool_parks_even_when_the_heuristic_says_read(harness: Harness) -> None:
    """§10 §4: unknown is not ungoverned; unknown is expensive until a human classifies it."""
    schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    with pytest.raises(RefusalError) as refused:
        harness.call("search_everything", schema=schema, query="secrets")
    document = refused.value.document
    assert document["result"] == "parked"
    assert document["classification-tier"] == "heuristic"
    assert harness.forwarded == []


def test_a_first_call_park_says_the_decision_also_classifies_the_tool(harness: Harness) -> None:
    """§10 §4.3 seeds the catalog from the decision, and the refusal is where anyone learns it.

    Two independent adoption evaluations read this refusal, concluded the product demands a human
    signature for every read, and rejected it without making the second call. §06 §4.1 bars a
    refusal from carrying a route around the gate; naming what the decision *does* is not one.
    """
    schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    with pytest.raises(RefusalError) as refused:
        harness.call("search_everything", schema=schema, query="secrets")
    hint = refused.value.document["hint"]
    assert "not yet classified" in hint
    assert "later calls resolve through it" in hint


def test_a_park_of_an_already_classified_tool_promises_no_such_thing(harness: Harness) -> None:
    """The paired negative. Without it the positive passes against a constant string.

    `create_issue` is classified `consequential` by the manifest, so it parks on every call. A
    refusal telling its caller that later calls resolve without parking would be the gateway
    promising something the next call disproves.
    """
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    hint = refused.value.document["hint"]
    assert "not yet classified" not in hint
    assert "later calls resolve" not in hint


def test_an_approval_signed_by_a_stranger_permits_nothing(harness: Harness) -> None:
    """§06 §2 step (5). The row exists, the signature is real, and it still permits nothing."""
    stranger = SigningKey(bytes.fromhex("ee" * 32), "human:nobody")
    _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=stranger)
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "gate-approver-not-permitted"
    assert harness.forwarded == []


def _with_gate_rule(harness: Harness, approvers: list[str]) -> None:
    """Republish the harness policy with `consequential` gated to exactly `approvers`."""
    document = baseline_policy("2026.07.2", clock_module.now(), ROOT.subject)
    document["gate-rules"] = [
        {"classes": ["prohibited"], "decision": "deny"},
        {"classes": ["consequential"], "decision": "gate", "approvers": approvers},
        {"classes": ["read", "benign"], "decision": "allow"},
    ]
    harness.policy = Policy.verified(POLICY_KEY.sign(document), POLICY_KEY.id)


def test_an_approver_the_gateway_cannot_resolve_refuses_rather_than_widening(
    harness: Harness,
) -> None:
    """§06 §5's second kind of approver is a human holding a mandate, and §06 §6 rules the rest.

    The gateway resolves approvers against enrolled roots only — it holds its own caller's mandate
    and has no way to learn who else holds one. Falling back to "any root" would accept a root's
    signature, forward the call, and leave the kernel to refuse the envelope
    `gate-approver-not-permitted` once the effect had already happened.
    """
    _with_gate_rule(harness, ["human:security-officer"])
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    document = refused.value.document
    assert document["result"] == "blocked"
    assert document["reason-code"] == "gate-approver-unresolvable"
    assert harness.forwarded == []
    assert harness.store.pending() == [], "an unenforceable rule must not park a request"
    blocked = [e for e in harness.chain() if e["execution"]["outcome"] == "blocked"]
    assert len(blocked) == 1, "the attempt must still reach the audit"
    assert document["envelope-id"] is not None, "the refusal must name the record it wrote"


def test_a_rule_that_names_nobody_still_admits_every_enrolled_root(harness: Harness) -> None:
    """The control for the test above: an *empty* approver set is first-call gating (§10 §4).

    No rule named anyone, so every enrolled root may approve, and the call parks as usual. Refusing
    this too would have fixed the widening by breaking the gate.
    """
    _with_gate_rule(harness, [])
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["result"] == "parked"
    assert len(harness.store.pending()) == 1
    # And a root's signature over that park is honoured, which is what "every root" has to mean.
    _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=ROOT)
    assert "upstream result" in harness.call("create_issue", title="ship it")


# -- arguments that have no canonical form (§01 §3.1, §06 §6) ------------------------------------


def test_arguments_outside_binary64_are_refused_and_recorded(harness: Harness) -> None:
    """`object_hash` on foreign input is the first thing done with a call's arguments.

    It fails closed, so this was never a bypass — it was an *unrecorded* refusal: an uncaught
    `OverflowError` reached the agent as an opaque MCP error and the attempt was absent from the
    audit, which §06 §6 has no row for.
    """
    with pytest.raises(RefusalError) as refused:
        harness.call("get_file_contents", n=10**400)
    document = refused.value.document
    assert document["result"] == "blocked"
    assert document["reason-code"] == "jcs-non-finite-number"
    assert harness.forwarded == []
    blocked = [e for e in harness.chain() if e["execution"]["outcome"] == "blocked"]
    assert len(blocked) == 1
    assert blocked[0]["execution"]["action"] == "github.get_file_contents"


def test_arguments_nested_past_the_canonicalizer_are_refused_and_recorded(
    harness: Harness,
) -> None:
    """The other uncaught one: unbounded recursion in `_write` and `_reject_lone_surrogates`."""
    deep: Any = {"leaf": 1}
    for _ in range(2000):
        deep = {"n": deep}
    with pytest.raises(RefusalError) as refused:
        harness.call("get_file_contents", deep=deep)
    document = refused.value.document
    assert document["result"] == "blocked"
    assert document["reason-code"] == "jcs-malformed-json"
    assert harness.forwarded == []
    assert [e["execution"]["outcome"] for e in harness.chain()] == ["blocked"]


def test_a_decision_whose_request_was_rewritten_permits_nothing(harness: Harness) -> None:
    """§06 §2 step (2): pairing a real signature with a rewritten request body."""
    request_hash = _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=ROOT)
    parked = harness.store.parked(request_hash)
    assert parked is not None
    # Tamper with a member the lookup does *not* key on, so the decision is still found for this
    # call and the hash check is what refuses it rather than a failure to match.
    rewritten = dict(parked.request)
    rewritten["requested-at"] = clock_module.shift(parked.request["requested-at"], -3600)
    harness.store.park(
        request_hash,
        rewritten,
        parked.server,
        parked.tool,
        parked.proposed_class,
        parked.arg_schema,
        parked.first_call,
        parked.created_at,
    )
    harness.store.record_decision(request_hash, parked.decision or {}, None)
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "gate-authorization-request-hash-mismatch"
    assert harness.forwarded == []


def test_a_valid_approval_forwards_once_and_carries_the_authorization(harness: Harness) -> None:
    _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=ROOT)
    result = harness.call("create_issue", title="ship it")
    assert "upstream result" in result
    assert harness.forwarded == ["create_issue"]
    effect = [e for e in harness.chain() if e.get("execution", {}).get("action") == "github.create_issue"]
    assert len(effect) == 1
    assert effect[0]["execution"]["outcome"] == "applied"
    assert effect[0]["authorization"]["decision"]["sig"]["key"] == ROOT.id
    # (11) single use: the same signature cannot be spent twice.
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["result"] == "parked", refused.value.document


def test_a_signed_denial_is_recorded_with_its_reason(harness: Harness) -> None:
    """§06 §4.5: the audit must show that a human said no, with the reason."""
    _park_and_decide(
        harness,
        "create_issue",
        {"title": "ship it"},
        approver=ROOT,
        verdict="deny",
        reason="we do not file public issues on behalf of customers",
    )
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    document = refused.value.document
    assert document["result"] == "denied"
    assert document["reason-code"] == "gate-denied"
    assert "customers" in document["reason"]
    assert document["decided-by"] == ROOT.id
    assert harness.forwarded == []
    denial = [e for e in harness.chain() if e.get("execution", {}).get("outcome") == "denied"]
    assert denial and denial[0]["authorization"]["decision"]["decision"] == "deny"


# -- write-ahead: the record before the effect (§09 §4.1, §06 §6) --------------------------------


def test_the_record_of_an_effect_is_persisted_before_the_effect_is_applied(
    harness: Harness,
) -> None:
    """`emitter-must-persist-before-apply` (§09 §4 requirement 1).

    The probe runs *inside* `forward()`, which is the only moment at which the question can be
    asked: at that instant the downstream call is about to happen, so a durable record of it must
    already exist. Asserting afterwards would pass on an implementation that emits last.
    """
    _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=ROOT)
    at_apply_time: list[list[tuple[str, dict[str, Any], list[dict[str, Any]]]]] = []

    def forward() -> str:
        at_apply_time.append(harness.store.open_intents(harness.session.stream, DEVICE.id))
        return "upstream result for create_issue"

    harness.enforcer.call(
        harness.session,
        Call("github", "create_issue", {"title": "ship it"}, {"type": "object", "properties": {}}),
        forward,
    )
    assert at_apply_time and at_apply_time[0], "the effect was applied before its record was durable"
    _, body, _ = at_apply_time[0][0]
    assert body["execution"]["action"] == "github.create_issue"
    assert body["execution"]["args-hash"] == object_hash({"title": "ship it"})
    # Completing the call closes the write-ahead record: it is a crash marker, not a second copy.
    assert harness.store.open_intents(harness.session.stream, DEVICE.id) == []


def test_a_crash_between_forwarding_and_chaining_still_leaves_a_record(harness: Harness) -> None:
    """The failure §09 §4 names: the downstream ran, then the process died before the append.

    `KeyboardInterrupt` is the simulation — a `BaseException` walks straight past the emit path the
    way a signal walks past everything — and the assertion is that the audit is not silent about an
    effect that reached the world.
    """
    _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=ROOT)

    def forward_then_die() -> str:
        harness.forwarded.append("create_issue")
        raise KeyboardInterrupt("the process was killed after the downstream applied it")

    with pytest.raises(KeyboardInterrupt):
        harness.enforcer.call(
            harness.session,
            Call(
                "github", "create_issue", {"title": "ship it"}, {"type": "object", "properties": {}}
            ),
            forward_then_die,
        )
    assert harness.forwarded == ["create_issue"], "the effect happened"
    assert harness.chain() == [], "and nothing was chained for it, because the process died"

    # Restart. The next session is what turns the surviving write-ahead record into audit.
    assert harness.enforcer.recover_intents(harness.session) == 1
    effects = [
        envelope
        for envelope in harness.chain()
        if envelope.get("execution", {}).get("action") == "github.create_issue"
    ]
    assert len(effects) == 1
    assert effects[0]["execution"]["outcome"] == "attempted"
    assert harness.enforcer.recover_intents(harness.session) == 0, "recovery is not repeatable"


def test_a_chain_write_failure_refuses_instead_of_returning_success(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§06 §6: a code path that returns success without emitting is non-conformant."""
    _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=ROOT)
    append = harness.emitter.append

    def refuse_the_applied_record(
        key: SigningKey,
        stream: str,
        body: dict[str, Any],
        payloads: list[dict[str, Any]] | None = None,
    ) -> str:
        if body.get("execution", {}).get("outcome") == "applied":
            raise ChainError("schema-missing-member", "the local chain would not take it", 3)
        return append(key, stream, body, payloads)

    monkeypatch.setattr(harness.emitter, "append", refuse_the_applied_record)
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "chain-write-failed"
    assert refused.value.document["result"] == "blocked"
    assert harness.forwarded == ["create_issue"], "the effect did happen; the caller is told so"
    # The write-ahead record survives unresolved, so the audit still gets it at the next session.
    assert len(harness.store.open_intents(harness.session.stream, DEVICE.id)) == 1


def test_a_stale_policy_blocks_consequential_and_still_allows_reads(harness: Harness) -> None:
    """§05 §7: offline behaviour is per class, and it is never "proceed silently"."""
    harness.enforcer = Enforcer(
        harness.config,
        harness.store,
        harness.classifier,
        harness.emitter,
        lambda: (harness.policy, False),
    )
    assert "upstream result" in harness.call("get_file_contents", path="a")
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "policy-stale-offline"


def test_without_a_verified_policy_nothing_proceeds(harness: Harness) -> None:
    """A component must refuse to run on an unverifiable policy rather than relax (§05 §2.3)."""

    def no_policy() -> Any:
        raise RuntimeError("policy-not-published")

    harness.enforcer = Enforcer(
        harness.config, harness.store, harness.classifier, harness.emitter, no_policy
    )
    with pytest.raises(RefusalError) as refused:
        harness.call("get_file_contents", path="a")
    assert refused.value.document["reason-code"] == "policy-not-published"
    assert harness.forwarded == []


def _park_and_decide(
    harness: Harness,
    tool: str,
    arguments: dict[str, Any],
    approver: SigningKey,
    verdict: str = "approve",
    reason: str | None = None,
) -> str:
    """Park a call, then sign a real gate decision over its request hash."""
    with pytest.raises(RefusalError) as refused:
        harness.call(tool, **arguments)
    request_hash = refused.value.document["request-hash"]
    now = clock_module.now()
    decision = approver.sign(
        {
            "v": "stozher/0.1",
            "kind": "gate-decision",
            "request-hash": request_hash,
            "decision": verdict,
            "decided-at": clock_module.shift(now, -1),
            "not-after": clock_module.shift(now, 900),
            "single-use": True,
            "reason": reason,
        }
    )
    harness.store.record_decision(request_hash, decision, None)
    harness.forwarded.clear()
    return str(request_hash)


# -- Tier C, the heuristic -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "schema", "expected"),
    [
        ("get_file", {"type": "object", "properties": {"path": {"type": "string"}}}, True),
        ("list_issues", {"type": "object", "properties": {}}, True),
        ("search", {"type": "object", "properties": {"query": {"type": "string"}}}, True),
        ("getaway_car", {"type": "object", "properties": {}}, False),
        ("create_issue", {"type": "object", "properties": {"title": {"type": "string"}}}, False),
        ("get_or_create", {"type": "object", "properties": {"body": {"type": "object"}}}, False),
        ("read_query", {"type": "object", "properties": {"sql": {"type": "string"}}}, False),
        ("get_page", None, False),
        ("get_page", {"type": "object"}, False),
        (
            "get_anything",
            {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": True},
            False,
        ),
    ],
)
def test_the_heuristic_is_a_pure_function_of_name_and_schema(
    tool: str, schema: Any, expected: bool
) -> None:
    """It reads no description, no documentation, and nothing the upstream server authored."""
    assert read_shaped(tool, schema) is expected


def test_the_heuristic_never_produces_benign_or_prohibited(tmp_path: Path) -> None:
    """Both are judgements a regex is not entitled to make (§10 §3.4)."""
    classifier = Classifier(scopes={})
    for tool in ("get_thing", "do_thing", "delete_everything", "list_things"):
        result = classifier.classify("unknown-server", tool, {"type": "object", "properties": {}})
        assert result.tier == "heuristic"
        assert result.classification in ("read", "consequential")
        assert result.known is False


def test_the_shipped_catalog_covers_the_servers_it_claims_to() -> None:
    """Tier B is product content, not a stub: assert it stayed non-trivial."""
    classifier = Classifier(scopes={})
    catalog = json.loads(
        (Path(__file__).parents[1] / "src/stozher_gateway/catalog/shipped.json").read_text()
    )
    servers = catalog["servers"]
    assert len(servers) >= 15, sorted(servers)
    assert sum(len(server["tools"]) for server in servers.values()) >= 150
    for server, entry in servers.items():
        for tool, classification in entry["tools"].items():
            resolved = classifier.classify(server, tool, None)
            assert resolved.tier == "shipped"
            assert resolved.classification == classification
            assert resolved.action.startswith(entry["scope"] + ".")
            assert resolved.known is True


def test_a_seeded_entry_outranks_the_heuristic(tmp_path: Path) -> None:
    """Tier B' comes before Tier C, and marks the tool known so it stops parking as a first call."""
    store = GatewayStore(tmp_path / "gateway.db")
    classifier = Classifier(scopes={}, org_seeded=store.catalog_entry)
    before = classifier.classify("acme", "echo_note", {"type": "object", "properties": {}})
    assert before.tier == "heuristic" and before.known is False
    store.seed_catalog("acme", "echo_note", "acme.echo_note", "read", clock_module.now(), "e" * 64)
    after = classifier.classify("acme", "echo_note", {"type": "object", "properties": {}})
    assert after.tier == "org-seeded"
    assert after.classification == "read"
    assert after.known is True


def test_governing_a_native_tool_preserves_its_surface(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """§10 §8: Harbormaster's own tools are actions too, and the agent sees no difference.

    Only `fn` is replaced. Name, description and schema stay exactly as Harbormaster declared them,
    the handler stays **sync** — an async one would return an un-awaited coroutine at
    `fleetq/dispatcher.py:626` and `ui/routes.py:2752` — and the call goes through the chokepoint.
    """
    from mcp.server.fastmcp import FastMCP

    from stozher_gateway.runtime import Gateway

    monkeypatch.setenv("STOZHER_GATEWAY_DB", str(tmp_path / "native.db"))
    mcp = FastMCP("probe")

    @mcp.tool()
    def list_projects(scope: str = "all") -> str:
        """List every project Harbormaster knows about."""
        return f"projects in {scope}"

    before = mcp._tool_manager.list_tools()[0]
    surface = (before.name, before.description, before.parameters)

    gateway = Gateway(harness.config)
    gateway.enforcer = harness.enforcer
    governed = gateway._govern_native(mcp, harness.session)

    after = mcp._tool_manager.list_tools()[0]
    assert governed == 1
    assert (after.name, after.description, after.parameters) == surface
    assert after.is_async is False
    assert after.fn(scope="all") == "projects in all"
    assert harness.classifier.classify("harbormaster", "list_projects", None).tier == "shipped"


def test_the_target_names_the_boundary_the_gateway_actually_knows(harness: Harness) -> None:
    """`args-hash` binds the arguments; `target` names the server, not a guessed sub-resource."""
    with pytest.raises(RefusalError):
        harness.call("create_issue", title="ship it")
    parked = harness.store.pending()[0]
    assert parked.request["target"] == "mcp:github"
    assert parked.request["args-hash"] == object_hash({"title": "ship it"})
    assert len(parked.request["nonce"]) == 32


def test_a_park_the_kernel_refused_does_not_blame_the_network(harness: Harness) -> None:
    """Three ways to not reach the queue are three different things to say.

    `_queue_with_kernel` returned a bool, so the hint read "the kernel was unreachable" for all of
    them — including the one where the kernel answered, was healthy, and refused on purpose. A user
    whose ordinary loop had filled the per-subject cap was told the network was down, went to debug
    the network, and had no way to learn that the request they were told to wait for was in no
    queue at all and never would be.
    """
    # Unreachable is still a park: the request is held locally, and a human sees it when the kernel
    # is back. Nothing about the answer is untrue.
    def gone(_request: dict[str, Any], _arguments: Any = None) -> Any:
        raise KernelUnreachableError("no route to host")

    harness.enforcer._kernel = type("Stub", (), {"park_gate_request": staticmethod(gone)})()
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it while the kernel is gone")
    document = refused.value.document
    assert document["result"] == "parked"
    assert "unreachable" in document["hint"]
    assert "held locally" in document["hint"], "a park nobody can see must say so"

    # Refused is *not* a park, and calling it one is the defect. The queue rejected the request on
    # purpose: no notification fires, no console row exists, no approval will ever arrive. An
    # evaluator ran three rounds against a filled per-subject cap and collected sixty "parked"
    # receipts against zero queue entries — `bin/stozher-approve` answered "was never queued" for
    # every one. §06 §4.1's word for a call that did not happen and cannot proceed is `blocked`.
    def refused_by_kernel(_request: dict[str, Any], _arguments: Any = None) -> Any:
        # `retry-after-seconds` is what the real kernel sends, and the kernel's own side of that is
        # asserted in `gate_queue_and_console_decisions.rs::one_subject_cannot_grow_the_queue_without_bound`
        # — the two halves are bound separately on purpose, because a stub that agreed with this
        # file about a value the kernel does not send would be this suite agreeing with itself.
        return KernelResponse(
            status=429,
            body={"reason-code": "gate-rate-limited", "retry-after-seconds": 300},
        )

    harness.enforcer._kernel = type(
        "Stub", (), {"park_gate_request": staticmethod(refused_by_kernel)}
    )()
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it into a full queue")
    document = refused.value.document
    assert document["result"] == "blocked", "a request in no queue was reported as pending"
    # The kernel's own code, not a gateway paraphrase: the operator greps for `gate-rate-limited`.
    assert document["reason-code"] == "gate-rate-limited"
    assert "no decision can be made about it" in document["reason"]
    assert "nothing is pending" in document["hint"]
    # DEF-18. `blocked` is the right word for a call that did not happen — and it must not also mean
    # "never ask again". The cap is a window, so this call is answerable in a few minutes, and a
    # design partner measured what the opposite costs: 66 of 93 gated calls in one simulated morning
    # refused as unretryable, which is work dropped rather than deferred. The refund never happens.
    assert document["retryable"] is True, (
        "a rate-limited call was reported as permanently refused; the agent will not come back and "
        "the work is silently lost"
    )
    assert document["retry-after-seconds"] == 300, "the window is not passed through to the caller"

    # The other direction, and it is the one that keeps the paragraph in `refusal.py` true: a
    # kernel that refuses without saying when leaves `retryable` false. A caller told "yes" with no
    # "when" retries immediately, which is how the cap filled in the first place.
    def refused_without_a_window(_request: dict[str, Any], _arguments: Any = None) -> Any:
        return KernelResponse(status=429, body={"reason-code": "gate-rate-limited"})

    harness.enforcer._kernel = type(
        "Stub",
        (),
        {
            "park_gate_request": staticmethod(refused_without_a_window),
            # `_collect_decisions` runs before the park on a repeat call and asks the kernel about
            # the still-undecided local row. It is not what this assertion is about.
            "gate_request": staticmethod(lambda _h: KernelResponse(status=404, body={})),
        },
    )()
    with pytest.raises(RefusalError) as no_window:
        harness.call("create_issue", title="ship it into a full queue")
    assert no_window.value.document["retryable"] is False, (
        "retryable was raised without a retry-after; the two travel together or neither does"
    )

    # And the control: queued successfully, so the hint says nothing about being held locally.
    harness.enforcer._kernel = type(
        "Stub",
        (),
        {"park_gate_request": staticmethod(lambda _r, _a=None: KernelResponse(status=201, body={}))},
    )()
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it queued")
    assert "held locally" not in refused.value.document["hint"]


def _capturing_kernel(harness: Harness) -> list[dict[str, Any]]:
    """Replace the kernel with one that records the submission body and accepts it."""
    bodies: list[dict[str, Any]] = []

    def park(request: dict[str, Any], arguments: Any = None) -> Any:
        body: dict[str, Any] = {"request": request}
        if arguments is not None:
            body["arguments"] = arguments
        bodies.append(body)
        return KernelResponse(status=201, body={})

    harness.enforcer._kernel = type("Stub", (), {"park_gate_request": staticmethod(park)})()
    return bodies


def test_the_parked_request_carries_the_arguments_a_human_has_to_read(harness: Harness) -> None:
    """`spec/06 §4.4` rule 2 — the approver cannot read a digest.

    This component is the only party that ever holds the preimage of `args-hash`: it is a stdio
    process that exits with the session, so an approver reading the queue an hour later has nobody
    to ask. Before this, the queue showed the hash and the console told them to ask the process that
    had exited, which made every approval an act of trust in the thing being approved.
    """
    bodies = _capturing_kernel(harness)
    with pytest.raises(RefusalError):
        harness.call("create_issue", title="ship it", body="revenue down 12%")

    assert len(bodies) == 1, "the park did not reach the queue"
    submitted = bodies[0]
    assert submitted["arguments"] == {"title": "ship it", "body": "revenue down 12%"}
    # And they are what the request commits to, which is the only reason the kernel will show them.
    assert object_hash(submitted["arguments"]) == submitted["request"]["args-hash"]


def test_arguments_too_large_to_show_cost_the_display_and_never_the_park(
    harness: Harness,
) -> None:
    """`spec/06 §4.4` rule 3. Losing the display costs an approver context; losing the park costs
    them the gate, and the call is blocked either way."""
    bodies = _capturing_kernel(harness)
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="x" * (ARGUMENTS_MAX_BYTES + 1))

    assert len(bodies) == 1, "an oversize argument list stopped the request being parked at all"
    assert "arguments" not in bodies[0], "the cap was not applied before submitting"
    assert refused.value.document["result"] == "parked"


def test_the_component_never_submits_arguments_the_request_does_not_commit_to() -> None:
    """`spec/06 §4.4` rule 4, held on this side too.

    The kernel checks it on receipt, but a component that only learnt of the mismatch from a refusal
    would have parked without the values and never known why — so the predicate lives on both sides
    and the corpus (`spec/vectors/gate-arguments.json`) pins them to each other.
    """
    approved = {"title": "ship it"}
    assert check_arguments(approved, object_hash(approved)) == canonicalize(approved)

    with pytest.raises(GateArgumentsError) as refused:
        check_arguments({"title": "ship it to production"}, object_hash(approved))
    assert refused.value.code == "gate-arguments-hash-mismatch"

    with pytest.raises(GateArgumentsError) as refused:
        check_arguments({"a": "x" * ARGUMENTS_MAX_BYTES}, "0" * 64)
    assert refused.value.code == "gate-arguments-too-large"


# -- the park notifier ---------------------------------------------------------------------------
#
# "No notification channel is configured. Nothing pings an approver when something parks." An
# incident responder read that on `/console/pending` with nine requests waiting, and wrote: the
# control that stopped this is a web page someone has to remember to open.


def _notifier(tmp_path: Path, script: str) -> tuple[list[str], Path]:
    """A hook that records what it was handed, plus whatever else `script` does."""
    seen = tmp_path / "notified.json"
    body = f"import sys, pathlib\npathlib.Path({str(seen)!r}).write_text(sys.stdin.read())\n{script}"
    return [sys.executable, "-c", body], seen


def test_a_park_hands_the_notifier_the_request_and_none_of_the_arguments(tmp_path: Path) -> None:
    argv, seen = _notifier(tmp_path, "")
    harness = Harness(tmp_path, park_notify=argv)
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="a very secret issue title")
    harness.enforcer.drain_park_notifications(timeout=5.0)

    notified = json.loads(seen.read_text())
    assert notified["request-hash"] == refused.value.document["request-hash"]
    assert notified["action"] == "github.create_issue"
    assert notified["classification"] == "consequential"
    # The parked *arguments* have a retention ceiling and an authenticated route; a notification has
    # neither and goes wherever the operator wired it. It is a pointer, not a copy.
    assert "a very secret issue title" not in seen.read_text()


def test_a_notifier_that_fails_changes_neither_the_refusal_nor_the_queue(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A notifier that can fail the call makes the gate less available than no notifier at all."""
    argv, _ = _notifier(tmp_path, "sys.exit(3)")
    harness = Harness(tmp_path, park_notify=argv)
    with caplog.at_level(logging.WARNING, logger="stozher_gateway.enforce"):
        with pytest.raises(RefusalError) as refused:
            harness.call("create_issue", title="ship it")
        harness.enforcer.drain_park_notifications(timeout=5.0)

    assert refused.value.document["reason-code"] == "gate-parked"
    assert len(harness.store.pending()) == 1, "the park itself must be unaffected"
    assert harness.forwarded == []
    # And it is not swallowed: "nothing pinged me" and "the ping failed" must not look identical.
    assert any("exited 3" in record.getMessage() for record in caplog.records), (
        f"the notifier failed silently: {[r.getMessage() for r in caplog.records]}"
    )


def test_a_notifier_that_hangs_does_not_hold_the_caller(tmp_path: Path) -> None:
    """The refusal is a terminal answer (§06 §4.2); a slow notifier must not turn it into a wait."""
    argv, _ = _notifier(tmp_path, "import time; time.sleep(30)")
    harness = Harness(tmp_path, park_notify=argv)
    started = time.monotonic()
    with pytest.raises(RefusalError):
        harness.call("create_issue", title="ship it")
    elapsed = time.monotonic() - started
    # Tighter than `park_notify_timeout_seconds` (2.0 in this harness), and that is the whole
    # assertion. A bound above the timeout passes against a *synchronous* notifier too — the timeout
    # would cap the wait and the test would report success while the caller sat through it. The
    # first version of this test was written that way and survived being made synchronous.
    assert elapsed < 1.0, f"the caller waited {elapsed:.2f}s on the notifier"


def test_no_notifier_configured_parks_exactly_as_before(tmp_path: Path) -> None:
    """The paired negative: the default install must be unchanged by all of the above."""
    harness = Harness(tmp_path)
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "gate-parked"
    assert len(harness.store.pending()) == 1


def test_a_first_call_parks_the_classification_question_beside_the_call(harness: Harness) -> None:
    """§10 §4.3's second request, parked where the same approval command can answer it.

    Until this existed the second request was built only inside `stozher-gateway decide --classify`,
    so an operator approving through the console — the path `deploy/README.md` teaches — produced
    one signature, the catalog was never written, and every call of the tool parked again. Three
    independent evaluations reported that as "a signature for every read"; one counted 22 approvals
    against 0 catalog rows.
    """
    schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    with pytest.raises(RefusalError) as refused:
        harness.call("search_everything", schema=schema, query="secrets")
    parked = harness.store.parked(refused.value.document["request-hash"])

    assert parked is not None and parked.seed is not None, "no classification question was parked"
    assert parked.seed["decision"] is None, "a parked question must not arrive pre-answered"
    assert parked.seed["request"]["action"] == "kernel.seed_catalog_entry"
    assert parked.seed["request"]["target"] == "tool:github/search_everything"
    # The class offered is the classifier's own proposal, not the class policy gated on. The
    # approver is being asked "is this a read?" — the question `default-unknown` could not answer.
    assert parked.catalog_class == "read"

    # And it is not authority yet. A row selected on the column's presence alone would hand
    # `_seed_catalog` a request nobody has answered.
    assert harness.store.seeded_pending() == []


def test_a_park_of_an_already_classified_tool_asks_no_classification_question(
    harness: Harness,
) -> None:
    """The paired negative. `create_issue` is classified by the manifest, so there is nothing to ask
    and a second signature demanded for it would be a ceremony with no question in it."""
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    parked = harness.store.parked(refused.value.document["request-hash"])
    assert parked is not None
    assert parked.seed is None


def test_an_answered_classification_question_becomes_catalog_authority(harness: Harness) -> None:
    """Answered, it is exactly what the gateway's own `decide --classify` produced."""
    schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    with pytest.raises(RefusalError) as refused:
        harness.call("search_everything", schema=schema, query="secrets")
    request_hash = refused.value.document["request-hash"]

    seed_request = harness.store.parked(request_hash).seed["request"]
    harness.store.attach_seed_decision(
        request_hash,
        ROOT.sign(
            {
                "v": "stozher/0.1",
                "kind": "gate-decision",
                "request-hash": object_hash(seed_request),
                "decision": "approve",
                "decided-at": clock_module.now(),
                "not-after": clock_module.shift(clock_module.now(), 900),
                "single-use": True,
                "reason": None,
            }
        ),
    )
    pending = harness.store.seeded_pending()
    assert [p.request_hash for p in pending] == [request_hash]
    assert pending[0].catalog_class == "read"


def test_a_tool_the_published_policy_names_does_not_park_on_its_first_call(
    harness: Harness,
) -> None:
    """§10 §4 gates an *unknown* tool. Policy naming it by action is the organization knowing it.

    `deploy/README.md` documents publishing a policy as the escape from a signature per call. It was
    not one: first-call gating read only the classifier's tier, so an action the organization had
    explicitly classified still parked, and the approval seeded a catalog entry saying what policy
    already said. An engineer measuring the everyday cost published exactly that policy and reported
    it "did not help".
    """
    # `echo_note` is named `read` by this harness's policy and is in no manifest or catalog.
    assert "upstream result" in harness.call("echo_note", note="hello")
    assert harness.forwarded == ["echo_note"]


def test_a_tool_the_policy_does_not_name_still_parks_on_its_first_call(harness: Harness) -> None:
    """The paired negative, and the rule this must not swallow: unknown is not ungoverned.

    `default-unknown` is lowered to `read` here, and that is the whole design of the test. Under the
    shipped `consequential` default an unknown tool parks because the *gate rule* says so, and the
    assertion would hold with §10 §4 deleted — measuring something adjacent to the question. With
    the default allowed, parking can only come from first-call gating.
    """
    document = baseline_policy(
        "2026.07.2", clock_module.now(), ROOT.subject, {"github.echo_note": "read"}
    )
    document["classification"]["default-unknown"] = "read"
    harness.policy = Policy.verified(POLICY_KEY.sign(document), POLICY_KEY.id)

    schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    with pytest.raises(RefusalError) as refused:
        harness.call("search_everything", schema=schema, query="secrets")
    assert refused.value.document["reason-code"] == "gate-parked"
    assert refused.value.document["classification"] == "read", (
        "the class is allowed; only §10 §4 is refusing this"
    )
    assert harness.forwarded == []


def test_every_effect_carries_its_arguments_as_a_payload_beside_the_envelope(
    harness: Harness,
) -> None:
    """ADR-0030 §6, the second residual: `_effect_body` builds `{server, tool, arguments}` for
    every effect and nothing asserted it.

    The nearest binding was `test_a_prohibited_action_is_never_forwarded_and_is_recorded_as_attempted`,
    which asserts only that an `evidence` member exists — so the member could have gone on naming a
    `payload-hash` while the payload behind it stopped being built, or stopped travelling with the
    envelope, and every test would still have passed. Every test that reads a payload's contents
    builds the payload by hand in its own fixture, which asserts the fixture.

    This is the claim ADR-0030 exists to record: the arguments of a call that ran ARE retained.
    """
    with pytest.raises(RefusalError):
        harness.call("delete_repo", repo="acme/backend")

    unpushed = harness.store.unpushed(limit=10)
    assert len(unpushed) == 1
    _, envelope, payloads = unpushed[0]

    # The payload travels beside the envelope, not inside it — §04 §5.2 binds them by hash, and the
    # values must be erasable without touching a signed byte.
    assert len(payloads) == 1, payloads
    carried = payloads[0]
    assert carried["payload"] == {
        "server": "github",
        "tool": "delete_repo",
        "arguments": {"repo": "acme/backend"},
    }
    assert carried["media-type"] == "application/json"

    # And the binding itself: the envelope's `payload-hash` is the hash of what was carried. A
    # payload that does not answer to the digest in the signed object is not evidence of anything.
    assert envelope["evidence"]["payload-hash"] == carried["payload-hash"]
    assert carried["payload-hash"] == object_hash(carried["payload"])

    # An attempt is the case that matters most and the one most easily missed: this call was never
    # forwarded, so the arguments in the store are the only record that it was tried at all.
    assert harness.forwarded == []
    assert envelope["execution"]["outcome"] == "attempted"


def test_the_approved_effect_carries_no_argument_values_in_any_signed_byte(
    harness: Harness,
) -> None:
    """§06 §4.4 rule 6, which ADR-0029 §8 recorded as holding *structurally* and untested.

    "Structure is not a test" is this project's own phrase (ADR-0013 §2: a guard no test binds is a
    guard a future edit deletes). The structure in question is that `authorization` is built as
    `{"request": parked.request, "decision": parked.decision}` and §06 §1.1's member set is closed —
    so an `arguments` member has nowhere to enter. One helpful edit widening `authorization.request`
    to "everything the submission carried" would breach the retention ceiling in a signed object,
    and every test would still have passed.

    The pairing is the point: the *envelope* carries no values, and the payload beside it carries
    them all. §04 §5.2 binds the two by hash precisely so the values can be erased later without
    touching a byte anyone signed.
    """
    secret = "delete everything in acme/backend"
    _park_and_decide(harness, "create_issue", {"title": secret}, approver=ROOT)
    assert "upstream result" in harness.call("create_issue", title=secret)

    applied = [e for _, e, _ in harness.store.unpushed(limit=50) if e.get("kind") == "effect"]
    assert applied, "the approved call emitted no effect"
    envelope = applied[-1]
    assert envelope["execution"]["outcome"] == "applied"

    # The claim, over the whole signed object rather than over the members we happen to remember:
    # nothing an approver's or emitter's signature covers contains the values themselves.
    assert secret not in canonicalize(envelope), (
        "argument values reached a signed envelope: " + canonicalize(envelope)
    )
    assert "arguments" not in envelope["authorization"]["request"], envelope["authorization"]
    assert "arguments" not in envelope["evidence"], envelope["evidence"]
    # `evidence` may hold the commitment and only the commitment.
    assert envelope["evidence"]["payload-hash"]

    # And the other half, so this test cannot pass by the arguments having been lost altogether —
    # which would satisfy every assertion above while destroying the evidence ADR-0030 exists for.
    payloads = [p for _, e, ps in harness.store.unpushed(limit=50) if e.get("kind") == "effect" for p in ps]
    assert any(secret in canonicalize(p["payload"]) for p in payloads), (
        "the values are in no payload either, so they were not withheld from the envelope — "
        "they were lost"
    )

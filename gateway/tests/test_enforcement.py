"""The chokepoint's own behaviour, in process: classification, gating, aggregation, refusals.

These run without a kernel — the local chain is the record of truth until the kernel has it, so the
emitter here points at a port nothing is listening on and every assertion is about what the gateway
did *before* anything was pushed. That is deliberate: a component that only behaves when its server
is up has not implemented offline behaviour, it has implemented optimism.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import object_hash
from stozher_gateway.chain import ChainError
from stozher_gateway.classify import Classifier, read_shaped
from stozher_gateway.config import GatewayConfig
from stozher_gateway.emitter import Emitter
from stozher_gateway.enforce import Call, Enforcer, Session
from stozher_gateway.kernel_client import KernelClient
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

    def __init__(self, tmp_path: Path) -> None:
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
                "gateway": {"enabled": True, "device": "test", "aggregate_max_events": 100},
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


def test_an_approval_signed_by_a_stranger_permits_nothing(harness: Harness) -> None:
    """§06 §2 step (5). The row exists, the signature is real, and it still permits nothing."""
    stranger = SigningKey(bytes.fromhex("ee" * 32), "human:nobody")
    _park_and_decide(harness, "create_issue", {"title": "ship it"}, approver=stranger)
    with pytest.raises(RefusalError) as refused:
        harness.call("create_issue", title="ship it")
    assert refused.value.document["reason-code"] == "gate-approver-not-permitted"
    assert harness.forwarded == []


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

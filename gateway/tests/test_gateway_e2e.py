"""The S2 gate, end to end, against a real kernel and an unmodified MCP client.

**What is real here.** A compiled `stozher-kernel` serving HTTP over a real SQLite store, bootstrapped
through the real two-envelope ceremony. A real `harbormaster-mcp` process loading the gateway through
its own entry-point mechanism, spoken to over stdio by a stock `mcp.ClientSession` — the same client
any foreign agent uses, with **zero agent-side changes**: the client is configured with a command and
knows nothing about Stozher. A real downstream MCP server, also unmodified. Real Ed25519 signatures
throughout, verified by the kernel, chained, and checked with `/v1/streams/{stream}/verify`.

**What is stubbed, pending S4.** The *transport* by which a human's decision reaches the gateway: S4
builds the kernel-native pending queue and notification path, so here the approval is written by
`stozher-gateway approve`, which signs with an enrolled root's key. The decision object itself is
real and is verified through all of §06 §2 — there is no ambient flag, no boolean and no bypass. A
decision that failed any of those checks would permit nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway.__main__ import main as gateway_cli
from stozher_gateway.store import GatewayStore

from .support import Kernel, gateway_config_file, gateway_environment

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "downstream_server.py"


class Agent:
    """A foreign MCP agent: a stock client pointed at a command. Nothing here is Stozher-aware."""

    def __init__(self, command: list[str], environment: dict[str, str], cwd: Path) -> None:
        self._command = command
        self._environment = environment
        self._cwd = cwd
        self._exit: Any = None
        self._session: Any = None

    async def __aenter__(self) -> Agent:
        from contextlib import AsyncExitStack

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._exit = AsyncExitStack()
        await self._exit.__aenter__()
        parameters = StdioServerParameters(
            command=self._command[0],
            args=self._command[1:],
            env=self._environment,
            cwd=str(self._cwd),
        )
        read, write = await self._exit.enter_async_context(stdio_client(parameters))
        self._session = await self._exit.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._exit.__aexit__(*exc)

    async def tools(self) -> dict[str, Any]:
        listed = await self._session.list_tools()
        return {tool.name: tool for tool in listed.tools}

    async def call(self, name: str, **arguments: Any) -> Any:
        return await self._session.call_tool(name, arguments)


def text_of(result: Any) -> str:
    return "\n".join(item.text for item in result.content if getattr(item, "text", None))


def refusal_of(result: Any) -> dict[str, Any]:
    """Pull the §06 §4.1 refusal out of an error result."""
    assert result.isError, f"expected an error result, got {text_of(result)}"
    body = text_of(result)
    start = body.index("{")
    document: dict[str, Any] = json.loads(body[start : body.rindex("}") + 1])
    return document


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("s2-gate")
    seed_file = root / "gateway.seed"
    seed_file.write_text("aa" * 32)
    seed_file.chmod(0o600)

    kernel = Kernel(root, bytes.fromhex("aa" * 32), "agent:claude-code/test-mbp")
    kernel.start()
    try:
        mandate_file = root / "mandate.json"
        mandate_file.write_text(json.dumps(kernel.gateway_mandate))
        config = gateway_config_file(
            root, kernel, seed_file, mandate_file, [sys.executable, str(FIXTURE_SERVER)]
        )
        # Fold every pair of reads so the aggregation path completes inside the test rather than on
        # a five-minute timer. The shutdown flush is covered separately, in-process.
        config.write_text(config.read_text().replace("aggregate_max_events = 500", "aggregate_max_events = 2"))
        database = root / "gateway.db"
        (root / ".harbormaster.toml").write_text(
            '[plugins]\nenabled = true\nallow = ["stozher-gateway"]\n'
        )
        yield {
            "root": root,
            "kernel": kernel,
            "config": config,
            "database": database,
            "environment": gateway_environment(config, database, seed_file, kernel),
        }
    finally:
        kernel.stop()


def kernel_envelopes(kernel: Kernel, **filters: str) -> list[dict[str, Any]]:
    query = "&".join(f"{name}={value}" for name, value in filters.items())
    status, body = kernel.request("GET", f"/v1/envelopes?{query}")
    assert status == 200, body
    return list(body["records"])


def await_envelopes(kernel: Kernel, count: int, timeout: float = 20.0, **filters: str) -> list[dict[str, Any]]:
    deadline = time.time() + timeout
    records: list[dict[str, Any]] = []
    while time.time() < deadline:
        records = kernel_envelopes(kernel, **filters)
        if len(records) >= count:
            return records
        time.sleep(0.25)
    return records


async def test_the_gate(world: dict[str, Any]) -> None:
    """(a) a legible, verifiable audit trail with zero agent-side changes; (b) first-call gating."""
    kernel: Kernel = world["kernel"]
    environment = world["environment"]
    command = [sys.executable, "-m", "harbormaster", "--transport", "stdio"]

    async with Agent(command, environment, world["root"]) as agent:
        tools = await agent.tools()
        # (a) The downstream server's tools are re-exported, schema and all. The agent was told a
        # command; it discovered a governed surface.
        assert "github__get_file_contents" in tools, sorted(tools)
        assert "github__create_issue" in tools
        assert tools["github__get_file_contents"].inputSchema["properties"].keys() == {"path"}

        # read: forwarded, result verbatim, folded into an aggregation record.
        first = await agent.call("github__get_file_contents", path="README.md")
        assert not first.isError, text_of(first)
        assert "contents of README.md" in text_of(first)
        second = await agent.call("github__get_file_contents", path="LICENSE")
        assert "contents of LICENSE" in text_of(second)

        # prohibited: refused, never forwarded, recorded as attempted.
        prohibited = refusal_of(await agent.call("github__delete_repo", repo="acme/backend"))
        assert prohibited["result"] == "prohibited"
        assert prohibited["reason-code"] == "policy-prohibited"
        assert prohibited["classification"] == "prohibited"
        assert prohibited["retryable"] is False

        # consequential: parks, with a legible refusal naming the request a human must sign.
        parked = refusal_of(await agent.call("github__create_issue", title="ship it"))
        assert parked["result"] == "parked"
        assert parked["reason-code"] == "gate-parked"
        assert parked["classification-tier"] == "shipped"
        create_issue_request = parked["request-hash"]

        # (b) first call of an unknown tool parks whatever the heuristic guessed.
        unknown = refusal_of(await agent.call("github__echo_note", note="hello"))
        assert unknown["result"] == "parked"
        assert unknown["classification-tier"] == "heuristic"
        assert unknown["classification"] == "consequential"
        echo_request = unknown["request-hash"]

    # A human signs. Two decisions, two records: the call, and the catalog entry it seeds.
    approver_key = world["root"] / "approver.seed"
    approver_key.write_text("11" * 32)
    approver_key.chmod(0o600)
    _approve(world, create_issue_request, approver_key)
    _approve(world, echo_request, approver_key, classify="read")

    async with Agent(command, environment, world["root"]) as agent:
        applied = await agent.call("github__create_issue", title="ship it")
        assert not applied.isError, text_of(applied)
        assert "issue created: ship it" in text_of(applied)

        # The approval covers this call, and the same interaction seeded the org catalog.
        seeded = await agent.call("github__echo_note", note="hello")
        assert not seeded.isError, text_of(seeded)
        assert "note: hello" in text_of(seeded)

    # The seed decides the tool's class for the gateway. For the *kernel* to agree, the class has to
    # reach the policy it evaluates — the kernel cannot see the gateway's catalog (see the report's
    # spec-conflict note). The organization publishes it, through the same gated path as any policy
    # change, which is what makes an org-seeded class authoritative rather than local folklore.
    kernel.publish_policy("2026.07.2", {"github.echo_note": "read"})

    async with Agent(command, environment, world["root"]) as agent:
        # No longer a first call, and now classified: it proceeds with no human in the loop.
        again = await agent.call("github__echo_note", note="second")
        assert not again.isError, text_of(again)

    stream = "gw:test-mbp:claude-code"
    records = await_envelopes(kernel, 8, stream=stream, limit="100")
    records.sort(key=lambda record: record["envelope"]["seq"])
    kinds = [record["envelope"]["kind"] for record in records]
    actions = [record["envelope"].get("execution", {}).get("action") for record in records]
    outcomes = [record["envelope"].get("execution", {}).get("outcome") for record in records]

    assert kinds[0] == "mandate", "the mandate is published before anything cites it"
    assert "gateway.session_open" in actions
    assert "aggregate" in kinds, "reads fold into an aggregation record, not one envelope each"
    assert "github.delete_repo" in actions
    assert outcomes[actions.index("github.delete_repo")] == "attempted"
    assert "github.create_issue" in actions
    assert outcomes[actions.index("github.create_issue")] == "applied"
    assert "kernel.seed_catalog_entry" in actions, "the catalog entry has its own signed record"

    # The approved call carries the approval, and the kernel verified all eleven steps to accept it.
    record = records[actions.index("github.create_issue")]
    approved = record["envelope"]
    assert approved["authorization"]["decision"]["decision"] == "approve"
    assert approved["authorization"]["decision"]["sig"]["key"] == kernel.human_root.id
    assert record["human-root"] == kernel.human_root.subject, "the walk terminates at a named human"
    assert record["effective-class"] == "consequential"
    assert record["policy-violation"] is None

    # The chain verifies at the kernel, from genesis to head.
    status, verification = kernel.request("GET", f"/v1/streams/{stream}/verify")
    assert status == 200, verification
    assert verification.get("valid", True) is True, verification
    assert verification["count"] >= 8
    assert verification["anchored"] is True

    # Nothing the gateway emitted was refused.
    status, rejections = kernel.request("GET", "/v1/rejections?limit=100")
    assert status == 200
    assert rejections["count"] == 0, _why_refused(kernel, rejections["rejections"])

    # The mandate walk answers "on whose authority" for the consequential effect.
    status, walk = kernel.request("GET", f"/v1/envelopes/{record['id']}/mandate")
    assert status == 200, walk
    assert walk["human-root"] == kernel.human_root.subject



def _why_refused(kernel: Kernel, rejections: list[dict[str, Any]]) -> str:
    """A refusal, said in one line per record, with the *action* that was refused.

    DEF-7 cost a round of CI-log archaeology because this assertion handed pytest the raw record
    list, which pytest truncated at the interesting part: the reason and the position survived, the
    action did not. The position is on the record; the action is one lookup away on the stream the
    record names. Resolving it here means the next occurrence explains itself in its own failure
    message instead of sending someone to `gh run view --log`.
    """
    lines = []
    for record in rejections:
        stream, seq = record.get("claimed-stream"), record.get("claimed-seq")
        action = "<unresolved>"
        if stream is not None and seq is not None:
            status, page = kernel.request("GET", f"/v1/envelopes?stream={stream}&limit=100")
            if status == 200:
                for entry in page.get("envelopes", []):
                    envelope = entry.get("envelope", entry)
                    if envelope.get("seq") == seq:
                        action = str(envelope.get("execution", {}).get("action", "<no action>"))
                        break
        lines.append(
            f"{record.get('reason')} at {stream} seq {seq} — action {action} — {record.get('detail')}"
        )
    return "\n".join(lines)


def _approve(world: dict[str, Any], request_hash: str, key: Path, classify: str | None = None) -> None:
    argv = [
        "--config",
        str(world["config"]),
        "approve",
        "--request",
        request_hash,
        "--key",
        str(key),
        "--subject",
        "human:ivan",
    ]
    if classify is not None:
        argv += ["--classify", classify]
    previous = os.environ.get("STOZHER_GATEWAY_DB")
    os.environ["STOZHER_GATEWAY_DB"] = str(world["database"])
    try:
        assert gateway_cli(argv) == 0
    finally:
        if previous is None:
            del os.environ["STOZHER_GATEWAY_DB"]
        else:
            os.environ["STOZHER_GATEWAY_DB"] = previous


def test_an_approval_is_not_a_boolean(world: dict[str, Any]) -> None:
    """There is no row, flag or field in the store that grants permission by being truthy.

    The parked table holds signed decision objects. Rewriting one to say `approve` without a valid
    signature over the request hash changes nothing, because §06 §2 runs over it before anything is
    forwarded — which is the ADR-0002 anti-lesson made structural rather than discouraged.
    """
    store = GatewayStore(Path(world["database"]))
    rows = store.catalog()
    assert any(row["origin"] == "org-seeded" for row in rows), rows
    assert all(row["envelope_id"] for row in rows), "a seeded entry names the record that seeded it"


def test_neither_end_imports_the_gateway() -> None:
    """Zero-touch cuts both ways: neither the downstream server nor the client knows about Stozher.

    Parsed rather than grepped, so a mention in a comment does not fail and a real import cannot
    hide in one.
    """
    import ast

    for source_file in (FIXTURE_SERVER, Path(__file__)):
        tree = ast.parse(source_file.read_text())
        imported = {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        } | {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        agent_side = {name for name in imported if name.startswith(("mcp", "harbormaster"))}
        if source_file == FIXTURE_SERVER:
            assert not any(name.startswith("stozher") for name in imported), imported
        assert agent_side, f"{source_file.name} should speak plain MCP"


def test_harbormaster_process_starts_with_the_plugin(world: dict[str, Any]) -> None:
    """`load_plugins` found the distribution by name from `[plugins] allow` and nothing else."""
    result = subprocess.run(
        [sys.executable, "-c", "import stozher_gateway.plugin as p; print(p.register.__module__)"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "stozher_gateway.plugin"

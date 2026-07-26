"""The S3 gate: the demo, end to end, against real processes and real rendered pages.

**What is real here.** A compiled `stozher-kernel` serving HTTP over a real SQLite store,
bootstrapped through the real two-envelope genesis ceremony. A real
`python -m harbormaster --transport stdio` process that loads the gateway through Harbormaster's own
plugin mechanism. A stock `mcp.ClientSession` speaking plain MCP over stdio — the client knows
nothing about Stozher. A real unmodified downstream MCP server that writes down every call it
receives. Real Ed25519 signatures throughout. Every console assertion below is made against the
**bytes the kernel rendered**, fetched over HTTP with a real credential — not against the return
value of a Rust function.

**What is not covered here, stated rather than implied.**

* The *transport* of a human's approval is still the gateway's local SQLite (S4 builds the
  kernel-native queue) — as in the S2 gate. The decision object is real and is verified through
  all of §06 §2.
* Therefore the console's pending page cannot show a gate-*parked* request: the park is held by
  the component that parked it, and no envelope kind carries one to the kernel. The park itself is
  real and is asserted at the MCP boundary; the page renders and states the boundary. See the S3
  report's spec-conflict note on `spec/06 §4.3`.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.__main__ import main as gateway_cli
from stozher_gateway.canonical import sha256_hex
from stozher_gateway.crypto import ROLE_DEVICE, derive
from stozher_gateway.signing import SigningKey, object_id

from .support import CORE_STREAM, Kernel, gateway_environment
from .test_gateway_e2e import Agent, refusal_of, text_of

RECORDING_SERVER = Path(__file__).parent / "fixtures" / "recording_server.py"
GATEWAY_SEED = "aa" * 32
#: The caller whose mandate the demo revokes. It holds its own stream, so revoking it cannot
#: disturb the chain the audit assertions are made against (a refused envelope wedges its stream —
#: ADR-0007 §6).
REVOKED_CALLER = "auditor-bot"


# -- the world ---------------------------------------------------------------------------------


def two_caller_config(
    root: Path,
    kernel: Kernel,
    seed_file: Path,
    mandates: dict[str, Path],
    server_command: list[str],
) -> Path:
    """A `stozher-gateway.toml` with two callers, so one mandate can be revoked in isolation."""
    roots = "\n".join(
        f'[[org.roots]]\nsubject = "{key.subject}"\nkey = "{key.id}"\n'
        for key in (kernel.human_root, kernel.second_root)
    )
    callers = "\n".join(
        f"""[[callers]]
name = "{name}"
subject = "{subject}"
key_index = {index}
token_sha256 = "{sha256_hex(b"caller-token")}"
mandate_file = "{mandates[name]}"
mandate_kind = "standing"
"""
        for name, subject, index in (
            ("claude-code", "agent:claude-code/test-mbp", 0),
            (REVOKED_CALLER, f"agent:{REVOKED_CALLER}/test-mbp", 1),
        )
    )
    arguments = ", ".join(json.dumps(argument) for argument in server_command[1:])
    path = root / "stozher-gateway.toml"
    path.write_text(
        f"""
[gateway]
enabled = true
device = "test-mbp"
govern_native_tools = false
aggregate_max_events = 2

[kernel]
url = "{kernel.url}"
token_env = "STOZHER_KERNEL_TOKEN"
timeout_seconds = 5.0
policy_refresh_seconds = 1

[identity]
seed_file = "{seed_file}"

[org]
policy_key = "{kernel.policy_key.id}"

{roots}

{callers}

[[servers]]
name = "github"
transport = "stdio"
command = {json.dumps(server_command[0])}
args = [{arguments}]
"""
    )
    return path


def standing_mandate_for(kernel: Kernel, grantee: SigningKey) -> dict[str, Any]:
    """A standing mandate signed by the enrolled human root — the same shape S2's ceremony uses."""
    now = clock_module.now()
    return kernel.human_root.sign(
        {
            "v": "stozher/0.1",
            "kind": "mandate",
            "mandate-kind": "standing",
            "grantor": {
                "subject": kernel.human_root.subject,
                "key": kernel.human_root.id,
                "role": "human",
            },
            "grantee": {"subject": grantee.subject, "key": grantee.id},
            "issued-at": clock_module.shift(now, -60),
            "not-before": clock_module.shift(now, -60),
            "not-after": clock_module.shift(now, 30 * 86400),
            "parent": None,
            "max-depth": 1,
            "scope": {
                "components": ["gateway"],
                "actions": ["github.*", "gateway.*", "kernel.*", "harbormaster.*"],
                "classes": ["read", "benign", "consequential", "prohibited"],
                "resources": ["*"],
            },
            "nonce": secrets.token_hex(16),
        }
    )


def submit_revocation(kernel: Kernel, mandate_ref: str) -> str:
    """The named human revokes a mandate, through ordinary ingest. Returns the revocation's id."""
    now = clock_module.now()
    seq, prev = kernel.head(CORE_STREAM)
    envelope = kernel.human_root.sign(
        {
            "v": "stozher/0.1",
            "kind": "revocation",
            "emitted-at": now,
            "stream": CORE_STREAM,
            "seq": seq,
            "prev-hash": prev,
            "identity": {
                "subject": kernel.human_root.subject,
                "key": kernel.human_root.id,
                "component": "kernel",
            },
            "revokes": mandate_ref,
            "revoked-at": now,
            "reason": "the demo revokes it",
        }
    )
    kernel.submit(envelope)
    return object_id(envelope)


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("s3-gate")
    seed_file = root / "gateway.seed"
    seed_file.write_text(GATEWAY_SEED)
    seed_file.chmod(0o600)
    call_log = root / "downstream-calls.log"
    call_log.write_text("")

    kernel = Kernel(root, bytes.fromhex(GATEWAY_SEED), "agent:claude-code/test-mbp")
    kernel.start()
    try:
        revoked_key = SigningKey(
            derive(bytes.fromhex(GATEWAY_SEED), ROLE_DEVICE, 1),
            f"agent:{REVOKED_CALLER}/test-mbp",
        )
        revoked_mandate = standing_mandate_for(kernel, revoked_key)
        mandates: dict[str, Path] = {}
        for name, document in (
            ("claude-code", kernel.gateway_mandate),
            (REVOKED_CALLER, revoked_mandate),
        ):
            path = root / f"mandate-{name}.json"
            path.write_text(json.dumps(document))
            mandates[name] = path

        config = two_caller_config(
            root, kernel, seed_file, mandates, [sys.executable, str(RECORDING_SERVER)]
        )
        database = root / "gateway.db"
        (root / ".harbormaster.toml").write_text(
            '[plugins]\nenabled = true\nallow = ["stozher-gateway"]\n'
        )
        environment = gateway_environment(config, database, seed_file, kernel)
        environment["STOZHER_TEST_CALL_LOG"] = str(call_log)
        yield {
            "root": root,
            "kernel": kernel,
            "config": config,
            "database": database,
            "environment": environment,
            "call_log": call_log,
            "revoked_mandate_ref": object_id(revoked_mandate),
        }
    finally:
        kernel.stop()


def agent_for(world: dict[str, Any], caller: str) -> Agent:
    environment = dict(world["environment"])
    environment["STOZHER_GATEWAY_CALLER"] = caller
    return Agent(
        [sys.executable, "-m", "harbormaster", "--transport", "stdio"],
        environment,
        world["root"],
    )


def console(world: dict[str, Any], path: str) -> tuple[int, str]:
    """Fetch a console page with a real credential and return the rendered bytes."""
    kernel: Kernel = world["kernel"]
    request = urllib.request.Request(f"{kernel.url}{path}", method="GET")
    request.add_header("Authorization", f"Bearer {kernel.token}")
    try:
        with urllib.request.urlopen(request, timeout=10.0) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def downstream_calls(world: dict[str, Any]) -> list[str]:
    return [line for line in Path(world["call_log"]).read_text().splitlines() if line]


def await_console(world: dict[str, Any], path: str, needle: str, timeout: float = 25.0) -> str:
    """Poll a console page until it shows `needle` — the gateway pushes envelopes in the background."""
    deadline = time.time() + timeout
    body = ""
    while time.time() < deadline:
        status, body = console(world, path)
        assert status == 200, body
        if needle in body:
            return body
        time.sleep(0.25)
    raise AssertionError(f"{path} never showed {needle!r}:\n{body[:4000]}")


def approve(world: dict[str, Any], request_hash: str, key: Path) -> None:
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
    previous = os.environ.get("STOZHER_GATEWAY_DB")
    os.environ["STOZHER_GATEWAY_DB"] = str(world["database"])
    try:
        assert gateway_cli(argv) == 0
    finally:
        if previous is None:
            del os.environ["STOZHER_GATEWAY_DB"]
        else:
            os.environ["STOZHER_GATEWAY_DB"] = previous


# -- the gate ----------------------------------------------------------------------------------

STREAM = "gw:test-mbp:claude-code"


async def test_the_demo(world: dict[str, Any]) -> None:
    """A foreign agent's calls, classified, verifiable, walked to a human — in the console."""
    kernel: Kernel = world["kernel"]

    async with agent_for(world, "claude-code") as agent:
        tools = await agent.tools()
        assert "github__get_file_contents" in tools, sorted(tools)

        # Reads: forwarded verbatim, folded into one aggregation record.
        first = await agent.call("github__get_file_contents", path="README.md")
        assert "contents of README.md" in text_of(first)
        await agent.call("github__get_file_contents", path="LICENSE")

        # Prohibited: refused, never forwarded, recorded as an attempt with full evidence.
        prohibited = refusal_of(await agent.call("github__delete_repo", repo="acme/backend"))
        assert prohibited["result"] == "prohibited"

        # An unknown tool parks at first call, whatever the heuristic guessed (§10 §4).
        unknown = refusal_of(await agent.call("github__echo_note", note="hello"))
        assert unknown["result"] == "parked"
        assert unknown["reason-code"] == "gate-parked"
        assert unknown["classification-tier"] == "heuristic"

        parked_consequential = refusal_of(await agent.call("github__create_issue", title="ship it"))
        assert parked_consequential["result"] == "parked"
        create_issue_request = parked_consequential["request-hash"]

    assert "delete_repo" not in downstream_calls(world), "a prohibited call reached the server"
    assert "echo_note" not in downstream_calls(world), "a parked call reached the server"

    # A named human signs the parked consequential request, and the call proceeds.
    approver_key = world["root"] / "approver.seed"
    approver_key.write_text("11" * 32)
    approver_key.chmod(0o600)
    approve(world, create_issue_request, approver_key)

    async with agent_for(world, "claude-code") as agent:
        applied = await agent.call("github__create_issue", title="ship it")
        assert not applied.isError, text_of(applied)
        assert "issue created: ship it" in text_of(applied)

    # -- 1. the calls appear classified in the audit explorer -----------------------------------

    audit = await_console(world, f"/console/audit?stream={STREAM}&limit=100", "github.create_issue")
    for expected in (
        "github.delete_repo",
        "prohibited",
        "attempted",
        "consequential",
        "applied",
        "aggregate",
        "gateway.session_open",
        "human:ivan",
    ):
        assert expected in audit, f"the audit explorer does not show {expected!r}"

    # The attempted-prohibited view is front and centre, on its own page and on the overview.
    attempts = await_console(world, "/console/attempts", "github.delete_repo")
    assert "Prohibited</span> actions attempted" in attempts
    overview = await_console(world, "/console", "github.delete_repo")
    assert "prohibited attempts" in overview

    # -- 2. the chain verifies through the console's own path -----------------------------------

    status, verification = console(world, f"/console/streams/{STREAM}/verify")
    assert status == 200, verification
    assert "VALID" in verification and "INVALID" not in verification, verification

    # -- 3. the mandate chain walks to the named human root -------------------------------------

    status, exported = console(world, f"/console/audit/export?stream={STREAM}&limit=100")
    assert status == 200
    records = [json.loads(line) for line in exported.splitlines() if line]
    applied_id = next(
        record["id"]
        for record in records
        if record["envelope"].get("execution", {}).get("action") == "github.create_issue"
    )

    status, detail = console(world, f"/console/envelopes/{applied_id}")
    assert status == 200, detail
    assert "On whose authority" in detail
    assert kernel.human_root.subject in detail, "the walk must terminate at the named human"
    assert "standing" in detail, "the standing mandate is the link that reaches the root"
    assert "approve by" in detail, "the approval that let the call proceed is on the page"

    # -- 4. the pending list renders, and names what it cannot see ------------------------------

    status, pending = console(world, "/console/pending")
    assert status == 200, pending
    assert "Pending approvals" in pending
    # Display only at S3: no control on the page can submit anything.
    assert "<form" not in pending.lower()
    assert "ADR-0007" in pending, "the S4 boundary is stated on the page, not left implicit"

    # -- 5. the mandate registry surfaces the standing rule and its expiry ----------------------

    status, registry = console(world, "/console/mandates")
    assert status == 200, registry
    assert "agent:claude-code/test-mbp" in registry
    assert "standing" in registry
    assert kernel.human_root.subject in registry


async def test_a_revoked_mandate_is_refused_before_the_downstream_call(world: dict[str, Any]) -> None:
    """The ADR-0007 §1 gap, closed and proved from outside the gateway's process.

    The witness is the downstream server's own log. "Refused" is a claim the gateway makes about
    itself; "never asked" is a fact recorded by a different process.
    """
    kernel: Kernel = world["kernel"]

    # First, prove the same call *does* reach the downstream server under this mandate. Without
    # this the refusal below would prove only that something was broken.
    async with agent_for(world, REVOKED_CALLER) as agent:
        allowed = await agent.call("github__get_file_contents", path="before-revocation")
        assert "contents of before-revocation" in text_of(allowed)
    before = downstream_calls(world)
    assert before.count("get_file_contents") >= 1

    # The named human revokes the mandate. This is an ordinary signed envelope through ordinary
    # ingest — there is no revocation API and no privileged channel.
    submit_revocation(kernel, world["revoked_mandate_ref"])
    status, feed = console(world, "/console/mandates")
    assert status == 200
    assert "revoked" in feed, "the console shows the revocation"

    # A new session pulls the feed at first use. The call is refused *before* forwarding.
    async with agent_for(world, REVOKED_CALLER) as agent:
        refused = refusal_of(await agent.call("github__get_file_contents", path="after-revocation"))
    assert refused["result"] == "blocked"
    assert refused["reason-code"] == "mandate-revoked"

    after = downstream_calls(world)
    assert after == before, (
        "the downstream server was invoked after the mandate was revoked: "
        f"{after[len(before) :]!r} — this is detection, not prevention"
    )

    # The refusal is audited. The gateway's own record of it cites the revoked mandate, so the
    # kernel refuses *that* envelope too (§03 §7 — correctly: an effect emitted after T is invalid).
    # The record therefore lands in the kernel's rejection stream, which is chained, signed, and
    # visible in the console. Nothing is lost and nothing is hidden.
    rejections = await_console(world, "/console/rejections", "mandate-revoked")
    assert "Refused submissions" in rejections
    assert "VALID" in rejections, "the rejection chain itself verifies"


async def test_no_console_page_answers_a_credential_free_request(world: dict[str, Any]) -> None:
    """The console is not a second, softer door into the audit trail."""
    kernel: Kernel = world["kernel"]
    for path in ("/console", "/console/audit", "/console/mandates", "/v1/revocations"):
        try:
            with urllib.request.urlopen(f"{kernel.url}{path}", timeout=5.0) as response:
                raise AssertionError(f"{path} answered {response.status} without a credential")
        except urllib.error.HTTPError as e:
            assert e.code == 401, f"{path} answered {e.code}"

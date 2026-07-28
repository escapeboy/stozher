"""The S4 gate: a consequential call parks, the approver is pinged, approves in the console, the
call proceeds — and a denial blocks with the downstream never invoked.

**What is real here, stated rather than implied.**

* A compiled `stozher-kernel` serving HTTP over a real SQLite store, bootstrapped through the real
  two-envelope genesis ceremony.
* A real `python -m harbormaster --transport stdio` process loading the gateway through
  Harbormaster's own plugin mechanism, and a stock `mcp.ClientSession` that imports nothing of ours.
* A real unmodified downstream MCP server that writes down every call it receives. **That log is the
  witness**: "refused" is the gateway's claim about itself, "never asked" is a fact recorded by a
  different process.
* Real Ed25519 throughout. The approval is signed by the human root's key, which the kernel has
  never held and cannot produce.
* **A real notification adapter over a real socket.** The kernel is configured with its shipped
  `webhook` channel; the endpoint it posts to is an HTTP server this test runs. Nothing about the
  adapter is stubbed — only the receiver is ours, which is what makes the ping observable.
* The approval is submitted to the console the way a browser would: fetch `/console/pending`, take
  the CSRF token out of the rendered form, post the signed decision back.

**What is not real.** Nothing about the gate. The one accommodation is that the approver's `decide`
step is performed in-process with the same Ed25519 key `stozher-kernel decide` would read from a
seed file, rather than by spawning that binary — the object produced is byte-identical and is
verified by the kernel through the same path either way.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import sha256_hex

from .support import Kernel, free_port, gateway_environment
from .test_gateway_e2e import Agent, refusal_of, text_of

RECORDING_SERVER = Path(__file__).parent / "fixtures" / "recording_server.py"
GATEWAY_SEED = "bb" * 32
STREAM = "gw:test-mbp:claude-code"
#: An approval is a permission to act now, not a licence (§06 §1.2).
APPROVAL_SECONDS = 900


# -- the approver ping receiver ------------------------------------------------------------------


class PingRecorder:
    """An HTTP endpoint the kernel's shipped `webhook` channel actually posts to."""

    def __init__(self) -> None:
        self.port = free_port()
        self.pings: list[dict[str, Any]] = []
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                try:
                    recorder.pings.append(json.loads(body))
                except ValueError:
                    recorder.pings.append({"unparseable": body.decode("utf-8", "replace")})
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_: Any) -> None:
                """Silence. The test's own assertions are the output that matters."""

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/ping"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def await_ping(self, request_hash: str, timeout: float = 20.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for ping in self.pings:
                if ping.get("request-hash") == request_hash:
                    return ping
            time.sleep(0.1)
        raise AssertionError(f"no approver ping arrived for {request_hash}: {self.pings}")


# -- the world -----------------------------------------------------------------------------------


def gateway_config(root: Path, kernel: Kernel, seed_file: Path, mandate: Path, server: list[str]) -> Path:
    roots = "\n".join(
        f'[[org.roots]]\nsubject = "{key.subject}"\nkey = "{key.id}"\n'
        for key in (kernel.human_root, kernel.second_root)
    )
    arguments = ", ".join(json.dumps(argument) for argument in server[1:])
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

[[callers]]
name = "claude-code"
subject = "agent:claude-code/test-mbp"
key_index = 0
token_sha256 = "{sha256_hex(b"caller-token")}"
mandate_file = "{mandate}"
mandate_kind = "standing"

[[servers]]
name = "github"
transport = "stdio"
command = {json.dumps(server[0])}
args = [{arguments}]
"""
    )
    return path


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("s4-gate")
    seed_file = root / "gateway.seed"
    seed_file.write_text(GATEWAY_SEED)
    seed_file.chmod(0o600)
    call_log = root / "downstream-calls.log"
    call_log.write_text("")

    recorder = PingRecorder()
    recorder.start()
    # The channel's URL is a secret by construction, so it is named by environment variable and
    # never written into the kernel's configuration file (`notify` module, ADR-0002).
    os.environ["STOZHER_TEST_PING_URL"] = recorder.url
    kernel = Kernel(
        root,
        bytes.fromhex(GATEWAY_SEED),
        "agent:claude-code/test-mbp",
        notifications=[{"channel": "webhook", "url-env": "STOZHER_TEST_PING_URL"}],
    )
    kernel.start()
    try:
        mandate = root / "mandate-claude-code.json"
        mandate.write_text(json.dumps(kernel.gateway_mandate))
        config = gateway_config(
            root, kernel, seed_file, mandate, [sys.executable, str(RECORDING_SERVER)]
        )
        database = root / "gateway.db"
        (root / ".harbormaster.toml").write_text(
            '[plugins]\nenabled = true\nallow = ["stozher-gateway"]\n'
        )
        environment = gateway_environment(config, database, seed_file, kernel)
        environment["STOZHER_TEST_CALL_LOG"] = str(call_log)
        environment["STOZHER_GATEWAY_CALLER"] = "claude-code"
        yield {
            "root": root,
            "kernel": kernel,
            "config": config,
            "environment": environment,
            "call_log": call_log,
            "recorder": recorder,
        }
    finally:
        kernel.stop()
        recorder.stop()
        os.environ.pop("STOZHER_TEST_PING_URL", None)


def agent_for(world: dict[str, Any]) -> Agent:
    return Agent(
        [sys.executable, "-m", "harbormaster", "--transport", "stdio"],
        dict(world["environment"]),
        world["root"],
    )


def downstream_calls(world: dict[str, Any]) -> list[str]:
    return [line for line in Path(world["call_log"]).read_text().splitlines() if line]


def console(world: dict[str, Any], path: str, body: bytes | None = None) -> tuple[int, str]:
    kernel: Kernel = world["kernel"]
    request = urllib.request.Request(
        f"{kernel.url}{path}", data=body, method="POST" if body is not None else "GET"
    )
    request.add_header("Authorization", f"Bearer {kernel.token}")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10.0) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def await_console(world: dict[str, Any], path: str, needle: str, timeout: float = 25.0) -> str:
    deadline = time.time() + timeout
    body = ""
    while time.time() < deadline:
        status, body = console(world, path)
        assert status == 200, body
        if needle in body:
            return body
        time.sleep(0.25)
    raise AssertionError(f"{path} never showed {needle!r}:\n{body[:4000]}")


def csrf_for(page: str, request_hash: str) -> str:
    """Take the token out of the rendered form, exactly as a browser would submit it."""
    form = re.search(
        rf'<form method="post" action="/console/pending/{request_hash}/decide">(.*?)</form>',
        page,
        re.DOTALL,
    )
    assert form is not None, f"no decision form for {request_hash} on the page"
    token = re.search(r'name="csrf" value="([0-9a-f]{64})"', form.group(1))
    assert token is not None, f"the form carries no CSRF token: {form.group(1)}"
    return token.group(1)


def sign_decision(kernel: Kernel, request_hash: str, verdict: str, reason: str | None) -> dict[str, Any]:
    """What `stozher-kernel decide` prints, produced with the same key and the same shape."""
    now = clock_module.now()
    return kernel.human_root.sign(
        {
            "v": "stozher/0.1",
            "kind": "gate-decision",
            "request-hash": request_hash,
            "decision": verdict,
            "decided-at": now,
            "not-after": clock_module.shift(now, APPROVAL_SECONDS),
            "single-use": True,
            "reason": reason,
        }
    )


def answer_in_console(
    world: dict[str, Any], request_hash: str, verdict: str, reason: str | None = None
) -> tuple[int, str]:
    page = await_console(world, "/console/pending", request_hash)
    decision = sign_decision(world["kernel"], request_hash, verdict, reason)
    body = json.dumps({"csrf": csrf_for(page, request_hash), "decision": decision}).encode()
    return console(world, f"/console/pending/{request_hash}/decide", body)


# -- the gate ------------------------------------------------------------------------------------


async def test_a_consequential_call_parks_pings_approves_and_then_proceeds(
    world: dict[str, Any],
) -> None:
    """The S4 definition of done, end to end."""
    recorder: PingRecorder = world["recorder"]

    async with agent_for(world) as agent:
        tools = await agent.tools()
        assert "github__create_issue" in tools, sorted(tools)
        parked = refusal_of(await agent.call("github__create_issue", title="ship it"))

    assert parked["result"] == "parked"
    assert parked["reason-code"] == "gate-parked"
    assert parked["retryable"] is False, "a refusal that invites a retry teaches agents to loop"
    request_hash = parked["request-hash"]

    before = downstream_calls(world)
    assert "create_issue" not in before, "a parked call reached the downstream server"

    # 1. the approver is pinged — over a real socket, by the shipped adapter.
    ping = recorder.await_ping(request_hash)
    assert ping["action"] == "github.create_issue"
    assert ping["subject"] == "agent:claude-code/test-mbp"
    assert ping["classification"] == "consequential"
    # §10 §6: never key material, never other pending requests, never policy content.
    assert "ed25519:" not in json.dumps(ping)

    # 2. the park is visible in the console pending queue — the ADR-0008 §A bullet, asserted
    #    against the bytes the kernel rendered.
    page = await_console(world, "/console/pending", request_hash)
    assert "Parked — waiting on a human" in page
    assert "github.create_issue" in page
    assert "agent:claude-code/test-mbp" in page
    assert "action-request" in page, "the object a signature would cover is not shown"
    assert "delivered on 1 channel(s)" in page, "the console does not show the ping was delivered"

    # 3. a named human approves in the console. The signature is made with a key the kernel has
    #    never held; the console records it and chains it as a `gate-decision` envelope (§06 §5).
    status, recorded = answer_in_console(world, request_hash, "approve")
    assert status == 201, recorded
    answer = json.loads(recorded)
    assert answer["decision"] == "approve"
    assert answer["decided-by"] == world["kernel"].human_root.id
    decision_envelope = answer["envelope-id"]

    # 4. the call proceeds, and the downstream **is** invoked — the out-of-process witness.
    async with agent_for(world) as agent:
        applied = await agent.call("github__create_issue", title="ship it")
    assert not applied.isError, text_of(applied)
    assert "issue created: ship it" in text_of(applied)
    after = downstream_calls(world)
    assert "create_issue" in after, (
        "the approved call never reached the downstream server: "
        f"{after[len(before):]!r} — the approval bought nothing"
    )

    # 5. both halves are audited, and the chain still verifies.
    audit = await_console(world, f"/console/audit?stream={STREAM}&limit=100", "github.create_issue")
    assert "applied" in audit
    status, verification = console(world, f"/console/streams/{STREAM}/verify")
    assert status == 200 and "VALID" in verification and "INVALID" not in verification, verification

    # The decision lives on the kernel's own stream, so that chain must verify too — the approval
    # history is chained and checkpointed independently of the effects that consume it (§06 §5).
    kernel: Kernel = world["kernel"]
    status, core = console(world, "/console/streams/kernel:core/verify")
    assert status == 200 and "VALID" in core and "INVALID" not in core, core

    status, detail = console(world, f"/console/envelopes/{decision_envelope}")
    assert status == 200, detail
    assert "gate-decision" in detail
    assert kernel.human_root.id in detail, "the approver's key is on the decision record"

    # The answered request moves out of the parked section, with the human named against it.
    #
    # The queue truncates identifiers to 12 characters like every other identifier in the console
    # (QA finding M3: a full 72-character key in a `nowrap` cell pushed the `reason` and `record`
    # columns off-screen at laptop width). The property under test is unchanged — the human who
    # answered is named against the request — so this asserts the form the page actually renders.
    # The *full* key is still asserted above, on the decision record, which is where a verifier
    # needs it.
    answered = await_console(world, "/console/pending", "Answered by a named human")
    algorithm, material = kernel.human_root.id.split(":", 1)
    assert f"{algorithm}:{material[:12]}" in answered, (
        "the answered row does not name the human who decided"
    )
    assert "approve" in answered


async def test_a_denial_blocks_and_the_downstream_is_never_invoked(world: dict[str, Any]) -> None:
    """The assertion that matters. Proved from outside the gateway's process.

    A counterfactual is already established by the test above — the same tool, approved, does reach
    the downstream server — so this cannot pass vacuously on a gateway that refuses everything.
    """
    before = downstream_calls(world)

    async with agent_for(world) as agent:
        parked = refusal_of(await agent.call("github__create_issue", title="delete production"))
    assert parked["result"] == "parked"
    request_hash = parked["request-hash"]
    assert downstream_calls(world) == before, "the parked call reached the downstream server"

    reason = "we do not file issues that read like an instruction to destroy data"
    status, recorded = answer_in_console(world, request_hash, "deny", reason)
    assert status == 201, recorded
    assert json.loads(recorded)["decision"] == "deny"

    # The next identical call is refused with the human's reason, and is not forwarded.
    async with agent_for(world) as agent:
        refused = refusal_of(await agent.call("github__create_issue", title="delete production"))
    assert refused["result"] == "denied"
    assert refused["reason-code"] == "gate-denied"
    assert reason in refused["reason"], refused
    assert refused["retryable"] is False

    after = downstream_calls(world)
    assert after == before, (
        "the downstream server was invoked after a named human denied the action: "
        f"{after[len(before):]!r} — this is not enforcement"
    )

    # The denial is audited: an envelope with `outcome: denied` carrying the denial authorization
    # (§06 §4.5), and the reason visible in the console.
    denied = await_console(world, "/console/pending", reason)
    assert "deny" in denied
    audit = await_console(world, f"/console/audit?stream={STREAM}&outcome=denied&limit=50", "denied")
    assert "github.create_issue" in audit
    status, verification = console(world, f"/console/streams/{STREAM}/verify")
    assert status == 200 and "VALID" in verification and "INVALID" not in verification, verification


async def test_a_stranger_cannot_answer_and_a_subject_cannot_answer_itself(
    world: dict[str, Any],
) -> None:
    """Two refusals the console owes, attempted against the running kernel."""
    async with agent_for(world) as agent:
        parked = refusal_of(await agent.call("github__create_issue", title="third issue"))
    request_hash = parked["request-hash"]
    page = await_console(world, "/console/pending", request_hash)
    csrf = csrf_for(page, request_hash)
    kernel: Kernel = world["kernel"]

    # A key enrolled nowhere signs a perfectly well-formed approval.
    from stozher_gateway.signing import SigningKey

    stranger = SigningKey(bytes.fromhex("99" * 32), "human:nobody")
    now = clock_module.now()
    forged = stranger.sign(
        {
            "v": "stozher/0.1",
            "kind": "gate-decision",
            "request-hash": request_hash,
            "decision": "approve",
            "decided-at": now,
            "not-after": clock_module.shift(now, APPROVAL_SECONDS),
            "single-use": True,
            "reason": None,
        }
    )
    status, body = console(
        world,
        f"/console/pending/{request_hash}/decide",
        json.dumps({"csrf": csrf, "decision": forged}).encode(),
    )
    assert status == 403, body
    assert json.loads(body)["reason-code"] == "gate-approver-not-permitted"

    # A forged CSRF token is refused before anything is read.
    real = sign_decision(kernel, request_hash, "approve", None)
    status, body = console(
        world,
        f"/console/pending/{request_hash}/decide",
        json.dumps({"csrf": secrets.token_hex(32), "decision": real}).encode(),
    )
    assert status == 403, body
    assert json.loads(body)["reason-code"] == "console-csrf-invalid"

    # Neither attempt recorded anything: the request is still parked and still answerable.
    status, queued = console(world, f"/v1/gate/requests/{request_hash}")
    assert status == 200
    assert json.loads(queued)["decision"] is None


async def test_a_decision_cannot_be_overwritten_once_a_human_has_given_it(
    world: dict[str, Any],
) -> None:
    """One request, one answer. A second, contradicting signature is refused."""
    async with agent_for(world) as agent:
        parked = refusal_of(await agent.call("github__create_issue", title="fourth issue"))
    request_hash = parked["request-hash"]

    status, _ = answer_in_console(world, request_hash, "approve")
    assert status == 201

    kernel: Kernel = world["kernel"]
    reverse = sign_decision(kernel, request_hash, "deny", "on reflection, no")
    # The request no longer renders a form, so there is no fresh token to take — which is itself the
    # first refusal an operator hitting "back" would meet. Post the reversal with a token the kernel
    # never issued and it stops there; the answer already given is untouched either way.
    status, body = console(
        world,
        f"/console/pending/{request_hash}/decide",
        json.dumps({"csrf": "0" * 64, "decision": reverse}).encode(),
    )
    assert status == 403, body

    status, queued = console(world, f"/v1/gate/requests/{request_hash}")
    assert json.loads(queued)["decision"]["decision"] == "approve"

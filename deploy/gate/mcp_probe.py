"""A minimal MCP client over stdio, in the standard library and nothing else.

This exists so the gate drives the **exact command the install documentation tells a design partner
to paste**, rather than something equivalent to it. MCP over stdio is newline-delimited JSON-RPC, so
a client is a hundred lines of `subprocess` and `json` — and writing it that way means the gate has
no dependency the operator does not already have, and no way to accidentally test a different code
path because a convenience library reconnected, retried or normalized something.

The agent side imports nothing from `stozher_gateway` and knows nothing about Stozher. That is the
same property S2's gate asserts by parsing its own AST: a foreign agent, unmodified.

Usage:
    python3 mcp_probe.py --call notes__write_note --args '{"name":"x","body":"y"}' -- <server cmd...>

Prints one JSON object per line: `{"event": "...", ...}`, so the caller can `grep` for what it needs
without parsing prose.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from typing import Any

PROTOCOL = "2024-11-05"


class Server:
    """A stdio MCP server as a subprocess, spoken to in JSON-RPC."""

    def __init__(self, command: list[str]) -> None:
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self._next_id = 0
        # The server's stderr is where a refusal to start says why. Draining it on a thread keeps
        # a chatty server from filling the pipe and deadlocking, and keeps the reason visible.
        self._stderr: list[str] = []
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._stderr.append(line.decode("utf-8", "replace").rstrip())

    def _send(self, message: dict[str, Any]) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write((json.dumps(message) + "\n").encode())
        self._process.stdin.flush()

    def _receive(self, expect_id: int) -> dict[str, Any]:
        assert self._process.stdout is not None
        while True:
            line = self._process.stdout.readline()
            if not line:
                tail = "\n".join(self._stderr[-25:])
                raise RuntimeError(f"the server closed its output. stderr:\n{tail}")
            try:
                message = json.loads(line)
            except ValueError:
                continue  # not a JSON-RPC frame; some servers greet on stdout.
            if message.get("id") == expect_id:
                return message

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        message = self._receive(request_id)
        if "error" in message:
            raise RuntimeError(f"{method}: {message['error']}")
        return dict(message.get("result") or {})

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": {}})

    def close(self) -> None:
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
            self._process.wait(timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            self._process.kill()


def emit(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--call", action="append", default=[], help="tool name to call")
    parser.add_argument("--args", action="append", default=[], help="JSON arguments per --call")
    parser.add_argument("server", nargs=argparse.REMAINDER)
    parsed = parser.parse_args()
    command = [a for a in parsed.server if a != "--"]
    if not command:
        sys.exit("no server command given")

    server = Server(command)
    try:
        server.call(
            "initialize",
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "stozher-gate-probe", "version": "0.1.0"},
            },
        )
        server.notify("notifications/initialized")
        tools = sorted(t["name"] for t in server.call("tools/list").get("tools", []))
        emit("tools", tools=tools)

        for index, name in enumerate(parsed.call):
            arguments = json.loads(parsed.args[index]) if index < len(parsed.args) else {}
            result = server.call("tools/call", {"name": name, "arguments": arguments})
            text = "".join(
                block.get("text", "")
                for block in result.get("content", [])
                if isinstance(block, dict)
            )
            # A structured refusal is JSON inside the error text. Surfacing it parsed is what lets
            # the gate assert on `reason-code` rather than on a substring of a sentence.
            refusal: dict[str, Any] | None = None
            start = text.find("{")
            if result.get("isError") and start >= 0:
                try:
                    refusal = json.loads(text[start:])
                except ValueError:
                    refusal = None
            emit(
                "call",
                tool=name,
                is_error=bool(result.get("isError")),
                text=text[:600],
                refusal=refusal,
            )
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""A downstream MCP server that writes down every invocation it receives.

Identical in shape to `downstream_server.py` — stock FastMCP, no Stozher awareness — with one
addition: each tool appends its name to the file named by `STOZHER_TEST_CALL_LOG` before returning.

That file is the witness the S3 gate needs. "The gateway refused the call" is a claim about the
gateway; "the downstream server was never asked" is a fact about the world, and it is the only way
to tell prevention from detection from outside the gateway's own process.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-github")


def _record(tool: str) -> None:
    log = os.environ.get("STOZHER_TEST_CALL_LOG")
    if log:
        with Path(log).open("a", encoding="utf-8") as handle:
            handle.write(f"{tool}\n")


@mcp.tool()
def get_file_contents(path: str) -> str:
    """Return the contents of a file."""
    _record("get_file_contents")
    return f"contents of {path}"


@mcp.tool()
def create_issue(title: str, body: str = "") -> str:
    """Open an issue."""
    _record("create_issue")
    return f"issue created: {title}"


@mcp.tool()
def delete_repo(repo: str) -> str:
    """Delete a repository. Should never be reached through the gateway."""
    _record("delete_repo")
    return f"deleted {repo}"


@mcp.tool()
def echo_note(note: str) -> str:
    """Echo a note back. Deliberately absent from every catalog."""
    _record("echo_note")
    return f"note: {note}"


if __name__ == "__main__":
    mcp.run()

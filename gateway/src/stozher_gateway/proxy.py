"""The MCP client side: the gateway is also an MCP client, fronting configured downstream servers.

ADR-0004: Harbormaster has no client-side proxy path to wrap, so this path is authored rather than
extended. Two constraints from the reconnaissance shape it:

* the async session lives on the gateway's own background loop, because the tool handlers that use
  it must be sync (`docs/gateway-integration-constraints.md` §2);
* under stdio, one process is spawned **per client connection** (`__main__.py:306-308`), so
  long-lived downstream sessions would duplicate per session and leak threads. The default is
  therefore a lazy per-call connection, and persistence is an explicit opt-in the same way
  `bridge_in_stdio` is.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from typing import Any

from .background import BackgroundLoop
from .config import ServerConfig

__all__ = ["Downstream", "DownstreamTool"]

logger = logging.getLogger(__name__)


class DownstreamTool:
    """A tool as the upstream server declares it."""

    def __init__(self, name: str, description: str, schema: dict[str, Any]) -> None:
        self.name = name
        self.description = description
        self.schema = schema


class Downstream:
    """One downstream MCP server."""

    def __init__(
        self,
        config: ServerConfig,
        loop: BackgroundLoop,
        persistent: bool,
        timeout: float = 30.0,
    ) -> None:
        self.config = config
        self._loop = loop
        self._persistent = persistent
        self._timeout = timeout
        self._session: Any = None
        self._closing: asyncio.Event | None = None
        self._ready: asyncio.Event | None = None
        self._runner: asyncio.Task[None] | None = None

    # -- transport ------------------------------------------------------------------------

    def _streams(self, stack: AsyncExitStack) -> Any:
        if self.config.transport == "stdio":
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client

            environment = dict(os.environ)
            environment.update(self.config.env)
            parameters = StdioServerParameters(
                command=self.config.command or "",
                args=list(self.config.args),
                env=environment,
            )
            return stack.enter_async_context(stdio_client(parameters))
        from mcp.client.streamable_http import streamablehttp_client

        headers = {}
        if self.config.token_env:
            token = os.environ.get(self.config.token_env)
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return stack.enter_async_context(
            streamablehttp_client(self.config.url or "", headers=headers)
        )

    async def _open_session(self, stack: AsyncExitStack) -> Any:
        from mcp import ClientSession

        streams = await self._streams(stack)
        read, write = streams[0], streams[1]
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return session

    async def _serve(self) -> None:
        """Hold a persistent session open. Entered and exited in one task, as anyio requires."""
        assert self._ready is not None and self._closing is not None
        try:
            async with AsyncExitStack() as stack:
                self._session = await self._open_session(stack)
                self._ready.set()
                await self._closing.wait()
        except Exception:  # noqa: BLE001 - a downstream that dies must not take the gateway with it
            logger.exception("the downstream session for %s ended", self.config.name)
        finally:
            self._session = None
            self._ready.set()

    def start(self) -> None:
        """Open the persistent session, if this instance is persistent."""
        if not self._persistent or self._runner is not None:
            return

        async def _launch() -> None:
            self._ready = asyncio.Event()
            self._closing = asyncio.Event()
            self._runner = asyncio.ensure_future(self._serve())
            await self._ready.wait()

        self._loop.run(_launch(), timeout=self._timeout)

    def close(self) -> None:
        if self._closing is None:
            return
        closing = self._closing

        async def _signal() -> None:
            closing.set()

        self._loop.submit(_signal())
        self._runner = None
        self._closing = None

    # -- operations ------------------------------------------------------------------------

    async def _with_session(self, work: Any) -> Any:
        if self._session is not None:
            return await work(self._session)
        async with AsyncExitStack() as stack:
            session = await self._open_session(stack)
            return await work(session)

    def list_tools(self) -> list[DownstreamTool]:
        """Discover the tools to re-export. Raises if the server cannot be reached."""

        async def work(session: Any) -> list[DownstreamTool]:
            listed = await session.list_tools()
            return [
                DownstreamTool(tool.name, tool.description or "", dict(tool.inputSchema or {}))
                for tool in listed.tools
            ]

        result: list[DownstreamTool] = self._loop.run(
            self._with_session(work), timeout=self._timeout
        )
        return result

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Forward one call and return the upstream result, unchanged."""

        async def work(session: Any) -> Any:
            return await session.call_tool(tool, arguments)

        result = self._loop.run(self._with_session(work), timeout=self._timeout)
        return _unwrap(result)


def _unwrap(result: Any) -> Any:
    """Turn an MCP `CallToolResult` into the value a sync tool handler returns.

    Content passes through verbatim: the gateway is zero-touch, so it never rewrites or summarizes
    an upstream result. An upstream error is re-raised as an error, not converted into a success.
    """
    if getattr(result, "isError", False):
        raise RuntimeError(_text(result) or "the upstream tool reported an error")
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured
    text = _text(result)
    if text is not None:
        return text
    return [item.model_dump(mode="json") for item in getattr(result, "content", [])]


def _text(result: Any) -> str | None:
    parts = [item.text for item in getattr(result, "content", []) if getattr(item, "text", None)]
    return "\n".join(parts) if parts else None

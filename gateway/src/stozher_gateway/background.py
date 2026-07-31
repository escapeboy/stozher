"""A persistent background event loop in a daemon thread, and the bridge to it.

Every Harbormaster tool is a **sync** `def`, and two dispatch sites call `tool.fn(**arguments)`
without awaiting it (`fleetq/dispatcher.py:626`, `ui/routes.py:2752`). An `async def` tool returns an
un-awaited coroutine there — a garbage envelope and a `RuntimeWarning`, not an error anyone sees.
So the gateway registers sync handlers, and the async MCP client they need lives on a loop this
module owns.

`asyncio.run()` inside a tool is not an alternative: on the stdio and HTTP paths the tool is already
running inside a loop, so it raises — and a long-lived downstream session cannot be owned by a
per-call loop anyway.

The lifecycle shape is Harbormaster's own (`jobs/worker.py:115-129`, `fleetq/heartbeat.py:125-137`):
`threading.Event` plus a daemon thread, `.stop(timeout=...)` that joins, and teardown from a
`finally` block.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

__all__ = ["BackgroundLoop"]

T = TypeVar("T")


class BackgroundLoop:
    """Owns one asyncio loop on a daemon thread; sync callers bridge with `run`."""

    def __init__(self, name: str = "stozher-gateway-loop") -> None:
        self._name = name
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the loop thread if it is not already running. Idempotent."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._ready.clear()
            self._thread = threading.Thread(target=self._serve, name=self._name, daemon=True)
            self._thread.start()
        if not self._ready.wait(timeout=10.0):
            raise RuntimeError("the gateway's background loop did not start")

    def _serve(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.call_soon(self._ready.set)
            loop.run_forever()
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            finally:
                loop.close()
                self._loop = None

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            raise RuntimeError("the gateway's background loop is not running")
        return self._loop

    def run(self, coroutine: Coroutine[Any, Any, T], timeout: float) -> T:
        """Run `coroutine` on the background loop and wait, with a hard bound.

        The bound is not optional: a sync tool blocks the MCP server's own loop while it waits, so an
        unbounded wait here stalls every concurrent call including Harbormaster's.

        Timing out abandons the *wait*, not the work: without the cancel below the coroutine goes on
        running, and in the default non-persistent mode it is holding an `AsyncExitStack` around a
        freshly spawned `stdio_client` — so a downstream that accepts a call and never answers leaves
        a task, a child process and its pipes behind on every call, accumulating for the life of the
        connection.
        """
        self.start()
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            # The future is still pending, so this succeeds and propagates to the task, which
            # unwinds the exit stack and reaps the child.
            future.cancel()
            raise

    def submit(self, coroutine: Coroutine[Any, Any, Any]) -> None:
        """Schedule `coroutine` and do not wait for it."""
        self.start()
        asyncio.run_coroutine_threadsafe(coroutine, self.loop)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the loop and join the thread."""
        with self._lock:
            thread, loop = self._thread, self._loop
            self._thread = None
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=timeout)
        self._ready.clear()

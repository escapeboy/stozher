"""Two resources the gateway shares with something it cannot see: a hung downstream and a stream.

Both defects here are of the same shape as the gate ones — a guarantee that holds inside one process
and was assumed to hold outside it. Neither is caught by `spec/vectors/`, which tests pure functions;
these are properties of the runtime.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.background import BackgroundLoop
from stozher_gateway.canonical import object_hash
from stozher_gateway.config import GatewayConfig
from stozher_gateway.emitter import Emitter
from stozher_gateway.kernel_client import KernelClient
from stozher_gateway.signing import SigningKey
from stozher_gateway.store import GatewayStore

# -- a downstream that accepts a call and never answers (§10, ADR-0004) ---------------------------


def test_a_timed_out_call_does_not_leave_its_coroutine_running() -> None:
    """`future.result(timeout=...)` abandons the wait, not the work.

    In the default non-persistent mode the abandoned coroutine is holding an `AsyncExitStack` around
    a freshly spawned `stdio_client`, so what survives it is a task, a child process and its pipes —
    once per call, for the life of the connection.
    """
    started = threading.Event()
    cancelled = threading.Event()

    async def hangs() -> None:
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def live_tasks() -> int:
        return len([task for task in asyncio.all_tasks() if not task.done()])

    loop = BackgroundLoop("test-reaping")
    try:
        with pytest.raises(concurrent.futures.TimeoutError):
            loop.run(hangs(), timeout=0.2)
        assert started.is_set(), "the coroutine never ran, so the test proves nothing"
        assert cancelled.wait(timeout=5.0), "the abandoned coroutine was never cancelled"
        # `live_tasks` counts itself, so one is the floor.
        remaining = asyncio.run_coroutine_threadsafe(live_tasks(), loop.loop).result(timeout=5.0)
        assert remaining == 1, f"{remaining - 1} task(s) outlived the call that gave up on them"
    finally:
        loop.stop()


def test_the_downstream_timeout_is_configurable() -> None:
    """It was `Downstream.__init__`'s default and nothing could reach it (`runtime.register`)."""
    config = GatewayConfig.model_validate({"gateway": {"downstream_timeout_seconds": 2.5}})
    assert config.gateway.downstream_timeout_seconds == 2.5
    assert GatewayConfig().gateway.downstream_timeout_seconds == 30.0
    with pytest.raises(ValueError, match="downstream_timeout_seconds"):
        GatewayConfig.model_validate({"gateway": {"downstream_timeout_seconds": 0}})


# -- one stream, two writers that cannot see each other (§04 §2, §07) -----------------------------


def _effect(key: SigningKey, n: int) -> dict[str, Any]:
    now = clock_module.now()
    payload_hash = object_hash({"n": n})
    return {
        "v": "stozher/0.1",
        "kind": "effect",
        "emitted-at": now,
        "identity": {"subject": key.subject, "key": key.id, "component": "gateway"},
        "mandate-ref": "a" * 64,
        "policy-version": "2026.07.1",
        "classification": "consequential",
        "execution": {
            "action": "github.create_issue",
            "target": "mcp:github",
            "args-hash": payload_hash,
            "outcome": "applied",
            "started-at": now,
            "finished-at": now,
        },
        "evidence": {
            "schema": "github.create_issue.v1",
            "media-type": "application/json",
            "payload-hash": payload_hash,
            "retain-until": clock_module.shift(now, 86400),
        },
    }


def test_two_writers_of_one_stream_never_collide_on_a_seq(tmp_path: Path) -> None:
    """The single-writer guarantee must hold between *processes*, not only between threads.

    A stream name is config-derived — `gw:<device>:<caller>` — and stdio spawns one process per
    client connection, so two connections of the same caller share a stream and a database file and
    nothing else. Two `GatewayStore` instances over one file is that situation exactly: separate
    connections, separate in-process locks, so an in-process lock protects neither from the other.

    Before the fix this lost ~17% of appends to `UNIQUE constraint failed: envelopes.stream,
    envelopes.seq`, which the enforcer reports as `chain-write-failed` — *after* the effect has been
    forwarded, which is precisely the ordering §09 §4's write-ahead exists to prevent.
    """
    database = tmp_path / "gateway.db"
    stream = "gw:test-mbp:claude-code"
    rounds = 150
    GatewayStore(database)
    failures: list[str] = []
    barrier = threading.Barrier(2)

    def writer(tag: int) -> None:
        emitter = Emitter(
            GatewayStore(database),
            KernelClient("http://127.0.0.1:9", None, 0.2),
            "gateway",
            max_events=10**6,
        )
        key = SigningKey(bytes.fromhex(f"{tag:02x}" * 32), "agent:claude-code/test-mbp")
        barrier.wait(timeout=10.0)
        for n in range(rounds):
            try:
                emitter.append(key, stream, _effect(key, n))
            except Exception as e:  # noqa: BLE001 - the collision is the thing under test
                failures.append(f"{type(e).__name__}: {e}")

    threads = [threading.Thread(target=writer, args=(tag,)) for tag in (0xAA, 0xBB)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120.0)
        assert not thread.is_alive(), "a writer deadlocked on the chain"

    assert failures == [], f"{len(failures)} append(s) lost a seq: {failures[:3]}"
    chained = GatewayStore(database).unpushed(limit=10**6)
    seqs = sorted(int(envelope["seq"]) for _, envelope, _ in chained)
    assert seqs == list(range(2 * rounds)), "the chain is not one contiguous run of seq values"

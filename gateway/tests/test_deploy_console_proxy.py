"""`deploy/bin/stozher-console` — the guards on the operator's header-injecting proxy.

That process binds 127.0.0.1 and attaches the kernel's `Bearer` credential to every request it
forwards, which is the whole reason it exists (ADR-0008). Binding loopback is not by itself a
boundary: an attacker page in the operator's browser reaches loopback through DNS rebinding, and the
only thing that distinguishes it from the operator's own tab is the `Host` header. The console
serves the audit trail, so "read the response" is the entire loss.

These tests drive the real server object over a real socket with the headers a rebound page sends.
The upstream port is deliberately dead: a permitted request answering `502` proves it got past the
guards, without needing a kernel.
"""

from __future__ import annotations

import http.client
import importlib.machinery
import importlib.util
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "bin" / "stozher-console"


def _load() -> ModuleType:
    """`bin/stozher-console` carries no `.py` suffix — it is a command, not a module."""
    loader = importlib.machinery.SourceFileLoader("stozher_console", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _get(port: int, headers: dict[str, str], path: str = "/console") -> tuple[int, dict[str, str]]:
    """A raw GET, so the `Host` header can be whatever an attacker's page would make it."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        response.read()
        return response.status, {name: value for name, value in response.getheaders()}
    finally:
        connection.close()


@pytest.fixture()
def proxy() -> Iterator[int]:
    module = _load()
    port = _free_port()
    upstream = f"http://127.0.0.1:{_free_port()}"  # nothing listens there, and nothing needs to
    server = module.build_server(port, upstream, "the-kernel-credential")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_a_rebound_host_header_is_refused_before_the_credential_is_spent(proxy: int) -> None:
    """The DNS-rebinding case: the socket is loopback, the origin in the browser is not."""
    status, _ = _get(proxy, {"Host": f"evil.example:{proxy}"})
    assert status == 403
    status, _ = _get(proxy, {"Host": f"evil.example:{proxy}"}, path="/console/audit?limit=10000")
    assert status == 403, "the audit trail is exactly what a rebound page would come for"


def test_the_operators_own_address_reaches_the_kernel(proxy: int) -> None:
    """The guard must not cost the operator the tool: both spellings of loopback are theirs."""
    for host in (f"127.0.0.1:{proxy}", f"localhost:{proxy}"):
        status, _ = _get(proxy, {"Host": host})
        assert status == 502, f"{host} should have been forwarded to the (dead) upstream"


def test_a_cross_origin_request_is_refused_even_from_the_right_host(proxy: int) -> None:
    """`Host` is the rebinding check; `Origin`/`Referer` catch what a browser labels itself."""
    for header in ("Origin", "Referer"):
        status, _ = _get(
            proxy, {"Host": f"127.0.0.1:{proxy}", header: "http://evil.example/some/page"}
        )
        assert status == 403, f"a foreign {header} was accepted"
    status, _ = _get(
        proxy, {"Host": f"127.0.0.1:{proxy}", "Referer": f"http://127.0.0.1:{proxy}/console"}
    )
    assert status == 502, "the operator's own page must still be able to link within the console"


def test_every_response_declines_to_be_framed_or_scripted(proxy: int) -> None:
    """Defence in depth behind the `Host` check, on refusals as well as on relayed pages."""
    for headers in ({"Host": f"127.0.0.1:{proxy}"}, {"Host": f"evil.example:{proxy}"}):
        _, received = _get(proxy, headers)
        assert received.get("X-Frame-Options") == "DENY"
        policy = received.get("Content-Security-Policy", "")
        assert "frame-ancestors 'none'" in policy
        assert "default-src 'none'" in policy

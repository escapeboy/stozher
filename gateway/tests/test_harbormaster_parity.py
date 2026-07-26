"""ADR-0005's promise, as automated checks: **a Harbormaster without a kernel loses nothing.**

The obvious reading of "ship as an enforcement mode" is impossible here. `HarbormasterConfig` applies
`ConfigDict(extra="forbid")` to every model including itself, so an `[enforcement]` section in
`harbormaster.toml` is a hard boot failure for anyone running vanilla Harbormaster. These three tests
hold the shape that makes the promise structural instead of aspirational:

1. a config that turns enforcement **on** still validates under vanilla `HarbormasterConfig`;
2. with the gateway distribution absent, `load_plugins` warns and skips — no exception, server builds;
3. with enforcement configured and the kernel unreachable, gateway tools fail **closed** and
   Harbormaster's own tools are untouched.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Any

import pytest
from harbormaster.config import HarbormasterConfig
from harbormaster.server import build_server

from stozher_gateway import plugin
from stozher_gateway.refusal import RefusalError

ENABLING_CONFIG = """
# The entire activation surface: keys Harbormaster already ships (config.py:258-266).
[plugins]
enabled = true
allow = ["stozher-gateway"]
"""


def tools_by_name(mcp: Any) -> dict[str, Any]:
    return {tool.name: tool for tool in mcp._tool_manager.list_tools()}


def test_a_gateway_enabling_config_still_validates_under_vanilla_harbormaster() -> None:
    """(1) Nothing in the activation surface is ours, so no Harbormaster can choke on it."""
    document = tomllib.loads(ENABLING_CONFIG)
    config = HarbormasterConfig.model_validate(document)
    assert config.plugins.enabled is True
    assert config.plugins.allow == ["stozher-gateway"]


def test_an_enforcement_section_in_harbormaster_toml_would_be_a_boot_failure() -> None:
    """Why (1) matters, stated as a test so nobody 'simplifies' the config surface later."""
    with pytest.raises(Exception) as refusal:
        HarbormasterConfig.model_validate(tomllib.loads("[enforcement]\nenabled = true\n"))
    assert "extra" in str(refusal.value).lower()


def test_a_missing_distribution_warns_and_skips(caplog: pytest.LogCaptureFixture) -> None:
    """(2) Uninstalling the gateway is a WARNING line, not a dead tool."""
    from harbormaster.plugins import load_plugins

    config = HarbormasterConfig.model_validate(
        tomllib.loads('[plugins]\nenabled = true\nallow = ["stozher-gateway-that-is-not-installed"]\n')
    )
    mcp = build_server(HarbormasterConfig())
    before = set(tools_by_name(mcp))
    with caplog.at_level(logging.WARNING):
        load_plugins(mcp, config)  # must not raise
    assert set(tools_by_name(mcp)) == before, "no tool appeared or vanished"
    assert any("stozher-gateway-that-is-not-installed" in record.message for record in caplog.records)


def test_enforcement_off_is_the_default_and_registers_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """With the distribution installed but `gateway.enabled` false, nothing changes at all."""
    config = tmp_path / "stozher-gateway.toml"
    config.write_text("[gateway]\nenabled = false\n")
    monkeypatch.setenv("STOZHER_GATEWAY_CONFIG", str(config))
    mcp = build_server(HarbormasterConfig())
    before = set(tools_by_name(mcp))
    with caplog.at_level(logging.INFO):
        plugin.register(mcp, HarbormasterConfig())
    assert set(tools_by_name(mcp)) == before
    assert any("enforcement mode is off" in record.message for record in caplog.records)


def test_importing_the_plugin_does_not_import_a_crypto_library() -> None:
    """Ed25519 is an optional extra, and the import graph has to prove it.

    Harbormaster's base install carries no crypto dependency at all. An unconditional import here
    would mean a bare Harbormaster with the distribution present fails at import — which is the
    opposite of "loses nothing", and is not something a `try/except` around `register()` can undo.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, stozher_gateway.plugin, stozher_gateway.runtime;"
            "print(any(name.startswith(('cryptography', 'nacl')) for name in sys.modules))",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False", result.stdout


def test_nothing_is_created_on_disk_at_import_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No import-time side effects (`docs/gateway-integration-constraints.md` §7)."""
    import subprocess
    import sys

    home = tmp_path / "home"
    home.mkdir()
    environment = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    subprocess.run(
        [sys.executable, "-c", "import stozher_gateway.plugin, stozher_gateway.store"],
        capture_output=True,
        text=True,
        check=True,
        env={**environment, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    assert list(home.iterdir()) == [], sorted(str(path) for path in home.iterdir())


def test_an_unreachable_kernel_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """(3) Enforcement configured, kernel gone: the proxied surface refuses, Harbormaster's does not.

    Failing *open* here would be the worst outcome available — an operator who asked for enforcement
    would get an ungoverned proxy and no signal at all.
    """
    seed = tmp_path / "gateway.seed"
    seed.write_text("bb" * 32)
    seed.chmod(0o600)
    config = tmp_path / "stozher-gateway.toml"
    config.write_text(
        f"""
[gateway]
enabled = true
device = "offline"

[kernel]
url = "http://127.0.0.1:9"
timeout_seconds = 0.5

[identity]
seed_file = "{seed}"

[org]
policy_key = "ed25519:{"11" * 32}"

[[org.roots]]
subject = "human:ivan"
key = "ed25519:{"22" * 32}"

[[callers]]
name = "claude-code"
subject = "agent:claude-code/offline"
token_sha256 = "{"33" * 32}"
mandate_file = "{tmp_path / "missing-mandate.json"}"

[[servers]]
name = "github"
transport = "stdio"
command = "true"
"""
    )
    monkeypatch.setenv("STOZHER_GATEWAY_CONFIG", str(config))
    monkeypatch.setenv("STOZHER_GATEWAY_DB", str(tmp_path / "gateway.db"))
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER", "claude-code")

    mcp = build_server(HarbormasterConfig())
    native = set(tools_by_name(mcp))
    with caplog.at_level(logging.ERROR):
        plugin.register(mcp, HarbormasterConfig())

    tools = tools_by_name(mcp)
    assert native <= set(tools), "Harbormaster's own tools are untouched"
    assert tools["list_projects"].fn is not None
    assert "github__unavailable" in tools, "the proxied surface exists and refuses"
    with pytest.raises(RefusalError) as refused:
        tools["github__unavailable"].fn()
    assert refused.value.document["result"] == "blocked"
    assert refused.value.document["retryable"] is False
    assert any("did not start" in record.message for record in caplog.records)

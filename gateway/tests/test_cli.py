"""The operator surface: `config check`, `catalog policy-fragment`, `pending`, `approve`, `deny`.

ADR-0005 accepted a real cost — an operator running enforcement configures two files — on the
grounds that the alternative is a boot-failure footgun. The bargain only holds if the second file's
checker is good, so its findings are asserted here rather than assumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stozher_gateway.__main__ import main as cli


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "stozher-gateway.toml"
    path.write_text(body)
    return path


def test_config_check_names_every_missing_prerequisite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("STOZHER_KERNEL_TOKEN", raising=False)
    # An address nothing can be listening on, named explicitly. The finding under test is "the
    # kernel is unreachable", and leaving the URL at its default asserted that instead against
    # `127.0.0.1:8787` — which is the port `deploy/docker-compose.yml` publishes, so this test
    # failed for anyone who had actually installed the product they were working on.
    config = write_config(
        tmp_path, '[gateway]\nenabled = true\n\n[kernel]\nurl = "http://127.0.0.1:1"\n'
    )
    assert cli(["--config", str(config), "config", "check"]) == 1
    findings = capsys.readouterr().out
    for expected in (
        "identity.seed_file",
        "org.policy_key",
        "org.roots is empty",
        "STOZHER_KERNEL_TOKEN is unset",
        "no downstream servers",
        "kernel is unreachable",
    ):
        assert expected in findings, findings


def test_config_check_names_a_downstream_it_cannot_reach(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A declared server that is down must not look like a server nobody configured.

    Its only other observable is that some tools are missing from `tools/list`, which an agent
    cannot distinguish from "never configured" and an operator sees only if they were reading the
    gateway's stderr at the moment it started.
    """
    config = write_config(
        tmp_path,
        '[gateway]\nenabled = true\n\n[kernel]\nurl = "http://127.0.0.1:1"\n\n'
        "[[servers]]\n"
        'name = "notes"\n'
        'transport = "stdio"\n'
        # A command that cannot start, so the failure is the enumeration and not a slow server.
        f'command = "{tmp_path / "there-is-no-such-binary"}"\n'
        "args = []\n",
    )
    assert cli(["--config", str(config), "config", "check"]) == 1
    findings = capsys.readouterr().out
    assert "downstream 'notes' cannot be enumerated" in findings, findings
    # And the "nothing is configured" finding is *not* raised: one server is declared. The two
    # conditions read almost identically to an operator and must not be reported interchangeably.
    assert "no downstream servers" not in findings, findings


def test_keygen_writes_owner_only_key_material_and_refuses_to_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "keys" / "gateway.seed"
    assert cli(["keygen", "--out", str(out)]) == 0
    assert len(bytes.fromhex(out.read_text())) == 32
    assert oct(out.stat().st_mode)[-3:] == "600"
    assert cli(["keygen", "--out", str(out)]) == 2, "key material is never silently overwritten"


def test_the_policy_fragment_is_what_an_org_publishes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bridge from Tier B to the kernel's own classification (see `policy.classify`)."""
    monkeypatch.setenv("STOZHER_GATEWAY_DB", str(tmp_path / "gateway.db"))
    config = write_config(
        tmp_path,
        '[gateway]\nenabled = true\n\n[[servers]]\nname = "github"\ntransport = "stdio"\ncommand = "true"\n',
    )
    assert cli(["--config", str(config), "catalog", "policy-fragment"]) == 0
    fragment = json.loads(capsys.readouterr().out)["by-action"]
    assert fragment["github.get_file_contents"] == "read"
    assert fragment["github.create_issue"] == "consequential"
    assert fragment["github.delete_repo"] == "prohibited"
    assert not any(key.startswith("slack.") for key in fragment), "only servers this gateway fronts"


def test_an_unenrolled_approver_is_refused_before_it_can_sign(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An approver is a named human the organization enrolled (§06 §5)."""
    monkeypatch.setenv("STOZHER_GATEWAY_DB", str(tmp_path / "gateway.db"))
    config = write_config(tmp_path, "[gateway]\nenabled = true\n")
    key = tmp_path / "stranger.seed"
    key.write_text("ee" * 32)
    code = cli(
        [
            "--config",
            str(config),
            "approve",
            "--request",
            "0" * 64,
            "--key",
            str(key),
            "--subject",
            "human:nobody",
        ]
    )
    assert code == 2

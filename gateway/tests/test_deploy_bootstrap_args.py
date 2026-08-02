"""`deploy/bin/stozher-bootstrap` — every argument it will reject, it rejects before it builds.

Step 1 of eight compiles the kernel image. On a cold cache that is minutes, and the check that
`--second-root` needs `--second-root-key` used to live at step 3, so an operator who named a second
root without its key paid for the whole build to be told a two-word mistake.

The assertion is on the *absence of the build*, not on the message. A test that only checked the
error text would pass with the wait still in front of it, which is the failure it exists to prevent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"


@pytest.fixture
def sandbox(tmp_path: Path) -> tuple[Path, Path]:
    """A copy of `deploy/`, and a `docker` on PATH that records rather than runs.

    A copy because the script `cd`s to its own parent and writes `.env` there: if the guard under
    test ever regresses, this must not be a run against the repository — or against whatever
    deployment its compose project resolves to.

    Tracked files only, via `git ls-files`. A developer's checkout holds a *running* deployment
    under this directory — `secrets/`, `var/`, `config/` are ignored, not absent — and `copytree`
    would put a live root seed in `/tmp` and hand the script a store it would refuse as already
    bootstrapped. Neither of those is something a test should do by accident.
    """
    deploy = tmp_path / "deploy"
    listed = subprocess.run(
        ["git", "ls-files", "-z", "."],
        cwd=DEPLOY,
        capture_output=True,
        check=True,
    ).stdout
    for name in listed.decode().split("\0"):
        if not name:
            continue
        source = DEPLOY / name
        target = deploy / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    witness = tmp_path / "docker-was-invoked"
    stub = stub_dir / "docker"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{witness}"\nexit 0\n')
    stub.chmod(0o755)
    return deploy / "bin" / "stozher-bootstrap", witness


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, PATH=f"{script.parents[2] / 'bin'}:{os.environ['PATH']}")
    return subprocess.run(
        [str(script), *args], capture_output=True, text=True, env=env, timeout=60
    )


def test_a_second_root_without_its_key_is_refused_before_anything_is_built(
    sandbox: tuple[Path, Path],
) -> None:
    script, witness = sandbox
    result = _run(script, "--root", "human:ivan", "--second-root", "human:mira")
    assert result.returncode != 0
    assert "given together" in result.stderr
    assert not witness.exists(), (
        "the build ran before the arguments were checked; docker was invoked with: "
        + witness.read_text()
    )


def test_a_missing_root_is_refused_before_anything_is_built(
    sandbox: tuple[Path, Path],
) -> None:
    """The guard that was already early, pinned so the reordering above cannot regress it."""
    script, witness = sandbox
    result = _run(script)
    assert result.returncode != 0
    assert "--root" in result.stderr
    assert not witness.exists()


def test_a_complete_second_root_pair_passes_the_argument_gate(
    sandbox: tuple[Path, Path],
) -> None:
    """The paired negative: the guard must refuse the incomplete pair and nothing else.

    A validation that rejected every `--second-root` would satisfy the two tests above while making
    the two-root install — the one `spec/03 §6` exists for — impossible. This run is expected to
    fail later, at the ceremony, having got past the gate; what it must not do is fail *at* it.
    """
    script, witness = sandbox
    result = _run(
        script,
        "--root",
        "human:ivan",
        "--second-root",
        "human:mira",
        "--second-root-key",
        "ed25519:" + "ab" * 32,
    )
    assert "given together" not in result.stderr
    assert witness.exists(), "the run stopped before it reached the build stage"

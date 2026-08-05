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


def _ceremony_images(witness: Path) -> set[str]:
    """Every image tag the ceremony's throwaway containers were started from.

    `docker run` lines only. `docker compose` reads `.env` itself and is not what this is about.
    """
    tags = set()
    for line in witness.read_text().splitlines():
        words = line.split()
        if not words or words[0] != "run":
            continue
        tags |= {word for word in words if word.startswith("stozher-kernel:")}
    return tags


def test_the_ceremony_runs_the_image_named_in_dot_env(sandbox: tuple[Path, Path]) -> None:
    """The tag in `.env` is the tag the ceremony executes.

    This script is the only one that runs before `.env` can be in anyone's environment, and `.env`
    is where `deploy/README.md` tells an operator to put a per-install tag. Resolving `IMAGE` at the
    top — before the file was read — meant the whole ceremony ran the shared `stozher-kernel:0.1.0`
    while `docker compose` read `.env` and built and started the right one. The install then had a
    store written by one binary and served by another; on a host with two installs, the binary was
    the other deployment's. It surfaced as a second root enrolled into the root set and missing from
    the policy's approvers — behaviour this repository had already fixed in the binary.
    """
    script, witness = sandbox
    (script.parents[1] / ".env").write_text(
        "STOZHER_UID=1000\nSTOZHER_GID=1000\nSTOZHER_KERNEL_PORT=8830\n"
        "COMPOSE_PROJECT_NAME=stozher-elsewhere\n"
        "STOZHER_KERNEL_IMAGE=stozher-kernel:from-dot-env\n"
    )
    # `--accept-unrecoverable` because this test is about image resolution, not about the root set.
    # Without it the ceremony now stops before docker is ever invoked (DEF-19), which is the correct
    # behaviour and would make this assert the wrong thing.
    _run(script, "--root", "human:ivan", "--accept-unrecoverable")
    assert witness.exists(), "the run stopped before it reached the ceremony"
    tags = _ceremony_images(witness)
    assert tags == {"stozher-kernel:from-dot-env"}, (
        "the ceremony ran a binary the operator did not name in .env: " + repr(sorted(tags))
    )


def test_the_environment_still_wins_over_dot_env(sandbox: tuple[Path, Path]) -> None:
    """The paired negative, and the precedence `docker compose` uses.

    Reading `.env` unconditionally would be the same defect with the operands swapped: an exported
    tag is how the two must be kept in step when a caller drives this script, and compose lets the
    environment override the file. A fix that always preferred the file would satisfy the test above
    while breaking that.
    """
    script, witness = sandbox
    (script.parents[1] / ".env").write_text(
        "STOZHER_UID=1000\nSTOZHER_GID=1000\n"
        "STOZHER_KERNEL_IMAGE=stozher-kernel:from-dot-env\n"
    )
    env = dict(
        os.environ,
        PATH=f"{script.parents[2] / 'bin'}:{os.environ['PATH']}",
        STOZHER_KERNEL_IMAGE="stozher-kernel:from-the-environment",
    )
    subprocess.run(
        [str(script), "--root", "human:ivan", "--accept-unrecoverable"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert _ceremony_images(witness) == {"stozher-kernel:from-the-environment"}


def test_a_single_root_install_is_refused_before_anything_is_built(
    sandbox: tuple[Path, Path],
) -> None:
    """DEF-19. A deployment that can never recover must not be the one you get by default.

    With one enrolled root the recovery act of §04 §7.2 is unreachable — it needs an approval, and a
    lone root approving its own request is refused `gate-self-approval`, correctly — and the root set
    cannot be changed later to fix that, because changing it needs two roots. So a revoked or expired
    mandate permanently removes a component from the fleet.

    Two design partners found this on 2026-08-04, both after doing something routine. The option to
    avoid it existed all along; nothing made anyone use it, and the warning was a comment at the top
    of the script.
    """
    script, witness = sandbox
    result = _run(script, "--root", "human:ivan")
    assert result.returncode != 0
    assert "can never recover" in result.stderr
    assert "--second-root" in result.stderr, "the refusal does not say what to do instead"
    assert "--accept-unrecoverable" in result.stderr, "the refusal offers no way past itself"
    assert not witness.exists(), (
        "docker was invoked before the refusal — an operator would wait through a Rust compile to "
        "be told something knowable from the arguments"
    )


def test_the_disposable_case_can_say_so_and_proceed(sandbox: tuple[Path, Path]) -> None:
    """The control. A refusal with no way past it would break `gate/clean-install.sh`, which
    legitimately wants a throwaway single-root install — it wipes the directory it runs in."""
    script, witness = sandbox
    _run(script, "--root", "human:ivan", "--accept-unrecoverable")
    assert witness.exists(), "the accepted single-root path never reached the ceremony"

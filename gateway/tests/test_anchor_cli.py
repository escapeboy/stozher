"""`stozher-kernel anchor` — taking the chain's head out of the box, as a process.

`spec/04 §4.7` asks that checkpoints be exported off-box, because one held only where it was made
cannot tell an intact store from a rebuilt one: the audited party attests to itself. The kernel has
signed checkpoints since v0.2 and, until this command, offered no way out — so `deploy/README.md`
instructed operators to "export checkpoints off-box" with nothing that did it.

Spawned as a subprocess, not called through the library it wraps. That rule is in this repository
because `bin/stozher-approve` shipped broken for a release behind four green unit tests, each
feeding its parser a page the test had written itself.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import urllib.request
from typing import Any

import pytest

from stozher_gateway.crypto import ROLE_AGENT, ROLE_HUMAN_ROOT, derive
from stozher_gateway.signing import SigningKey

from .support import Kernel, build_kernel

GATEWAY_SEED = "7c" * 32


def run(*arguments: str, token: str | None) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    if token is not None:
        environment["STOZHER_KERNEL_TOKEN"] = token
    else:
        environment.pop("STOZHER_KERNEL_TOKEN", None)
    return subprocess.run(
        [str(build_kernel()), *arguments], capture_output=True, env=environment, timeout=60
    )


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("anchor")
    seed_hex = secrets.token_hex(32)
    seed_file = root / "operator.seed"
    seed_file.write_text(seed_hex)
    seed_file.chmod(0o600)
    seed = bytes.fromhex(seed_hex)

    kernel = Kernel(root, bytes.fromhex(GATEWAY_SEED), "agent:gateway/dev")
    kernel.human_root = SigningKey(derive(seed, ROLE_HUMAN_ROOT, 0), "human:ivan")
    kernel.bootstrap = SigningKey(derive(seed, ROLE_AGENT, 0), "agent:bootstrap")
    kernel.start()
    try:
        yield kernel
    finally:
        kernel.stop()


def _checkpoint_everything(kernel: Kernel) -> None:
    request = urllib.request.Request(f"{kernel.url}/v1/checkpoints", method="POST", data=b"")
    request.add_header("authorization", f"Bearer {kernel.token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 200


def test_the_anchor_command_prints_a_document_an_outsider_can_come_back_to(world: Any) -> None:
    """Empty first, populated after — one function, because the two halves share a store.

    Split across two tests these would pass only in file order, and silently stop meaning anything
    the day somebody inserted a third above them.
    """
    kernel = world

    # A young store has reached no checkpoint interval, and the document must not pretend it has.
    before = run("anchor", "--url", kernel.url, token=kernel.token)
    assert before.returncode == 0, before.stderr.decode()
    empty = json.loads(before.stdout)
    assert empty["heads"] == [], "a store with no checkpoint reported heads"
    assert empty["taken-at"], "an anchor states when it was taken even when it is empty"

    # Forced rather than waited for: checkpoints are emitted on the policy's interval, and the
    # assertions below would loop over an empty list and check nothing while passing.
    _checkpoint_everything(kernel)

    result = run("anchor", "--url", kernel.url, token=kernel.token)
    assert result.returncode == 0, result.stderr.decode()
    document = json.loads(result.stdout)
    assert document["heads"], "nothing to anchor after a forced checkpoint of every stream"
    for head in document["heads"]:
        # Each head must name the envelope that attests it. Without that the file is a list of
        # numbers whose only provenance is whoever mailed it — which is the position the operator
        # was already in before this command existed.
        assert head["checkpoint-envelope"], head
        assert head["head-hash"], head
        assert head["to-seq"] >= head["from-seq"], head


def test_the_anchor_command_refuses_without_a_credential(world: Any) -> None:
    """It reads the audit surface, so it is authenticated like everything else (§05 §2.2).

    It refuses before opening a socket, which is why the assertion is on the missing credential and
    not on a 401: an operator running this from cron gets the reason without a round trip.
    """
    kernel = world
    result = run("anchor", "--url", kernel.url, token=None)
    assert result.returncode != 0
    assert b"STOZHER_KERNEL_TOKEN is unset" in result.stderr, result.stderr.decode()
    assert result.stdout == b"", "a refusal must not print a document"

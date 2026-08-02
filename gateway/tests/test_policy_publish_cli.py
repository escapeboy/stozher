"""Publishing a policy version after the install, through the commands an operator actually runs.

`spec/05 §5` refuses a privileged path: changing policy is a `consequential` effect, judged by the
policy already in force and carrying a named human's signature over the exact bytes of the document
that takes effect. The install ceremony does this once, for the first version. **For every version
after it, no command existed.** The operation was possible — the gateway's own test support has
hand-built the envelope since S1 — and an operator with a shell had no way to perform it short of
writing that envelope themselves, which is the definition of a product defect for a product whose
plan says *the operator is on their own*.

**What is real here, stated rather than implied.**

* A compiled `stozher-kernel serve` over a real SQLite store, bootstrapped through the real
  two-envelope ceremony, reachable over a real socket.
* Every operator step is that same **binary, spawned as a subprocess**, with the arguments
  `deploy/bin/` would pass. Nothing is done in-process: this file exists to test the commands, and a
  command exercised through the library it wraps is a command nobody has run.
* The root's key is derived by SLIP-0010 from a seed file on disk, at role `0'` — so the key the
  kernel enrolled and the key `decide` reads are the same key for the same reason they are in a real
  deployment, rather than because a fixture said so.
* The approval is a real Ed25519 signature the kernel has never held and cannot produce.

**What is not real.** The clock is the host's, and the deployment lives in a temporary directory.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import object_hash
from stozher_gateway.crypto import ROLE_AGENT, ROLE_HUMAN_ROOT, derive
from stozher_gateway.signing import SigningKey

from .support import Kernel, baseline_policy, build_kernel

GATEWAY_SEED = "5a" * 32
NEXT_VERSION = "2026.08.1"


def run(*arguments: str, token: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    """One operator command, as a process, with the credential named by variable and never argued."""
    environment = dict(os.environ, STOZHER_KERNEL_TOKEN=token)
    return subprocess.run(
        [str(build_kernel()), *arguments],
        input=stdin,
        capture_output=True,
        env=environment,
        timeout=60,
    )


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("policy-publish")
    seed_file = root / "operator.seed"
    seed_hex = secrets.token_hex(32)
    seed_file.write_text(seed_hex)
    seed_file.chmod(0o600)
    seed = bytes.fromhex(seed_hex)

    kernel = Kernel(root, bytes.fromhex(GATEWAY_SEED), "agent:gateway/dev")
    # The two subjects `genesis` derives from one seed (§01 §6), rather than the fixture's constants:
    # the point of this test is that the operator's own commands, reading that file, produce keys
    # this deployment already trusts. With unrelated constants the commands would be exercised
    # against a root the kernel never enrolled, and every refusal would be the fixture's fault.
    kernel.human_root = SigningKey(derive(seed, ROLE_HUMAN_ROOT, 0), "human:ivan")
    kernel.bootstrap = SigningKey(derive(seed, ROLE_AGENT, 0), "agent:bootstrap")
    kernel.start()
    try:
        yield kernel, seed_file, root
    finally:
        kernel.stop()


def new_document(kernel: Kernel, root: Path) -> tuple[Path, dict[str, Any]]:
    """The next policy version, signed by the organization's policy key, on disk."""
    document = kernel.policy_key.sign(
        baseline_policy(NEXT_VERSION, clock_module.now(), kernel.human_root.subject)
    )
    path = root / "policy-next.json"
    path.write_text(json.dumps(document))
    return path, document


def test_an_operator_can_publish_a_second_policy_version_with_the_shipped_commands(
    world: Any,
) -> None:
    kernel, seed_file, root = world
    # Asked of the kernel, which is how `bin/stozher-publish-policy` gets it: §05 §5 rule 1 makes
    # this the outgoing version, and a script that assumed the last version *it* published is still
    # in force is wrong the first time two people publish.
    reported = run("policy-current", "--url", kernel.url, token=kernel.token)
    assert reported.returncode == 0, reported.stderr.decode()
    in_force = reported.stdout.decode().strip()
    assert in_force == kernel.policy_version

    document_path, document = new_document(kernel, root)
    request_path = root / "policy-request.json"

    built = run(
        "policy-request",
        "--document", str(document_path),
        "--subject", kernel.bootstrap.subject,
        "--key", str(seed_file),
        "--mandate", kernel.bootstrap_mandate,
        "--in-force", in_force,
        "--out", str(request_path),
        token=kernel.token,
    )
    assert built.returncode == 0, built.stderr.decode()
    request_hash = built.stdout.decode().strip()
    assert len(request_hash) == 64

    parked = run("park", "--url", kernel.url, "--file", str(request_path), token=kernel.token)
    assert parked.returncode == 0, parked.stderr.decode()
    assert json.loads(parked.stdout)["request-hash"] == request_hash

    # Publishing before a human has answered is refused *locally*, without a signature being built
    # or a request reaching the kernel. The operator is told which of the two it is.
    early = run(
        "policy-publish",
        "--url", kernel.url,
        "--request", str(request_path),
        "--document", str(document_path),
        "--key", str(seed_file),
        token=kernel.token,
    )
    assert early.returncode != 0
    assert "has not been answered yet" in early.stderr.decode(), early.stderr.decode()

    # The root's own process: reads the seed, signs, opens no socket.
    signed = run(
        "decide",
        "--request", request_hash,
        "--key", str(seed_file),
        "--role", "0",
        "--index", "0",
        "--approve",
        token=kernel.token,
    )
    assert signed.returncode == 0, signed.stderr.decode()
    # A different process, holding no seed, carrying an object it could not have produced.
    answered = run(
        "answer", "--url", kernel.url, "--request", request_hash,
        token=kernel.token, stdin=signed.stdout,
    )
    assert answered.returncode == 0, answered.stderr.decode()

    published = run(
        "policy-publish",
        "--url", kernel.url,
        "--request", str(request_path),
        "--document", str(document_path),
        "--key", str(seed_file),
        token=kernel.token,
    )
    assert published.returncode == 0, published.stderr.decode()

    # The version in force is the new one, and the bytes served are the bytes that were approved —
    # not a copy uploaded beside them. `args-hash` is what the human signed over.
    status, current = kernel.request("GET", "/v1/policy/current")
    assert status == 200
    assert current["policy-version"] == NEXT_VERSION
    assert object_hash(current) == object_hash(document)


def test_publishing_a_document_the_approval_did_not_name_is_refused_before_anything_is_signed(
    world: Any,
) -> None:
    # The substitution this guards against is the whole point of `args-hash`: approve a harmless
    # policy, publish a permissive one. It is caught at ingest as well — the envelope's `args-hash`
    # comes from the request the approval covers — but catching it here means the operator learns
    # they have the wrong file rather than reading a rejection about a hash mismatch.
    kernel, seed_file, root = world
    request_path = root / "policy-request.json"
    other = kernel.policy_key.sign(
        baseline_policy("2026.08.2", clock_module.now(), kernel.human_root.subject)
    )
    other_path = root / "policy-other.json"
    other_path.write_text(json.dumps(other))

    refused = run(
        "policy-publish",
        "--url", kernel.url,
        "--request", str(request_path),
        "--document", str(other_path),
        "--key", str(seed_file),
        token=kernel.token,
    )
    assert refused.returncode != 0
    assert "is not the document" in refused.stderr.decode(), refused.stderr.decode()


def test_a_request_that_installs_the_version_already_in_force_is_refused(world: Any) -> None:
    # §05 §5 rule 1: `policy-version` is the outgoing version and `execution.target` the incoming
    # one. Passing the same value twice produces an envelope claiming the change was judged by the
    # policy it installs — which the kernel would accept, because every member is well formed.
    kernel, seed_file, root = world
    document_path, _ = new_document(kernel, root)

    refused = run(
        "policy-request",
        "--document", str(document_path),
        "--subject", kernel.bootstrap.subject,
        "--key", str(seed_file),
        "--mandate", kernel.bootstrap_mandate,
        "--in-force", NEXT_VERSION,
        "--out", str(root / "unused.json"),
        token=kernel.token,
    )
    assert refused.returncode != 0
    assert "pass the version currently in force" in refused.stderr.decode()
    assert not (root / "unused.json").exists()

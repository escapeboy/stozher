"""Registering a component with the shipped commands — `spec/08 §3.3`.

v0.4's gate was *"a component not written by us registers through the documented path, its manifest
governs its classification, and its budget is enforced at spend time."* The kernel implements every
part of it. The **path** was a helper in this repository's own test kit — `World::register_component`
— which is not a path an operator has, and the gate was graded against it.

Two envelopes, both root-approved whatever policy says (§05 §5 rule 6):

1. `kernel.conformance_run`, committing to the manifest hash, carrying the run report as evidence.
   §08 §3.3 makes this the thing registration rests on: no green run, no registration.
2. `kernel.register_component`, committing to the same hash and carrying the **manifest itself** as
   the payload — so what is registered is the document that was approved, byte for byte.

Both go through the general `effect-request` / `effect-publish` pair, because neither carries a rule
of its own the way a policy change or a root enrolment does. Every step is the real binary as a
subprocess against a live kernel.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import object_hash
from stozher_gateway.crypto import ROLE_AGENT, ROLE_HUMAN_ROOT, ROLE_POLICY, derive
from stozher_gateway.signing import SigningKey, object_id

from .support import CORE_STREAM, Kernel, build_kernel

GATEWAY_SEED = "7f" * 32
COMPONENT = "acmetool"


def run(*arguments: str, token: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ, STOZHER_KERNEL_TOKEN=token)
    return subprocess.run(
        [str(build_kernel()), *arguments],
        input=stdin,
        capture_output=True,
        env=environment,
        timeout=60,
    )


def manifest_object(name: str) -> dict[str, Any]:
    """The smallest manifest §08 §1 accepts, for a component nothing here wrote.

    The component's key is not a member: §08 §1 makes the manifest a *signed object*, so the key
    that vouches for it is its signer. The component signs its own manifest, and the roots approve
    registering that document — neither of them speaks for the other.
    """
    return {
        "v": "stozher/0.1",
        "kind": "manifest",
        "name": name,
        "version": "1.0.0",
        "subject-class": "tool-proxy",
        "description": "a component registered through the operator's own commands",
        "actions": [
            {
                "action": f"{name}.get_file",
                "class": "read",
                "evidence-schema": f"{name}.get_file.v1",
                "aggregate": {"sampling": "first-and-last", "max-samples": 8},
                "idempotent": True,
                "target-kind": "repo-path",
            }
        ],
        "evidence-schemas": {
            f"{name}.get_file.v1": {
                "type": "object",
                "required": ["path"],
                "properties": {"path": {"type": "string"}},
                "additionalProperties": False,
            }
        },
        "budget-dimensions": ["requests"],
        "durable-objects": [],
        "conformance": {"self-test": f"{name}.selftest", "vectors-version": "stozher/0.1"},
    }


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Any:
    root = tmp_path_factory.mktemp("register")
    ivan_file = root / "ivan.seed"
    mira_file = root / "mira.seed"
    ivan_hex, mira_hex = secrets.token_hex(32), secrets.token_hex(32)
    for path, text in ((ivan_file, ivan_hex), (mira_file, mira_hex)):
        path.write_text(text)
        path.chmod(0o600)
    ivan, mira = bytes.fromhex(ivan_hex), bytes.fromhex(mira_hex)

    kernel = Kernel(root, bytes.fromhex(GATEWAY_SEED), "agent:gateway/dev")
    kernel.human_root = SigningKey(derive(ivan, ROLE_HUMAN_ROOT, 0), "human:ivan")
    kernel.second_root = SigningKey(derive(mira, ROLE_HUMAN_ROOT, 0), "human:mira")
    kernel.bootstrap = SigningKey(derive(ivan, ROLE_AGENT, 0), "agent:bootstrap")
    kernel.policy_key = SigningKey(derive(ivan, ROLE_POLICY, 0), "org:policy")
    kernel.start()
    try:
        yield kernel, ivan_file, mira_file, root
    finally:
        kernel.stop()


def mandate_from_mira_to_ivan(kernel: Kernel) -> str:
    now = clock_module.now()
    mandate = kernel.second_root.sign(
        {
            "v": "stozher/0.1",
            "kind": "mandate",
            "mandate-kind": "standing",
            "grantor": {
                "subject": kernel.second_root.subject,
                "key": kernel.second_root.id,
                "role": "human",
            },
            "grantee": {"subject": kernel.human_root.subject, "key": kernel.human_root.id},
            "issued-at": now,
            "not-before": now,
            "not-after": clock_module.shift(now, 8 * 3600),
            "parent": None,
            "max-depth": 2,
            "scope": {
                "components": ["kernel"],
                "actions": ["kernel.*"],
                "classes": ["read", "benign", "consequential"],
                "resources": ["*"],
            },
            "nonce": secrets.token_hex(16),
        }
    )
    seq, prev = kernel.head(CORE_STREAM)
    kernel.submit(
        kernel.human_root.sign(
            {
                "v": "stozher/0.1",
                "kind": "mandate",
                "emitted-at": now,
                "stream": CORE_STREAM,
                "seq": seq,
                "prev-hash": prev,
                "identity": {
                    "subject": kernel.human_root.subject,
                    "key": kernel.human_root.id,
                    "component": "kernel",
                },
                "mandate": mandate,
            }
        )
    )
    return object_id(mandate)


def approved(kernel: Kernel, mira_file: Any, request_hash: str) -> None:
    """Mira answers what Ivan asked — §06 §5, and the reason this needs two roots."""
    signed = run(
        "decide", "--request", request_hash, "--key", str(mira_file),
        "--role", "0", "--index", "0", "--approve", token=kernel.token,
    )
    assert signed.returncode == 0, signed.stderr.decode()
    answered = run(
        "answer", "--url", kernel.url, "--request", request_hash,
        token=kernel.token, stdin=signed.stdout,
    )
    assert answered.returncode == 0, answered.stderr.decode()


def test_a_component_nobody_here_wrote_registers_through_the_operators_own_commands(
    world: Any,
) -> None:
    kernel, ivan_file, mira_file, root = world
    mandate = mandate_from_mira_to_ivan(kernel)
    component = SigningKey(derive(bytes.fromhex("8a" * 32), ROLE_AGENT, 0), f"agent:{COMPONENT}")
    manifest = component.sign(manifest_object(COMPONENT))
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    manifest_hash = object_hash(manifest)
    target = f"manifest:{manifest_hash}"

    def ceremony(
        action: str, classification: str, evidence: Any | None, name: str, retain_days: str = "365"
    ) -> None:
        request_path = root / f"{name}.json"
        built = run(
            "effect-request",
            "--action", action,
            "--target", target,
            "--requester", kernel.human_root.subject,
            "--key", str(ivan_file),
            "--mandate", mandate,
            "--in-force", kernel.policy_version,
            "--args-hash", manifest_hash,
            "--classification", classification,
            "--out", str(request_path),
            token=kernel.token,
        )
        assert built.returncode == 0, built.stderr.decode()
        request_hash = built.stdout.decode().strip()
        parked = run("park", "--url", kernel.url, "--file", str(request_path), token=kernel.token)
        assert parked.returncode == 0, parked.stderr.decode()
        approved(kernel, mira_file, request_hash)
        arguments = (
            ["--evidence", str(evidence), "--retain-days", retain_days]
            if evidence is not None
            else []
        )
        published = run(
            "effect-publish",
            "--url", kernel.url,
            "--request", str(request_path),
            "--key", str(ivan_file),
            *arguments,
            token=kernel.token,
        )
        assert published.returncode == 0, published.stdout.decode() + published.stderr.decode()

    # §08 §3.3: no green run, no registration. Asserted by attempting the registration first.
    early_request = root / "early.json"
    built = run(
        "effect-request",
        "--action", "kernel.register_component",
        "--target", target,
        "--requester", kernel.human_root.subject,
        "--key", str(ivan_file),
        "--mandate", mandate,
        "--in-force", kernel.policy_version,
        "--args-hash", manifest_hash,
        "--out", str(early_request),
        token=kernel.token,
    )
    assert built.returncode == 0, built.stderr.decode()
    early_hash = built.stdout.decode().strip()
    assert run("park", "--url", kernel.url, "--file", str(early_request), token=kernel.token).returncode == 0
    approved(kernel, mira_file, early_hash)
    early = run(
        "effect-publish",
        "--url", kernel.url,
        "--request", str(early_request),
        "--key", str(ivan_file),
        "--evidence", str(manifest_path),
        token=kernel.token,
    )
    assert early.returncode != 0
    assert "manifest-conformance-not-green" in early.stdout.decode(), early.stdout.decode()

    # The run report is the evidence; the manifest hash is what the run attests, so the two hashes
    # differ here and are the same for the registration below.
    report_path = root / "run.json"
    report_path.write_text(
        json.dumps(
            {
                "schema": "kernel.conformance_run.v1",
                "manifest-hash": manifest_hash,
                "component": COMPONENT,
                "at": clock_module.now(),
                "green": True,
                "outstanding": [],
                "groups": {},
            }
        )
    )
    # `benign` has a shorter retention ceiling than `consequential` (§09 §2), which is why
    # `--retain-days` is a flag: the same 365 days that is fine for the registration below is
    # refused here, and the refusal names the ceiling.
    ceremony("kernel.conformance_run", "benign", report_path, "run", retain_days="20")
    ceremony("kernel.register_component", "consequential", manifest_path, "register")

    # The manifest feed is what a component's classification is read from afterwards.
    status, feed = kernel.request("GET", "/v1/manifests")
    assert status == 200, feed
    registered = [m for m in feed["manifests"] if m["name"] == COMPONENT]
    assert len(registered) == 1, feed
    assert registered[0]["version"] == "1.0.0"
    # The feed serves the manifest documents themselves, so this is the strongest available
    # statement: what a component's classification is now read from is byte-identical to the
    # document the roots approved, not a summary of it.
    assert object_hash(registered[0]) == manifest_hash

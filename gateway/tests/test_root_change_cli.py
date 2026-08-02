"""Changing the root set with the shipped commands — `spec/03 §6`.

The root set decides who may approve the five actions policy cannot lower the bar on, including
changing the root set again. It was specified, implemented in the kernel, and reachable by no
command: an operator who enrolled one root and later needed a second had nothing to type.

Two properties are asserted here because they are the ones a fixture can accidentally satisfy:

* **Two humans, not one.** §03 §1 forbids self-grant and effect kinds require `mandate-ref`, so the
  root making the change acts under a mandate the *other* root granted, and §06 §5 forbids answering
  one's own request. The whole ceremony below therefore needs both, and a one-root deployment cannot
  perform it at all — which `deploy/README.md` warns about before the install, and which this file
  is the executable form of.
* **The human's name is on the chain, under the hash the approver signed over.** The subject is what
  §06 §5 compares, and the kernel recorded `execution.target` there until 2026-08-02 — so the
  mechanism for giving a person a second key was the mechanism that stopped the rule recognising
  them. What this file checks is the *record*: the evidence served back under `args-hash` names the
  human. The projection it becomes is asserted where it can be read directly, in
  `kernel/stozher-kernel/tests/root_enrollment.rs`.

Every step is the real binary as a subprocess against a live kernel.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from typing import Any

import pytest

from stozher_gateway.crypto import ROLE_AGENT, ROLE_HUMAN_ROOT, ROLE_POLICY, derive
from stozher_gateway.signing import SigningKey, object_id

from .support import CORE_STREAM, Kernel, build_kernel

GATEWAY_SEED = "6b" * 32
THIRD_ROOT = "human:third"


def run(*arguments: str, token: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
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
    root = tmp_path_factory.mktemp("root-change")

    def seed_file(name: str) -> tuple[Any, bytes]:
        path = root / f"{name}.seed"
        text = secrets.token_hex(32)
        path.write_text(text)
        path.chmod(0o600)
        return path, bytes.fromhex(text)

    ivan_file, ivan = seed_file("ivan")
    mira_file, mira = seed_file("mira")

    kernel = Kernel(root, bytes.fromhex(GATEWAY_SEED), "agent:gateway/dev")
    # Two operators, two machines, two seeds — which is what §03 §6's "at least two enrolled roots"
    # means in practice, and what the fixture has to reproduce for the refusals to be the kernel's.
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
    """A root acting directly still acts under a mandate another human granted (§03 §1)."""
    from stozher_gateway import clock as clock_module

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


def test_two_roots_can_enrol_a_third_and_the_human_is_the_name_recorded(world: Any) -> None:
    kernel, ivan_file, mira_file, root = world
    mandate = mandate_from_mira_to_ivan(kernel)
    third = SigningKey(derive(bytes.fromhex("7c" * 32), ROLE_HUMAN_ROOT, 0), THIRD_ROOT)
    request_path = root / "enrol.json"

    built = run(
        "root-request",
        "--requester", kernel.human_root.subject,
        "--key", str(ivan_file),
        "--mandate", mandate,
        "--in-force", kernel.policy_version,
        "--enrol", third.id,
        "--subject", THIRD_ROOT,
        "--out", str(request_path),
        token=kernel.token,
    )
    assert built.returncode == 0, built.stderr.decode()
    request_hash = built.stdout.decode().strip()
    assert (root / "enrol.json.evidence").exists(), "the evidence naming the human was not written"

    parked = run("park", "--url", kernel.url, "--file", str(request_path), token=kernel.token)
    assert parked.returncode == 0, parked.stderr.decode()

    # Ivan asked, so Mira answers. Ivan answering his own request is refused by the kernel, which
    # the next test asserts rather than this one assuming.
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

    published = run(
        "root-publish",
        "--url", kernel.url,
        "--request", str(request_path),
        "--key", str(ivan_file),
        token=kernel.token,
    )
    assert published.returncode == 0, published.stderr.decode()

    status, listed = kernel.request("GET", "/v1/envelopes?kind=effect")
    assert status == 200
    enrolments = [
        r["envelope"]
        for r in listed["records"]
        if r["envelope"].get("execution", {}).get("action") == "kernel.enroll_root"
    ]
    assert len(enrolments) == 1, "the enrolment was not appended"
    assert enrolments[0]["execution"]["target"] == f"root:{third.id}"
    assert enrolments[0]["identity"]["subject"] == kernel.human_root.subject

    # The name, on the chain and readable. `args-hash` is what Mira signed over, so the evidence the
    # kernel served back under that hash is the evidence she approved — and it names the human, not
    # the key string this kernel used to record until 2026-08-02. The *projection* is asserted
    # directly by `kernel/stozher-kernel/tests/root_enrollment.rs`, which can read `roots_at`.
    args_hash = enrolments[0]["execution"]["args-hash"]
    status, evidence = kernel.request("GET", f"/v1/payloads/{args_hash}")
    assert status == 200, evidence
    assert evidence == {"subject": THIRD_ROOT, "key": third.id}, evidence


def test_a_root_may_not_approve_its_own_change_to_the_root_set(world: Any) -> None:
    # The most privileged action in the system, performed by one person, is exactly the shape §03 §6
    # spends a paragraph refusing. It is refused at the console, before any envelope is built.
    kernel, ivan_file, _mira_file, root = world
    mandate = mandate_from_mira_to_ivan(kernel)
    fourth = SigningKey(derive(bytes.fromhex("7d" * 32), ROLE_HUMAN_ROOT, 0), "human:fourth")
    request_path = root / "self-approved.json"

    built = run(
        "root-request",
        "--requester", kernel.human_root.subject,
        "--key", str(ivan_file),
        "--mandate", mandate,
        "--in-force", kernel.policy_version,
        "--enrol", fourth.id,
        "--subject", "human:fourth",
        "--out", str(request_path),
        token=kernel.token,
    )
    assert built.returncode == 0, built.stderr.decode()
    request_hash = built.stdout.decode().strip()
    assert run("park", "--url", kernel.url, "--file", str(request_path), token=kernel.token).returncode == 0

    signed = run(
        "decide", "--request", request_hash, "--key", str(ivan_file),
        "--role", "0", "--index", "0", "--approve", token=kernel.token,
    )
    assert signed.returncode == 0, signed.stderr.decode()
    answered = run(
        "answer", "--url", kernel.url, "--request", request_hash,
        token=kernel.token, stdin=signed.stdout,
    )
    assert answered.returncode != 0, "ivan approved his own request"
    assert "gate-self-approval" in answered.stdout.decode(), answered.stdout.decode()


def test_enrolling_without_naming_a_human_is_refused_before_a_request_exists(world: Any) -> None:
    kernel, ivan_file, _mira_file, root = world
    fifth = SigningKey(derive(bytes.fromhex("7e" * 32), ROLE_HUMAN_ROOT, 0), "human:fifth")

    for subject in ([], ["--subject", "agent:not-a-human"], ["--subject", "human:"]):
        refused = run(
            "root-request",
            "--requester", kernel.human_root.subject,
            "--key", str(ivan_file),
            "--mandate", "0" * 64,
            "--in-force", kernel.policy_version,
            "--enrol", fifth.id,
            *subject,
            "--out", str(root / "never.json"),
            token=kernel.token,
        )
        assert refused.returncode != 0, f"{subject} produced a request"
        assert not (root / "never.json").exists()

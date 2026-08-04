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

import json
import os
import secrets
import subprocess
from typing import Any

import pytest

from stozher_gateway.canonical import object_hash
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


def mandate_through_the_shipped_commands(
    kernel: Kernel, grantor_seed: Any, publisher_seed: Any, work: Any
) -> str:
    """The same mandate, produced and published the way an operator has to: two subprocesses.

    The fixture above builds the envelope in Python, and for a year that was the only way it could
    be built — `grant` writes a bare mandate object and nothing in the kernel published one, so a
    human's mandate could be signed and never made resolvable. Three independent evaluators hit
    that in one day, from three directions; each was told `mandate-unresolved` by a ceremony
    `deploy/README.md` documents end to end.

    The test above therefore proved the ceremony works *given* a published mandate, while imitating
    the one step no operator could perform. This is the binding version.
    """
    path = work / "mira-to-ivan.json"
    granted = run(
        "grant",
        "--key", str(grantor_seed),
        "--root", kernel.second_root.subject,
        "--grantee", kernel.human_root.subject,
        "--grantee-key", kernel.human_root.id,
        "--actions", "kernel.enroll_root,kernel.retire_root",
        "--classes", "consequential",
        "--days", "1",
        "--out", str(path),
        token=kernel.token,
    )
    assert granted.returncode == 0, granted.stderr.decode()

    published = run(
        "submit-mandate",
        "--url", kernel.url,
        "--mandate", str(path),
        "--key", str(publisher_seed),
        "--subject", kernel.human_root.subject,
        "--stream", CORE_STREAM,
        token=kernel.token,
    )
    assert published.returncode == 0, published.stderr.decode()
    return object_id(json.loads(path.read_text()))


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


def test_an_operator_can_put_a_granted_mandate_on_the_chain_and_then_use_it(world: Any) -> None:
    """The gap three evaluators found: signed mandates that nothing could publish.

    `grant` writes the object; `submit-mandate` wraps it into the envelope and submits it. Until
    the second existed, `deploy/README.md`'s own human-only root-change ceremony ran four commands
    and died on the last one with `mandate-unresolved`, and the root set could never change after
    install — which is exactly the day the person who ran the ceremony leaves.
    """
    kernel, ivan_file, mira_file, root = world
    work = root / "handover"
    work.mkdir(exist_ok=True)

    mandate_id = mandate_through_the_shipped_commands(kernel, mira_file, ivan_file, work)

    # Resolvable is the whole point: an envelope that cites it must now be judged on its merits
    # rather than refused for a mandate the kernel has never seen.
    request = work / "enrol.json"
    built = run(
        "root-request",
        "--requester", kernel.human_root.subject,
        "--key", str(ivan_file),
        "--mandate", mandate_id,
        "--in-force", kernel.policy_version,
        "--enrol", "ed25519:" + "ab" * 32,
        "--subject", THIRD_ROOT,
        "--out", str(request),
        token=kernel.token,
    )
    assert built.returncode == 0, built.stderr.decode()
    parked = run("park", "--url", kernel.url, "--file", str(request), token=kernel.token)
    assert parked.returncode == 0, parked.stderr.decode()

    # It reached the gate, which is only reachable once the mandate resolved.
    assert b"mandate-unresolved" not in parked.stdout + parked.stderr


def test_submit_mandate_tells_an_envelope_from_a_mandate(world: Any) -> None:
    """The refusal an operator actually met, and what it cost them.

    Following the README's `submit --file <the grant>` answered `schema-unknown-member: grantee` —
    a complaint about a member of the *inner* object, which reads as "your mandate is malformed"
    when the mandate is correct and the wrapping is what is missing. Both directions are named
    here instead.
    """
    kernel, ivan_file, mira_file, root = world
    work = root / "shapes"
    work.mkdir(exist_ok=True)

    not_a_mandate = work / "policy.json"
    not_a_mandate.write_text(json.dumps({"kind": "policy", "policy-version": "2026.07.1"}))
    refused = run(
        "submit-mandate",
        "--url", kernel.url,
        "--mandate", str(not_a_mandate),
        "--key", str(ivan_file),
        "--subject", kernel.human_root.subject,
        token=kernel.token,
    )
    assert refused.returncode != 0
    assert b"is not a mandate" in refused.stderr, refused.stderr.decode()

    already_wrapped = work / "wrapped.json"
    already_wrapped.write_text(
        json.dumps({"kind": "mandate", "stream": CORE_STREAM, "seq": 7, "mandate": {}})
    )
    refused = run(
        "submit-mandate",
        "--url", kernel.url,
        "--mandate", str(already_wrapped),
        "--key", str(ivan_file),
        "--subject", kernel.human_root.subject,
        token=kernel.token,
    )
    assert refused.returncode != 0
    assert b"already an envelope" in refused.stderr, refused.stderr.decode()


def test_an_operator_can_build_the_act_that_unwedges_a_stream(world: Any) -> None:
    """`spec/04 §7.2` shipped specified, gated and tested, and nothing minted one.

    The same shape as `submit-mandate` before it: an operation with no command has no user, and the
    kernel's own tests build the envelope by hand, which proves the ceremony works *given* the
    document while imitating the one step no operator could perform. This drives the shipped binary
    as a subprocess — a command exercised only through the library it wraps is a command nobody has
    run.
    """
    kernel, ivan_file, _mira_file, root = world
    out = root / "resume.json"
    bridge = "a" * 64

    built = run(
        "resume-request",
        "--stream", "gw:ivan-mbp:0001",
        "--resume-seq", "7",
        "--refused-object-hash", bridge,
        "--reason-code", "mandate-unresolved",
        "--requester", kernel.human_root.subject,
        "--key", str(ivan_file),
        "--mandate", "0" * 64,
        "--in-force", kernel.policy_version,
        "--out", str(out),
        token=kernel.token,
    )
    assert built.returncode == 0, built.stderr.decode()

    request = json.loads(out.read_text())
    document = json.loads((root / "resume.json.evidence").read_text())

    # §04 §7.2's closed member set, and nothing else in it.
    assert set(document) == {"stream", "resume-seq", "refused-object-hash", "reason-code"}
    assert document["resume-seq"] == 7, "the seq must survive as a number, not as its spelling"

    # Rule 2: the target names the same stream as the document, and `args-hash` is the document's
    # own hash — so the root's signature binds this position rather than "a resumption".
    assert request["action"] == "kernel.resume_stream"
    assert request["target"] == "stream:gw:ivan-mbp:0001"
    assert request["classification"] == "consequential"
    assert request["args-hash"] == object_hash(document)
    assert built.stdout.decode().strip() == object_hash(request)


def test_resume_publish_refuses_a_document_that_is_not_the_one_approved(world: Any) -> None:
    """The counterfactual that makes the command worth having.

    Re-reading the evidence and re-hashing it is the whole of rule 2's protection: a resume whose
    document was swapped after the signature would bridge a position nobody approved. It must fail
    on the operator's terminal rather than at the kernel, because by then the request is spent.
    """
    kernel, ivan_file, _mira_file, root = world
    out = root / "swapped.json"
    run(
        "resume-request",
        "--stream", "gw:ivan-mbp:0001",
        "--resume-seq", "7",
        "--refused-object-hash", "b" * 64,
        "--reason-code", "mandate-unresolved",
        "--requester", kernel.human_root.subject,
        "--key", str(ivan_file),
        "--mandate", "0" * 64,
        "--in-force", kernel.policy_version,
        "--out", str(out),
        token=kernel.token,
    )
    evidence = root / "swapped.json.evidence"
    document = json.loads(evidence.read_text())
    document["resume-seq"] = 8  # one position further on: a different wedge entirely
    evidence.write_text(json.dumps(document, separators=(",", ":"), sort_keys=True))

    refused = run(
        "resume-publish",
        "--url", kernel.url,
        "--request", str(out),
        "--key", str(ivan_file),
        token=kernel.token,
    )
    assert refused.returncode != 0
    assert b"is not the resume that was approved" in refused.stderr, refused.stderr.decode()


def test_resume_publish_tells_a_resume_from_any_other_request(world: Any) -> None:
    """`submit-mandate` answered `schema-unknown-member: grantee` when handed the wrong object — a
    complaint about the document when the wrapping was what was wrong, and a wrong instruction that
    produces a plausible error is worse than no instruction. This one says what it was handed."""
    kernel, ivan_file, _mira_file, root = world
    other = root / "not-a-resume.json"
    run(
        "root-request",
        "--requester", kernel.human_root.subject,
        "--key", str(ivan_file),
        "--mandate", "0" * 64,
        "--in-force", kernel.policy_version,
        "--retire", kernel.human_root.id,
        "--out", str(other),
        token=kernel.token,
    )
    refused = run(
        "resume-publish",
        "--url", kernel.url,
        "--request", str(other),
        "--key", str(ivan_file),
        token=kernel.token,
    )
    assert refused.returncode != 0
    assert b"kernel.retire_root, not to resume a stream" in refused.stderr, refused.stderr.decode()

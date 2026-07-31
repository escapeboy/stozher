"""The component half of `spec/08 §4.8`.

The harness's own tests live in the kernel and prove its judgement. What has to be proved here is
the other half of the contract: that this component answers the protocol as written, and — the part
easiest to get wrong and hardest to notice — that it does not move its chain for an envelope the
kernel refused.

A run happens once against a live kernel, in the deploy gate. These are the properties a green run
would not distinguish from a lucky one.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from stozher_gateway import crypto, signing
from stozher_gateway.conformance import SelfTest, sample_manifest

VECTORS = Path(__file__).resolve().parents[2] / "spec" / "vectors"


def key() -> signing.SigningKey:
    return signing.SigningKey.derived(bytes([0x11]) * 32, crypto.ROLE_DEVICE, 0, "agent:selftest")


def self_test() -> SelfTest:
    signer = key()
    return SelfTest(signer, sample_manifest("github", signer))


def context(at: str = "2026-07-26T09:00:00.000Z") -> dict[str, Any]:
    return {"at": at, "mandate-ref": "a" * 64, "policy-version": "conformance.1"}


def test_hello_names_the_key_the_manifest_was_signed_with() -> None:
    """The harness refuses a run where these differ, and it is right to.

    A component answering with one key while its manifest carries another would have the run certify
    one program's behaviour against another program's declaration — and the human signing the
    registration would be naming a component nobody tested.
    """
    signer = key()
    component = SelfTest(signer, sample_manifest("github", signer))
    hello = component.answer({"case": "hello"})
    assert hello["key"] == sample_manifest("github", signer)["sig"]["key"]
    assert hello["subject"] == signer.subject


def test_a_refused_attempt_does_not_take_a_chain_position() -> None:
    """§08 §4.8's position rule, which is invisible until the next envelope falls into the gap.

    Seven of §4.4's eight cases are refused. A component that counted them would come out of the
    group seven positions ahead of the kernel, and every envelope it emitted afterwards — including
    the whole offline queue — would be refused for a chain gap that has nothing to do with what it
    was being tested on.
    """
    component = self_test()
    first = component.answer(
        {
            "case": "emit",
            "context": context(),
            "action": "github.get_file",
            "count": 1,
        }
    )
    assert first["submissions"][0]["envelope"]["seq"] == 0

    refused = component.answer(
        {
            "case": "negative",
            "negative": "gate-authorization-missing",
            "context": context(),
            "expect": "refused",
        }
    )
    assert refused["submissions"][0]["envelope"]["seq"] == 1

    # The refused attempt used position 1 and did not take it.
    again = component.answer(
        {
            "case": "emit",
            "context": context(),
            "action": "github.get_file",
            "count": 1,
        }
    )
    assert again["submissions"][0]["envelope"]["seq"] == 1


def test_an_accepted_attempt_does_take_one() -> None:
    # The mirror of the rule above. `prohibited` is the case §4.4 requires the kernel to *record*,
    # so the position it used is occupied and the next envelope must follow it.
    component = self_test()
    attempt = component.answer(
        {
            "case": "negative",
            "negative": "prohibited-attempted",
            "context": context(),
            "expect": "accepted",
        }
    )
    assert attempt["submissions"][0]["envelope"]["execution"]["outcome"] == "attempted"
    following = component.answer(
        {"case": "emit", "context": context(), "action": "github.get_file", "count": 1}
    )
    assert following["submissions"][0]["envelope"]["seq"] == 1


def test_the_replay_pair_chains_the_first_and_reuses_the_authorization() -> None:
    component = self_test()
    answer = component.answer(
        {
            "case": "negative",
            "negative": "gate-authorization-replayed",
            "context": context(),
            "expect": "refused",
            "authorization": {"request": {"marker": 1}, "decision": {"marker": 2}},
            "target": "conformance:approved",
            "args-hash": "b" * 64,
        }
    )
    first, second = (s["envelope"] for s in answer["submissions"])
    assert second["seq"] == first["seq"] + 1, "the second attempt must be a new envelope, not a retry"
    assert first["authorization"] == second["authorization"], "the point of the case is reuse"


def test_the_vector_answers_reproduce_the_corpus() -> None:
    """A round of §4.1 against real vectors, with the expected values stripped as §4.8 requires."""
    component = self_test()
    corpus = json.loads((VECTORS / "sha256.json").read_text())
    requests = []
    expected = {}
    for vector in corpus["vectors"]:
        identifier = f"sha256/{vector['name']}"
        expected[identifier] = vector["sha256"]
        requests.append(
            {"id": identifier, "kind": "sha256", "input-hex": vector["input-hex"]}
        )
    answers = component.answer({"case": "vectors", "vectors": requests})["answers"]
    for identifier, digest in expected.items():
        assert answers[identifier]["sha256"] == digest, identifier


def test_an_unknown_case_is_an_error_object_rather_than_a_crash() -> None:
    # A crash closes the pipe, and the harness reports "the component closed its output" — true and
    # useless. An operator debugging their component needs the case named.
    component = self_test()
    assert "error" in component.answer({"case": "interpretive-dance"})


def test_a_case_that_raises_reports_itself_instead_of_dying() -> None:
    component = self_test()
    answer = component.answer({"case": "emit", "context": {}, "action": "github.get_file"})
    assert "error" in answer and "emit" in answer["error"]


def test_the_process_speaks_one_json_object_per_line(tmp_path: Path) -> None:
    """The transport, end to end, including the flush.

    A buffered answer is indistinguishable from a component that has hung, and the harness's only
    recourse would be its timeout — turning a working component into a failed run.
    """
    seed = tmp_path / "seed.hex"
    seed.write_text("11" * 32)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(sample_manifest("github", key())))

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "stozher_gateway.conformance",
            "--seed",
            str(seed),
            "--subject",
            "agent:selftest",
            "--manifest",
            str(manifest),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(json.dumps({"case": "hello"}) + "\n")
        process.stdin.flush()
        hello = json.loads(process.stdout.readline())
        assert hello["stream"] == "cf:selftest:0001"

        # A malformed line is answered, not fatal: the run continues and the operator learns which
        # request was unreadable.
        process.stdin.write("not json\n")
        process.stdin.flush()
        assert "error" in json.loads(process.stdout.readline())

        process.stdin.close()
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()

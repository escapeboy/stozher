"""The cross-language conformance contract: `spec/vectors/`, consumed by the gateway.

Every expected value is read from the vector files. Nothing here hardcodes a digest, a signature or
an error code — that rule is the entire reason the files exist, because two implementations that
each assert against their own constants cannot discover that they disagree. The Rust kernel runs the
same files.

Two anti-vacuity guards, matching S0/S1:

* an unrecognised vector `kind` **fails the run** rather than being skipped, so adding a kind to
  `index.json` breaks loudly until support is written;
* every file asserts a non-zero vector count against `index.json`'s own `count`, and the run asserts
  a non-zero total assertion count — a harness that silently stops looking is the failure mode a
  green suite hides best.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import chain as chain_module
from stozher_gateway import crypto, mandate, money, payload
from stozher_gateway.canonical import (
    CanonicalizationError,
    canonicalize,
    object_hash,
    parse,
    sha256_hex,
)
from stozher_gateway.envelope import EnvelopeError
from stozher_gateway.envelope import validate as validate_shape
from stozher_gateway.gate import Approver, GateRefusedError, verify_authorization
from stozher_gateway.signing import object_id, signing_input, verify_signed_object

VECTORS = Path(__file__).resolve().parents[2] / "spec" / "vectors"

#: Every assertion the run made, so an empty or short-circuiting harness cannot pass.
ASSERTIONS: list[str] = []


def check(condition: bool, label: str, detail: str = "") -> None:
    ASSERTIONS.append(label)
    assert condition, f"{label}{': ' + detail if detail else ''}"


def equal(actual: Any, expected: Any, label: str) -> None:
    ASSERTIONS.append(label)
    assert actual == expected, f"{label}: expected {expected!r}, got {actual!r}"


def load(path: str) -> dict[str, Any]:
    return json.loads((VECTORS / path).read_text())  # type: ignore[no-any-return]


INDEX = load("index.json")


def refusal(call: Callable[[], Any]) -> str | None:
    """Run `call` and return the normative reason code it refused with, or None on success."""
    try:
        call()
    except (CanonicalizationError, EnvelopeError, GateRefusedError, mandate.MandateRefusedError) as e:
        return e.code
    except chain_module.ChainError as e:
        return e.code
    except payload.PayloadError as e:
        return e.code
    return None


# --------------------------------------------------------------------------------------------
# one handler per `kind` in index.json
# --------------------------------------------------------------------------------------------


def handle_jcs(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    value = parse(vector["input-json"])
    equal(canonicalize(value), vector["canonical"], f"{label}/canonical")
    equal(
        sha256_hex(canonicalize(value).encode("utf-8")),
        vector["canonical-sha256"],
        f"{label}/canonical-sha256",
    )


def handle_jcs_invalid(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    equal(refusal(lambda: canonicalize(parse(vector["input-json"]))), vector["error"], label)


def handle_sha256(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    equal(sha256_hex(bytes.fromhex(vector["input-hex"])), vector["sha256"], label)


def handle_ed25519(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    message = bytes.fromhex(vector["message-hex"])
    if vector.get("secret-key"):
        secret = bytes.fromhex(vector["secret-key"])
        equal(crypto.sign(secret, message).hex(), vector["signature"], f"{label}/deterministic-sign")
        equal(
            crypto.public_key_of(secret).hex(), vector["public-key"], f"{label}/public-key-of-seed"
        )
    key = crypto.key_id(bytes.fromhex(vector["public-key"]))
    equal(crypto.verify(key, message, vector["signature"]), vector["verifies"], f"{label}/verifies")


def handle_slip10(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    private, chain_code = crypto.derive_path(bytes.fromhex(vector["seed"]), vector["path"])
    equal(private.hex(), vector["private-key"], f"{label}/private-key")
    equal(chain_code.hex(), vector["chain-code"], f"{label}/chain-code")
    public = crypto.public_key_of(private)
    equal(public.hex(), vector["public-key"], f"{label}/public-key")
    equal("00" + public.hex(), vector["slip10-public-key"], f"{label}/slip10-public-key")
    equal(crypto.key_id(public), vector["key-id"], f"{label}/key-id")


def handle_object_hash(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    obj = vector["object"]
    equal(canonicalize(obj), vector["expected-jcs"], f"{label}/jcs")
    equal(object_hash(obj), vector["expected-object-hash"], f"{label}/object-hash")
    if "expected-signing-input" in vector:
        equal(
            signing_input(obj).decode("utf-8"),
            vector["expected-signing-input"],
            f"{label}/signing-input",
        )
        equal(
            sha256_hex(signing_input(obj)),
            vector["expected-signing-input-sha256"],
            f"{label}/signing-input-sha256",
        )
    if "expected-signature-valid" in vector:
        equal(
            verify_signed_object(obj) is not None,
            vector["expected-signature-valid"],
            f"{label}/signature-valid",
        )


def handle_envelope(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    envelope = vector["envelope"]
    expected = vector["expected"]
    equal(
        sha256_hex(signing_input(envelope)),
        expected["signing-input-sha256"],
        f"{label}/signing-input-sha256",
    )
    equal(object_id(envelope), expected["envelope-hash"], f"{label}/envelope-hash")
    equal(
        verify_signed_object(envelope) is not None,
        expected["signature-valid"],
        f"{label}/signature-valid",
    )


def handle_envelope_shape(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    code = refusal(lambda: validate_shape(vector["envelope"]))
    equal(code is None, vector["expected"]["valid"], f"{label}/valid")
    equal(code, vector["expected"]["error"], f"{label}/error")


def handle_chain(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    expected = vector["expected"]
    try:
        report = chain_module.verify_chain(vector["envelopes"], vector["stream"])
    except chain_module.ChainError as e:
        check(not expected["valid"], f"{label}/valid", f"unexpected refusal {e.code}")
        equal(e.code, expected["error"], f"{label}/error")
        equal(e.seq, expected.get("failed-at-seq"), f"{label}/failed-at-seq")
        return
    check(expected["valid"], f"{label}/valid", "expected a refusal")
    equal(report.head_hash, expected["head-hash"], f"{label}/head-hash")
    equal(report.anchored, expected["anchored"], f"{label}/anchored")
    equal(report.count, expected["count"], f"{label}/count")


def handle_mandate_chain(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    expected = vector["expected"]
    request = vector["request"]
    try:
        ok = mandate.verify_mandate_chain(
            doc["mandates"],
            vector["leaf-ref"],
            mandate.MandateRequest(
                request["component"],
                request["action"],
                request["classification"],
                request["resource"],
            ),
            at=vector["at"],
            subject_key=vector["subject-key"],
            roots=doc["roots"],
            revocations=vector.get("revocations", []),
            max_depth=vector["max-delegation-depth"],
        )
    except mandate.MandateRefusedError as e:
        check(not expected["valid"], f"{label}/valid", f"unexpected refusal {e.code}")
        equal(e.code, expected["error"], f"{label}/error")
        return
    check(expected["valid"], f"{label}/valid", "expected a refusal")
    equal(ok.human_root, expected["human-root"], f"{label}/human-root")
    equal(ok.root_key, expected["root-key"], f"{label}/root-key")
    equal(ok.depth, expected["depth"], f"{label}/depth")


def _approvers(entries: list[Any]) -> list[Approver]:
    """`authorization.json` lists bare key strings; `parity.json` lists `{key, subject}` objects.

    A bare string is a key whose subject the deployment cannot name, which is exactly what
    `Approver.subject is None` means — so the older corpus keeps its meaning rather than acquiring
    a subject it never stated.
    """
    return [
        Approver(entry["key"], entry.get("subject"))
        if isinstance(entry, dict)
        else Approver(entry, None)
        for entry in entries
    ]


def _verify_authorization(vector: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    try:
        ok = verify_authorization(
            vector["envelope"],
            vector["requires-gate"],
            _approvers(vector["approvers"]),
            set(vector.get("seen-request-hashes", [])),
        )
    except GateRefusedError as e:
        check(not expected["valid"], f"{label}/valid", f"unexpected refusal {e.code}")
        equal(e.code, expected["error"], f"{label}/error")
        return
    check(expected["valid"], f"{label}/valid", "expected a refusal")
    if "request-hash" in expected:
        assert ok is not None
        equal(ok.request_hash, expected["request-hash"], f"{label}/request-hash")
        equal(ok.decided_by, expected["decided-by"], f"{label}/decided-by")
    if "single-use" in expected:
        assert ok is not None
        equal(ok.single_use, expected["single-use"], f"{label}/single-use")


def handle_authorization(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    _verify_authorization(vector, vector["expected"], label)


def handle_parity(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    """Branches on which two independent implementations of this specification disagreed.

    Dispatch is on the vector's own `algorithm`, and an unrecognised one fails rather than being
    skipped — the same anti-vacuity rule the file-level dispatch uses, applied one level down.
    `divergence` is documentation and is deliberately not asserted on.
    """
    expected = vector["expected"]
    algorithm = vector["algorithm"]
    if algorithm == "verify-authorization":
        _verify_authorization(vector["input"], expected, label)
        return
    assert algorithm == "verify-chain", f"{label}: no handler for algorithm {algorithm!r}"
    supplied = vector["input"]
    try:
        report = chain_module.verify_chain(
            supplied["envelopes"], supplied["stream"], supplied.get("expected-first-prev")
        )
    except chain_module.ChainError as e:
        check(not expected["valid"], f"{label}/valid", f"unexpected refusal {e.code}")
        equal(e.code, expected["error"], f"{label}/error")
        equal(e.seq, expected.get("failed-at-seq"), f"{label}/failed-at-seq")
        return
    check(expected["valid"], f"{label}/valid", "expected a refusal")
    equal(report.head_hash, expected["head-hash"], f"{label}/head-hash")


def handle_payload_binding(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    expected = vector["expected"]
    ingest = vector["ingest"]
    envelope = ingest["envelope"]
    try:
        decayed = payload.verify_ingest(envelope, ingest["payloads"])
    except payload.PayloadError as e:
        check(not expected["valid"], f"{label}/valid", f"unexpected refusal {e.code}")
        equal(e.code, expected["error"], f"{label}/error")
        return
    check(expected["valid"], f"{label}/valid", "expected a refusal")
    equal(object_id(envelope), expected["envelope-hash"], f"{label}/envelope-hash")
    equal(decayed, expected.get("decayed", False), f"{label}/decayed")
    if "chain" in vector:
        # §04 §5.1: the same chain verifies with every payload erased, and to the same head.
        report = chain_module.verify_chain(vector["chain"], vector["chain"][0]["stream"])
        equal(report.head_hash, expected["chain-head-hash"], f"{label}/chain-head-hash")
        equal(True, expected["chain-valid"], f"{label}/chain-valid")


def handle_money_compare(doc: dict[str, Any], vector: dict[str, Any], label: str) -> None:
    """Exact monetary comparison (§01 §2.5, §03 §4.3).

    The expected values are computed in `generate_vectors.py` by a third technique — integer tuples,
    no `Decimal` and no float — so agreement here is three implementations agreeing rather than this
    one checking itself. Answering these through `float()` fails the boundary vectors, which is why
    they are in the corpus at all.
    """
    try:
        observed = {-1: "less", 0: "equal", 1: "greater"}[
            money.compare(vector["left"], vector["right"])
        ]
    except money.MoneyFormatError:
        observed = "refused"
    assert observed == vector["expected"], (
        f"{label}: compare({vector['left']!r}, {vector['right']!r}) is {observed}, "
        f"the corpus says {vector['expected']}"
    )


HANDLERS: dict[str, Callable[[dict[str, Any], dict[str, Any], str], None]] = {
    "jcs": handle_jcs,
    "jcs-invalid": handle_jcs_invalid,
    "sha256": handle_sha256,
    "ed25519": handle_ed25519,
    "slip10-ed25519": handle_slip10,
    "object-hash": handle_object_hash,
    "envelope": handle_envelope,
    "envelope-shape": handle_envelope_shape,
    "chain": handle_chain,
    "mandate-chain": handle_mandate_chain,
    "authorization": handle_authorization,
    "payload-binding": handle_payload_binding,
    "money-compare": handle_money_compare,
    "parity": handle_parity,
}


@pytest.mark.parametrize("entry", INDEX["files"], ids=lambda entry: entry["path"])
def test_vector_file(entry: dict[str, Any]) -> None:
    doc = load(entry["path"])
    assert doc["kind"] == entry["kind"], f"{entry['path']}: kind disagrees with index.json"
    handler = HANDLERS.get(doc["kind"])
    # An unrecognised kind fails the run rather than being skipped (`spec/vectors/README.md` §1).
    assert handler is not None, f"{entry['path']}: no handler for kind {doc['kind']!r}"
    vectors = doc["vectors"]
    assert vectors, f"{entry['path']}: carries no vectors"
    assert len(vectors) == entry["count"], f"{entry['path']}: count disagrees with index.json"
    for vector in vectors:
        handler(doc, vector, f"{entry['path']}/{vector['name']}")


def test_the_run_asserted_something() -> None:
    """The whole suite is vacuous if the handlers stopped asserting; this is the guard."""
    assert len(INDEX["files"]) >= 13, "index.json lost vector files"
    assert len(ASSERTIONS) > 200, f"only {len(ASSERTIONS)} vector assertions ran"
    assert len(set(ASSERTIONS)) == len(ASSERTIONS), "an assertion label was reused"

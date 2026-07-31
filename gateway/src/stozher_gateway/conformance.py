"""The component half of the conformance harness — `spec/08 §4.8`.

`spec/08 §1.1` has always required a manifest to declare `conformance.self-test`, and the kernel has
always refused a manifest without one. This is that action: the mode in which the gateway lets itself
be certified.

**Why the component drives its own refusals.** §08 §4.4 requires eight attempts to fail, seven of
them envelopes signed by this component's key. A harness able to build those would need that key —
and a harness holding a component's key could forge exactly the attribution it is certifying. So the
harness says what the attempt is, this module signs it, and the kernel's answer is the measurement.

**Why this touches nothing.** §08 §4 requires a run to be re-runnable "with no component-side state".
Nothing here opens the gateway's store, its chain or its queue: the self-test builds envelopes in
memory, on a stream of its own, and exits. Two runs of the same component against the same harness
produce the same bytes, because the harness supplies the instant every envelope is stamped with.

**What it is not.** It is not a second implementation of the emitter. It signs with the same key
material, canonicalizes with the same module and chains with the same rule; what it does differently
is emit envelopes it knows to be invalid, which is the one thing production code must never do.

Usage::

    python -m stozher_gateway.conformance --seed <path> --manifest <path>
    python -m stozher_gateway.conformance --seed <path> --emit-manifest --name github

The first speaks §4.8 on stdin and stdout, one JSON object per line. The second prints a manifest
signed by the same key, so an operator has the pair a run needs.
"""

from __future__ import annotations

import argparse
import binascii
import json
import sys
from pathlib import Path
from typing import Any

from . import canonical, chain, clock as clock_module, crypto, signing

__all__ = ["SelfTest", "main"]

#: The stream the self-test writes. Its own, so a run never lands in the gateway's real chain.
STREAM = "cf:selftest:0001"
#: Mandate envelopes go on their own stream: one stream holds one kind (`stream-kind-mixed`), and
#: §4.4's rootless-chain attempt is a mandate envelope.
MANDATE_STREAM = "cf:selftest:mandates"


class SelfTest:
    """One conformance run's worth of component behaviour."""

    def __init__(self, key: signing.SigningKey, manifest: dict[str, Any]) -> None:
        self._key = key
        self._manifest = manifest
        # The next free position on the component's stream, and what precedes it. A refused envelope
        # never occupies a position, so this only moves when the harness says an attempt lands.
        self._seq = 0
        self._prev: str | None = None

    # -- dispatch ---------------------------------------------------------------------------------

    def answer(self, request: dict[str, Any]) -> dict[str, Any]:
        case = request.get("case")
        handler = {
            "hello": self._hello,
            "vectors": self._vectors,
            "emit": self._emit,
            "negative": self._negative,
            "offline": self._offline,
        }.get(str(case))
        if handler is None:
            return {"error": f"unknown case {case!r}"}
        try:
            return handler(request)
        except Exception as e:  # noqa: BLE001 - a self-test reports its own failures, never crashes
            # A crash would close the pipe, and the harness would report "the component closed its
            # output" — true, but useless. Naming the case and the fault is the difference between
            # an operator debugging their component and an operator debugging the harness.
            return {"error": f"{case}: {type(e).__name__}: {e}"}

    def _hello(self, _request: dict[str, Any]) -> dict[str, Any]:
        return {"subject": self._key.subject, "key": self._key.id, "stream": STREAM}

    # -- §4.1 -------------------------------------------------------------------------------------

    def _vectors(self, request: dict[str, Any]) -> dict[str, Any]:
        answers: dict[str, Any] = {}
        for vector in request.get("vectors") or []:
            answers[vector["id"]] = self._vector(vector)
        return {"answers": answers}

    def _vector(self, vector: dict[str, Any]) -> dict[str, Any]:
        kind = vector.get("kind")
        if kind == "jcs":
            value = canonical.parse(vector["input-json"])
            text = canonical.canonicalize(value)
            return {
                "canonical": text,
                "canonical-sha256": canonical.sha256_hex(text.encode("utf-8")),
            }
        if kind == "sha256":
            return {"sha256": canonical.sha256_hex(binascii.unhexlify(vector["input-hex"]))}
        if kind == "ed25519":
            return self._ed25519(vector)
        if kind == "object-hash":
            return self._object_hash(vector["object"])
        if kind == "chain":
            return {"expected": self._chain(vector)}
        raise ValueError(f"the harness asked for a vector kind nobody declared: {kind}")

    def _ed25519(self, vector: dict[str, Any]) -> dict[str, Any]:
        message = binascii.unhexlify(vector["message-hex"])
        answer: dict[str, Any] = {}
        # With a secret key the signature is ours to produce; without one it is given and only
        # verification is asked for (§08 §4.8).
        secret = vector.get("secret-key")
        if secret:
            signature = crypto.sign(binascii.unhexlify(secret), message)
            answer["signature"] = signature.hex()
        else:
            signature = binascii.unhexlify(vector["signature"])
        answer["verifies"] = crypto.verify(
            f"ed25519:{vector['public-key']}", message, signature.hex()
        )
        return answer

    def _object_hash(self, obj: Any) -> dict[str, Any]:
        answer: dict[str, Any] = {
            "expected-jcs": canonical.canonicalize(obj),
            "expected-object-hash": signing.object_id(obj),
            "expected-signature-valid": signing.verify_signed_object(obj) is not None,
        }
        if isinstance(obj, dict) and "sig" in obj:
            payload = signing.signing_input(obj)
            answer["expected-signing-input"] = payload.decode("utf-8")
            answer["expected-signing-input-sha256"] = canonical.sha256_hex(payload)
        return answer

    def _chain(self, vector: dict[str, Any]) -> dict[str, Any]:
        try:
            report = chain.verify_chain(vector["envelopes"], vector["stream"], None)
        except chain.ChainError as e:
            return {"valid": False, "error": e.code, "failed-at-seq": e.seq}
        return {
            "valid": True,
            "error": None,
            "head-hash": report.head_hash,
            "anchored": report.anchored,
            "count": report.count,
        }

    # -- envelope construction --------------------------------------------------------------------

    def _class_of(self, action: str) -> str:
        for declared in self._manifest.get("actions") or []:
            if declared.get("action") == action:
                return str(declared.get("class", "consequential"))
        return "consequential"

    def _effect(self, context: dict[str, Any], action: str, klass: str, **extra: Any) -> dict:
        at = context["at"]
        execution = {
            "action": action,
            "target": extra.pop("target", None) or "conformance:sample",
            "args-hash": extra.pop("args_hash", None)
            or canonical.sha256_hex(b"conformance-sample"),
            "outcome": extra.pop("outcome", "applied"),
            "started-at": at,
            "finished-at": at,
        }
        body: dict[str, Any] = {
            "v": "stozher/0.1",
            "kind": "effect",
            "emitted-at": at,
            "stream": STREAM,
            "seq": self._seq,
            "prev-hash": self._prev,
            "identity": {
                "subject": self._key.subject,
                "key": self._key.id,
                "component": "gateway",
            },
            "mandate-ref": context["mandate-ref"],
            "policy-version": context["policy-version"],
            "classification": klass,
            "execution": execution,
        }
        body.update({k.replace("_", "-"): v for k, v in extra.items() if v is not None})
        return self._key.sign(body)

    def _commit(self, envelope: dict[str, Any]) -> None:
        """Take the position an accepted envelope occupies."""
        self._seq = int(envelope["seq"]) + 1
        self._prev = signing.object_id(envelope)

    def _with_evidence(self, context: dict[str, Any], action: str, klass: str, **extra: Any):
        body = {"path": "README.md"} if klass == "read" else {"title": "conformance"}
        payload_hash = canonical.object_hash(body)
        # `read` retains for nothing at all under the baseline profile, so the retention asked for
        # is the instant itself; anything later is clamped, and asking for what cannot be had is a
        # component making a promise the kernel will quietly refuse to keep.
        retain_until = context["at"] if klass == "read" else context.get("retain-until", context["at"])
        envelope = self._effect(
            context,
            action,
            klass,
            evidence={
                "schema": f"{action}.v1",
                "media-type": "application/json",
                "payload-hash": payload_hash,
                "retain-until": retain_until,
            },
            **extra,
        )
        return {
            "envelope": envelope,
            "payloads": [
                {
                    "payload-hash": payload_hash,
                    "media-type": "application/json",
                    "payload": body,
                }
            ],
        }

    # -- §4.2 and §4.3 ----------------------------------------------------------------------------

    def _emit(self, request: dict[str, Any]) -> dict[str, Any]:
        context = request["context"]
        action = request["action"]
        klass = self._class_of(action)
        count = int(request.get("count", 1))

        if count > 1:
            envelope = self._aggregate(context, action, count)
            self._commit(envelope)
            return {"submissions": [{"envelope": envelope, "payloads": []}]}

        submission = self._with_evidence(
            context,
            action,
            klass,
            target=request.get("target"),
            args_hash=request.get("args-hash"),
            authorization=request.get("authorization"),
        )
        self._commit(submission["envelope"])
        return {"submissions": [submission]}

    def _aggregate(self, context: dict[str, Any], action: str, count: int) -> dict[str, Any]:
        at = context["at"]
        return self._key.sign(
            {
                "v": "stozher/0.1",
                "kind": "aggregate",
                "emitted-at": at,
                "stream": STREAM,
                "seq": self._seq,
                "prev-hash": self._prev,
                "identity": {
                    "subject": self._key.subject,
                    "key": self._key.id,
                    "component": "gateway",
                },
                "mandate-ref": context["mandate-ref"],
                "policy-version": context["policy-version"],
                "classification": "read",
                "window": {"from": at, "to": at},
                "counts": {"total": count, "by-action": {action: count}},
                "sample-hashes": [
                    canonical.sha256_hex(b"first"),
                    canonical.sha256_hex(b"last"),
                ],
            }
        )

    # -- §4.4 -------------------------------------------------------------------------------------

    def _negative(self, request: dict[str, Any]) -> dict[str, Any]:
        context = request["context"]
        case = request["negative"]
        action = request.get("action") or "github.create_issue"
        gated = {
            "authorization": request.get("authorization"),
            "target": request.get("target"),
            "args_hash": request.get("args-hash"),
        }

        if case == "gate-authorization-missing":
            submissions = [self._bare(self._effect(context, action, "consequential"))]
        elif case == "gate-authorization-action-mismatch":
            # A real approval, over a target this envelope does not name. Both halves have to be
            # genuine, or the kernel refuses it for the wrong reason and the case proves nothing.
            submissions = [self._bare(self._effect(context, action, "consequential", **gated))]
        elif case == "gate-authorization-replayed":
            first = self._effect(context, action, "consequential", **gated)
            self._commit(first)
            second = self._effect(context, action, "consequential", **gated)
            submissions = [self._bare(first), self._bare(second)]
        elif case == "mandate-expired":
            submissions = [self._bare(self._effect(context, "github.get_file", "read"))]
        elif case == "mandate-root-not-human":
            submissions = [self._bare(self._rootless_mandate(context))]
        elif case == "prohibited-attempted":
            submissions = [
                self._bare(
                    self._effect(context, "github.delete_repo", "prohibited", outcome="attempted")
                )
            ]
        elif case == "cognition-with-evidence":
            submissions = [self._bare(self._cognition_with_evidence(context))]
        else:
            raise ValueError(f"the harness asked for a case §08 §4.4 does not define: {case}")

        if request.get("expect") == "accepted":
            self._commit(submissions[-1]["envelope"])
        return {"submissions": submissions}

    @staticmethod
    def _bare(envelope: dict[str, Any]) -> dict[str, Any]:
        return {"envelope": envelope, "payloads": []}

    def _rootless_mandate(self, context: dict[str, Any]) -> dict[str, Any]:
        """A standing mandate this component grants authority with, rooted in an agent.

        `spec/03 §1` wants a root mandate's grantor to be a human. This kernel refuses to *store*
        such a chain at all, so the refusal arrives when the chain is introduced rather than when it
        is used — stronger than §4.4 describes, and carrying the code §4.4 names.
        """
        at = context["at"]
        # A key other than the grantor's: §03 §1 forbids self-grant, and tripping that would be
        # refused before the rootless chain was ever examined.
        child = crypto.key_id(crypto.public_key_of(bytes([0x22]) * 32))
        mandate = self._key.sign(
            {
                "v": "stozher/0.1",
                "kind": "mandate",
                "mandate-kind": "standing",
                "grantor": {
                    "subject": self._key.subject,
                    "key": self._key.id,
                    "role": "agent",
                },
                "grantee": {"subject": "agent:selftest-child", "key": child},
                "issued-at": at,
                "not-before": at,
                "not-after": clock_module.shift(at, 60 * 60 * 24),
                "parent": None,
                "max-depth": 1,
                "scope": {
                    "components": ["gateway"],
                    "actions": ["github.*"],
                    "classes": ["read"],
                    "resources": ["*"],
                },
                "nonce": "0000000000000000000000000000cccc",
            }
        )
        return self._key.sign(
            {
                "v": "stozher/0.1",
                "kind": "mandate",
                "emitted-at": at,
                "stream": MANDATE_STREAM,
                "seq": 0,
                "prev-hash": None,
                "identity": {
                    "subject": self._key.subject,
                    "key": self._key.id,
                    "component": "gateway",
                },
                "mandate": mandate,
            }
        )

    def _cognition_with_evidence(self, context: dict[str, Any]) -> dict[str, Any]:
        at = context["at"]
        return self._key.sign(
            {
                "v": "stozher/0.1",
                "kind": "cognition",
                "emitted-at": at,
                "stream": STREAM,
                "seq": self._seq,
                "prev-hash": self._prev,
                "identity": {
                    "subject": self._key.subject,
                    "key": self._key.id,
                    "component": "gateway",
                },
                "mandate-ref": context["mandate-ref"],
                "policy-version": context["policy-version"],
                "classification": "benign",
                "model": {"provider": "anthropic", "name": "claude", "version": "1"},
                "evidence": {
                    "schema": "github.get_file.v1",
                    "media-type": "application/json",
                    "payload-hash": canonical.sha256_hex(b"nothing"),
                    "retain-until": at,
                },
            }
        )

    # -- §4.5 -------------------------------------------------------------------------------------

    def _offline(self, request: dict[str, Any]) -> dict[str, Any]:
        context = request["context"]
        gated = request["gated"]
        submissions: list[dict[str, Any]] = []
        blocked: list[str] = []
        for action in request.get("actions") or []:
            if action == gated:
                # Consequential under a gate rule, and nobody could have approved it while the
                # kernel was away. The record of having declined is what makes the refusal auditable
                # rather than invisible.
                envelope = self._effect(context, action, "consequential", outcome="blocked")
                blocked.append(action)
            else:
                envelope = self._effect(context, action, self._class_of(action))
            self._commit(envelope)
            submissions.append(self._bare(envelope))
        return {"submissions": submissions, "blocked": blocked}


def sample_manifest(name: str, key: signing.SigningKey) -> dict[str, Any]:
    """A manifest for the self-test, signed by the key the run will certify.

    The harness checks that the key saying hello is the key the manifest was signed with, so the two
    have to be produced together or a run certifies one component's behaviour against another's
    declaration.
    """
    return key.sign(
        {
            "v": "stozher/0.1",
            "kind": "manifest",
            "name": name,
            "version": "1.0.0",
            "subject-class": "tool-proxy",
            "description": "the gateway's conformance self-test",
            "actions": [
                {
                    "action": f"{name}.get_file",
                    "class": "read",
                    "evidence-schema": f"{name}.get_file.v1",
                    "aggregate": {"sampling": "first-and-last", "max-samples": 8},
                    "idempotent": True,
                    "target-kind": "repo-path",
                },
                {
                    "action": f"{name}.create_issue",
                    "class": "consequential",
                    "evidence-schema": f"{name}.create_issue.v1",
                    "idempotent": False,
                    "target-kind": "repo",
                    "degrade": None,
                },
            ],
            "evidence-schemas": {
                f"{name}.get_file.v1": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {"path": {"type": "string"}},
                    "additionalProperties": False,
                },
                f"{name}.create_issue.v1": {
                    "type": "object",
                    "required": ["title"],
                    "properties": {"title": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            "budget-dimensions": ["requests", "wall-clock-seconds"],
            "durable-objects": [
                {
                    "object-type": f"{name}.ticket",
                    "id-kind": "ticket-id",
                    "transitions": [
                        {
                            "transition": "opened",
                            "from": [],
                            "to": "open",
                            "signers": ["agent"],
                        },
                        {
                            "transition": "closed",
                            "from": ["open"],
                            "to": "closed",
                            "signers": ["agent"],
                        },
                        {
                            "transition": "approved",
                            "from": ["open"],
                            "to": "approved",
                            "signers": ["human"],
                        },
                    ],
                }
            ],
            "conformance": {"self-test": f"{name}.selftest", "vectors-version": "stozher/0.1"},
        }
    )


def _key(seed_path: Path, subject: str) -> signing.SigningKey:
    seed = binascii.unhexlify(seed_path.read_text().strip())
    return signing.SigningKey.derived(seed, crypto.ROLE_DEVICE, 0, subject)


def main(argv: list[str] | None = None) -> int:
    """Speak `spec/08 §4.8` on stdin and stdout, or print a manifest and exit."""
    parser = argparse.ArgumentParser(prog="stozher_gateway.conformance")
    parser.add_argument("--seed", type=Path, required=True, help="the identity seed file")
    parser.add_argument("--subject", default="agent:gateway/conformance")
    parser.add_argument("--manifest", type=Path, help="the manifest under test")
    parser.add_argument("--emit-manifest", action="store_true", help="print a signed manifest")
    parser.add_argument("--name", default="github", help="the component name for --emit-manifest")
    args = parser.parse_args(argv)

    key = _key(args.seed, args.subject)
    if args.emit_manifest:
        print(json.dumps(sample_manifest(args.name, key), indent=2))
        return 0
    if args.manifest is None:
        parser.error("--manifest is required unless --emit-manifest is given")

    self_test = SelfTest(key, json.loads(args.manifest.read_text()))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            answer: dict[str, Any] = {"error": f"the request is not JSON: {e}"}
        else:
            answer = self_test.answer(request)
        # One object per line, flushed: the harness reads a line and waits, so a buffered answer is
        # indistinguishable from a component that has hung.
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

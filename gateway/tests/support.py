"""Test support: a real kernel binary, a real genesis ceremony, and a real operator.

Nothing here reaches around a pipeline. The kernel is the compiled binary serving HTTP; the ceremony
is the same two envelopes an operator would submit (`spec/05` §5.2, ADR-0006 §2); the policy is a
signed document this side builds and the kernel verifies against the enrolled policy key. If any of
that were faked, the end-to-end test would prove that the gateway agrees with a mock.
"""

from __future__ import annotations

import atexit
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import canonicalize_bytes, object_hash, sha256_hex
from stozher_gateway.crypto import ROLE_DEVICE, derive
from stozher_gateway.signing import SigningKey, object_id

REPO = Path(__file__).resolve().parents[2]
KERNEL_BINARY = REPO / "kernel" / "target" / "debug" / "stozher-kernel"
CORE_STREAM = "kernel:core"
POLICY_VERSION = "2026.07.1"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


#: The copy this test session runs, taken once and reused. Set by `build_kernel`.
_SESSION_BINARY: Path | None = None


def build_kernel() -> Path:
    """Build the kernel once, then run every test in this session against a **copy** of it.

    The gate runs against the real binary, not a stub. But `cargo build` replaces
    `target/debug/stozher-kernel` in place, and a concurrent build in the same working tree — a
    watcher, a second shell, the Rust suite running beside this one — can therefore swap the file
    out from under a kernel this suite is in the middle of starting. ADR-0009 §6 recorded that
    exact suspicion for an intermittency observed twice in ~25 runs and never reproduced: the S2
    module fixture erroring immediately after a heavy cargo run in the same shell.

    Copying the binary aside removes the race whether or not that was the cause. It is cheap, it
    is deterministic, and it makes the suite independent of anything else compiling at the time —
    which is a property worth having on its own terms, not only as a fix for one flake.
    """
    global _SESSION_BINARY
    if _SESSION_BINARY is not None and _SESSION_BINARY.exists():
        return _SESSION_BINARY
    # **Always build.** This used to be `if not KERNEL_BINARY.exists()`, and in CI the gateway job
    # restores `kernel/target` from a cache keyed on `Cargo.lock` — which does not change when Rust
    # *source* does. So the binary existed, the build was skipped, and this suite spent days testing
    # the gateway against a kernel from some earlier commit.
    #
    # It cost most of a day on DEF-7: three separate diagnostics were added to the kernel and none
    # of them ever appeared in a failure, because the kernel running in CI did not contain them.
    # The fix for the concurrent-submission window looked like it had not worked, for the same
    # reason. The docstring below calls this suite "the real binary, not a stub" and it was true of
    # every local run and false of every CI run.
    #
    # Letting cargo decide is the whole point: it is incremental, it is the authority on whether
    # anything needs doing, and a warm cache makes a no-op build cost about a second. A guard that
    # second-guesses it can only ever be wrong in this direction.
    if shutil.which("cargo") is None:  # pragma: no cover - CI always has cargo
        raise RuntimeError("cargo is needed to build the kernel for the integration gate")
    subprocess.run(
        ["cargo", "build", "--bin", "stozher-kernel"],
        cwd=REPO / "kernel",
        check=True,
        capture_output=True,
    )
    session = Path(tempfile.gettempdir()) / f"stozher-kernel-{os.getpid()}"
    shutil.copy2(KERNEL_BINARY, session)
    session.chmod(0o755)
    atexit.register(lambda: session.unlink(missing_ok=True))
    _SESSION_BINARY = session
    return session


def baseline_policy(
    version: str, issued_at: str, approver: str, extra_by_action: dict[str, str] | None = None
) -> dict[str, Any]:
    """`baseline-conservative`, plus the two gateway actions an org running enforcement declares.

    `gateway.session_open` is `benign` per §10 §1.6, but `default-unknown` is `consequential`, so an
    org that does not classify it would gate its own sessions open. The organization states it here,
    which is where classification belongs.
    """
    document = {
        "v": "stozher/0.1",
        "kind": "policy",
        "policy-version": version,
        "issued-at": issued_at,
        "profile": "baseline-conservative",
        "revoke-cached": False,
        "max-staleness-seconds": 300,
        "checkpoint-interval": "PT1H",
        "aggregate-max-window": "PT5M",
        "classification": {
            "default-unknown": "consequential",
            "by-action": {
                "fs.read_file": "read",
                "gateway.session_open": "benign",
                "github.create_issue": "consequential",
                "github.delete_repo": "prohibited",
                "github.get_file": "read",
                "github.get_file_contents": "read",
                "github.list_issues": "read",
                "kernel.conformance_run": "benign",
                "kernel.enroll_root": "consequential",
                "kernel.erase_payload": "consequential",
                "kernel.publish_policy": "consequential",
                "kernel.register_component": "consequential",
                "kernel.retire_root": "consequential",
                "kernel.seed_catalog_entry": "consequential",
                "slack.post_message": "consequential",
            },
            "reclassify": [],
        },
        "gate-rules": [
            {"classes": ["prohibited"], "decision": "deny"},
            {"classes": ["consequential"], "decision": "gate", "approvers": [approver]},
            {"classes": ["read", "benign"], "decision": "allow"},
        ],
        "evidence-ttl": {
            "read": "P0D",
            "benign": "P30D",
            "consequential": "P365D",
            "prohibited": "P3650D",
        },
        "budgets": {"defaults": {"requests": 10000, "money-eur": "50.00"}},
        "delegation": {"max-depth": 3, "max-standing-lifetime": "P90D"},
        "offline": {"read": "allow", "benign": "allow", "consequential": "block", "prohibited": "block"},
    }
    # What an operator would paste from `stozher-gateway catalog policy-fragment` once a tool has
    # been classified — the step that makes an org-seeded class authoritative for the kernel too.
    document["classification"]["by-action"].update(extra_by_action or {})  # type: ignore[index]
    return document


class Kernel:
    """A live kernel process plus the operator keys that bootstrapped it."""

    def __init__(
        self,
        root: Path,
        gateway_seed: bytes,
        gateway_subject: str,
        notifications: list[dict[str, Any]] | None = None,
    ) -> None:
        #: Approver-ping channels, in the kernel's own configuration shape. Secrets are named by
        #: environment variable, never carried here (ADR-0002, `notify` module).
        self.notifications = notifications or []
        self.root = root
        self.token = secrets.token_urlsafe(24)
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.human_root = SigningKey(bytes.fromhex("11" * 32), "human:ivan")
        self.second_root = SigningKey(bytes.fromhex("12" * 32), "human:mira")
        self.policy_key = SigningKey(bytes.fromhex("13" * 32), "org:policy")
        self.bootstrap = SigningKey(bytes.fromhex("14" * 32), "agent:bootstrap")
        self.gateway_key = SigningKey(derive(gateway_seed, ROLE_DEVICE, 0), gateway_subject)
        self.process: subprocess.Popen[bytes] | None = None
        self.policy_document: dict[str, Any] = {}
        self.gateway_mandate: dict[str, Any] = {}
        self.bootstrap_mandate = ""
        self.policy_version = ""

    # -- lifecycle ---------------------------------------------------------------------------

    def start(self) -> None:
        enrolled = "2026-01-01T00:00:00.000Z"
        config = {
            "bind": f"127.0.0.1:{self.port}",
            "database": str(self.root / "kernel.db"),
            "kernel-seed": str(self._seed_file()),
            "policy-key": self.policy_key.id,
            "roots": [
                {"subject": self.human_root.subject, "key": self.human_root.id, "enrolled-at": enrolled},
                {
                    "subject": self.second_root.subject,
                    "key": self.second_root.id,
                    "enrolled-at": enrolled,
                },
            ],
            "callers": [
                {"subject": "agent:gateway", "token-sha256": sha256_hex(self.token.encode())}
            ],
            "notifications": self.notifications,
            "console-base-url": self.url,
        }
        path = self.root / "kernel-config.json"
        path.write_text(json.dumps(config))
        self.process = subprocess.Popen(
            [str(build_kernel()), "serve", "--config", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._await_health()
        self.bootstrap_ceremony()

    def _seed_file(self) -> Path:
        path = self.root / "kernel.seed"
        path.write_text(secrets.token_hex(32))
        path.chmod(0o600)
        return path

    def _await_health(self, timeout: float = 20.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{self.url}/health", timeout=1.0) as response:
                    if response.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                time.sleep(0.1)
        raise RuntimeError("the kernel did not come up")

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None

    # -- HTTP --------------------------------------------------------------------------------

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, dict[str, Any]]:
        data = canonicalize_bytes(body) if body is not None else None
        request = urllib.request.Request(f"{self.url}{path}", data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10.0) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def submit(self, envelope: dict[str, Any], payloads: list[dict[str, Any]] | None = None) -> None:
        status, body = self.request(
            "POST", "/v1/ingest", {"envelope": envelope, "payloads": payloads or []}
        )
        if status not in (200, 201):
            raise AssertionError(f"the kernel refused a fixture envelope: {body}")

    def head(self, stream: str) -> tuple[int, str | None]:
        # A failed verification carries `valid: false`; a successful one carries the head hash.
        status, body = self.request("GET", f"/v1/streams/{stream}/verify")
        if status != 200 or body.get("valid") is False or "head-hash" not in body:
            return 0, None
        return int(body["count"]), str(body["head-hash"])

    # -- the ceremony -------------------------------------------------------------------------

    def bootstrap_ceremony(self) -> None:
        """The two genesis envelopes, then a standing mandate for the gateway's device key."""
        now = clock_module.now()
        interactive = self.human_root.sign(
            {
                "v": "stozher/0.1",
                "kind": "mandate",
                "mandate-kind": "interactive",
                "grantor": {
                    "subject": self.human_root.subject,
                    "key": self.human_root.id,
                    "role": "human",
                },
                "grantee": {"subject": self.bootstrap.subject, "key": self.bootstrap.id},
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
        self.submit(
            self.bootstrap.sign(
                {
                    "v": "stozher/0.1",
                    "kind": "mandate",
                    "emitted-at": now,
                    "stream": CORE_STREAM,
                    "seq": 0,
                    "prev-hash": None,
                    "identity": {
                        "subject": self.bootstrap.subject,
                        "key": self.bootstrap.id,
                        "component": "kernel",
                    },
                    "mandate": interactive,
                }
            )
        )
        self.bootstrap_mandate = object_id(interactive)
        self.publish_policy(POLICY_VERSION)
        self.gateway_mandate = self.grant_to_gateway()

    def publish_policy(self, version: str, extra_by_action: dict[str, str] | None = None) -> None:
        """Publish a policy version through the ordinary gated path (§05 §5).

        Used twice: once as `seq` 1 of the ceremony, and once again when the organization makes an
        org-seeded classification authoritative for the kernel as well as for the gateway.
        """
        now = clock_module.now()
        document = self.policy_key.sign(
            baseline_policy(version, now, self.human_root.subject, extra_by_action)
        )
        self.policy_document = document
        document_hash = object_hash(document)
        target = f"policy:{version}"
        outgoing = self.policy_version or version
        authorization = self.authorize(
            subject=self.bootstrap,
            component="kernel",
            mandate_ref=self.bootstrap_mandate,
            policy_version=outgoing,
            classification="consequential",
            action="kernel.publish_policy",
            target=target,
            args_hash=document_hash,
            at=now,
        )
        seq, prev = self.head(CORE_STREAM)
        self.submit(
            self.bootstrap.sign(
                {
                    "v": "stozher/0.1",
                    "kind": "policy-change",
                    "emitted-at": now,
                    "stream": CORE_STREAM,
                    "seq": seq,
                    "prev-hash": prev,
                    "identity": {
                        "subject": self.bootstrap.subject,
                        "key": self.bootstrap.id,
                        "component": "kernel",
                    },
                    "mandate-ref": self.bootstrap_mandate,
                    "policy-version": outgoing,
                    "classification": "consequential",
                    "execution": {
                        "action": "kernel.publish_policy",
                        "target": target,
                        "args-hash": document_hash,
                        "outcome": "applied",
                        "started-at": now,
                        "finished-at": now,
                    },
                    "evidence": {
                        "schema": "kernel.publish_policy.v1",
                        "media-type": "application/json",
                        "payload-hash": document_hash,
                        "retain-until": clock_module.shift(now, 365 * 86400),
                    },
                    "authorization": authorization,
                }
            ),
            [
                {
                    "payload-hash": document_hash,
                    "media-type": "application/json",
                    "payload": document,
                }
            ],
        )
        self.policy_version = version

    def grant_to_gateway(self) -> dict[str, Any]:
        """A standing mandate for the gateway's derived device key, signed by a human root."""
        now = clock_module.now()
        return self.human_root.sign(
            {
                "v": "stozher/0.1",
                "kind": "mandate",
                "mandate-kind": "standing",
                "grantor": {
                    "subject": self.human_root.subject,
                    "key": self.human_root.id,
                    "role": "human",
                },
                "grantee": {
                    "subject": self.gateway_key.subject,
                    "key": self.gateway_key.id,
                },
                "issued-at": clock_module.shift(now, -60),
                "not-before": clock_module.shift(now, -60),
                "not-after": clock_module.shift(now, 30 * 86400),
                "parent": None,
                "max-depth": 1,
                "scope": {
                    "components": ["gateway"],
                    "actions": ["github.*", "gateway.*", "kernel.*", "harbormaster.*"],
                    "classes": ["read", "benign", "consequential", "prohibited"],
                    "resources": ["*"],
                },
                "nonce": secrets.token_hex(16),
            }
        )

    def authorize(
        self,
        subject: SigningKey,
        component: str,
        mandate_ref: str,
        policy_version: str,
        classification: str,
        action: str,
        target: str,
        args_hash: str,
        at: str | None = None,
    ) -> dict[str, Any]:
        now = at or clock_module.now()
        # The decision is taken before the effect is emitted, which is the only order §06 §2 step
        # (9) accepts: an approval cannot be used before it was granted.
        decided_at = clock_module.shift(now, -1)
        request = {
            "v": "stozher/0.1",
            "kind": "action-request",
            "requested-at": now,
            "subject": subject.subject,
            "key": subject.id,
            "component": component,
            "mandate-ref": mandate_ref,
            "policy-version": policy_version,
            "classification": classification,
            "action": action,
            "target": target,
            "args-hash": args_hash,
            "nonce": secrets.token_hex(16),
            "not-after": clock_module.shift(now, 3600),
        }
        decision = self.human_root.sign(
            {
                "v": "stozher/0.1",
                "kind": "gate-decision",
                "request-hash": object_hash(request),
                "decision": "approve",
                "decided-at": decided_at,
                "not-after": clock_module.shift(now, 900),
                "single-use": True,
                "reason": None,
            }
        )
        return {"request": request, "decision": decision}


def gateway_config_file(
    root: Path, kernel: Kernel, seed_file: Path, mandate_file: Path, server_command: list[str]
) -> Path:
    """A `stozher-gateway.toml` an operator would write. It names no Harbormaster key at all."""
    roots = "\n".join(
        f'[[org.roots]]\nsubject = "{key.subject}"\nkey = "{key.id}"\n'
        for key in (kernel.human_root, kernel.second_root)
    )
    arguments = ", ".join(json.dumps(argument) for argument in server_command[1:])
    path = root / "stozher-gateway.toml"
    path.write_text(
        f"""
[gateway]
enabled = true
device = "test-mbp"
govern_native_tools = false
aggregate_max_events = 500

[kernel]
url = "{kernel.url}"
token_env = "STOZHER_KERNEL_TOKEN"
timeout_seconds = 5.0
policy_refresh_seconds = 5

[identity]
seed_file = "{seed_file}"

[org]
policy_key = "{kernel.policy_key.id}"

{roots}

[[callers]]
name = "claude-code"
subject = "agent:claude-code/test-mbp"
key_index = 0
token_sha256 = "{sha256_hex(b"caller-token")}"
mandate_file = "{mandate_file}"
mandate_kind = "standing"

[[servers]]
name = "github"
transport = "stdio"
command = {json.dumps(server_command[0])}
args = [{arguments}]
"""
    )
    return path


def gateway_environment(config: Path, database: Path, seed: Path, kernel: Kernel) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "STOZHER_GATEWAY_CONFIG": str(config),
            "STOZHER_GATEWAY_DB": str(database),
            "STOZHER_GATEWAY_SEED": str(seed),
            "STOZHER_GATEWAY_CALLER": "claude-code",
            "STOZHER_GATEWAY_CALLER_TOKEN": "caller-token",
            "STOZHER_KERNEL_TOKEN": kernel.token,
        }
    )
    return environment

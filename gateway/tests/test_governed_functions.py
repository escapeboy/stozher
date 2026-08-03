"""`@governor.governed` — the integrator's rejection, answered.

An engineer with a working Python agent system evaluated this product and rejected it: their tools
were plain functions, the only way in was to re-expose all of them as an MCP server, the adaptation
layer came to 134 lines against a 123-line application, and their tool state had to leave their
process. Their driver's own assertions then read an empty ledger.

The subprocess was never buying a security property. The gateway holds one private key — its own
emitter seed — and `org.roots` holds public key ids; the approving key is on a human's machine
either way, and the gateway process is spawned by the agent's own MCP client as the same user on
the same host. What these tests hold is that the in-process path is the *same* enforcement, not a
lighter one: same classification, same gate, same envelopes, same refusal, and the state stays put.
"""

from __future__ import annotations

import contextlib
import secrets
from pathlib import Path
from typing import Any

import pytest

from stozher_gateway import clock as clock_module
from stozher_gateway.canonical import sha256_hex
from stozher_gateway.config import GatewayConfig
from stozher_gateway.governed import Governor
from stozher_gateway.refusal import RefusalError
from stozher_gateway.signing import SigningKey

from .support import baseline_policy

ROOT = SigningKey(bytes.fromhex("21" * 32), "human:ivan")
POLICY_KEY = SigningKey(bytes.fromhex("23" * 32), "org:policy")


@pytest.fixture
def governor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A Governor over a real store and a real enforcer, with no kernel behind it.

    The kernel is absent on purpose, exactly as in `test_enforcement.py`: the local chain is the
    record of truth until the kernel has it, and everything asserted here is what the component did
    before anything was pushed.
    """
    now = clock_module.now()
    seed = tmp_path / "identity.seed"
    seed.write_text(secrets.token_hex(32))
    seed.chmod(0o600)
    mandate_file = tmp_path / "mandate.json"

    config = GatewayConfig.model_validate(
        {
            "gateway": {"enabled": True, "device": "test", "state_db": str(tmp_path / "gw.db")},
            "kernel": {"url": "http://127.0.0.1:9"},
            "identity": {"seed_file": str(seed)},
            "org": {"policy_key": POLICY_KEY.id, "roots": [{"subject": ROOT.subject, "key": ROOT.id}]},
            "callers": [
                {
                    "name": "opsbot",
                    "subject": "agent:opsbot/test",
                    "mandate_file": str(mandate_file),
                    "mandate_kind": "standing",
                    "token_sha256": sha256_hex(b"opsbot-token"),
                }
            ],
        }
    )
    monkeypatch.setenv("STOZHER_GATEWAY_SEED", str(seed))
    monkeypatch.setenv("STOZHER_GATEWAY_CALLER_TOKEN", "opsbot-token")

    governor = Governor(config)
    # The caller key is derived from the seed the config names, so the mandate has to be granted to
    # *that* key — a fixture whose grantee is a constant would make the gateway refuse for a reason
    # that has nothing to do with the test.
    from stozher_gateway import crypto

    caller_key = SigningKey.derived(bytes.fromhex(seed.read_text()), crypto.ROLE_DEVICE, 0, "agent:opsbot/test")
    mandate_file.write_text(
        __import__("json").dumps(
            ROOT.sign(
                {
                    "v": "stozher/0.1",
                    "kind": "mandate",
                    "mandate-kind": "standing",
                    "grantor": {"subject": ROOT.subject, "key": ROOT.id, "role": "human"},
                    "grantee": {"subject": "agent:opsbot/test", "key": caller_key.id},
                    "issued-at": clock_module.shift(now, -60),
                    "not-before": clock_module.shift(now, -60),
                    "not-after": clock_module.shift(now, 86400),
                    "parent": None,
                    "max-depth": 1,
                    "scope": {
                        "components": ["gateway"],
                        "actions": ["ops.*"],
                        "classes": ["read", "benign", "consequential", "prohibited"],
                        "resources": ["*"],
                    },
                    "nonce": secrets.token_hex(16),
                }
            )
        )
    )
    policy = POLICY_KEY.sign(
        baseline_policy("2026.07.1", now, ROOT.subject, {"ops.tail_logs": "read"})
    )
    governor._gateway.store.cache_policy("2026.07.1", policy, now)
    yield governor
    # Teardown must not mask the assertion that failed: a Governor the test never opened, or one a
    # refusal left half-open, has nothing to flush and its close is not what the test is about.
    with contextlib.suppress(Exception):
        governor.close(timeout=1.0)


def test_an_ordinary_function_is_governed_without_leaving_the_process(governor: Any) -> None:
    ledger: list[str] = []

    with governor:

        @governor.governed(server="ops", schema={"type": "object", "properties": {}})
        def tail_logs(service: str) -> str:
            ledger.append(service)
            return f"logs for {service}"

        assert tail_logs("checkout") == "logs for checkout"

    # The whole point of the integrator's rejection: their `LEDGER` ended up in a subprocess and
    # their driver's assertions read an empty one. It is a plain list in this process.
    assert ledger == ["checkout"]


def test_a_gated_function_refuses_and_never_runs_its_body(governor: Any) -> None:
    ran: list[str] = []

    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            ran.append(order_id)
            return "refunded"

        with pytest.raises(RefusalError) as refused:
            issue_refund("ORD-88214", 4_999_000)

    assert refused.value.document["result"] == "parked"
    assert refused.value.document["action"] == "ops.issue_refund"
    # Not "the call was refused after the fact": the body did not run.
    assert ran == [], "the wrapped function ran despite the refusal"


def test_the_same_call_written_two_ways_is_one_action(governor: Any) -> None:
    """Positional and keyword calls must produce the same `args-hash`, or one approval binds only
    one spelling of what is visibly one action.

    Not the same *request* hash: a request carries a nonce and a timestamp, so two parks of the same
    call are two requests by construction. What has to match is the commitment to the arguments.
    """
    hashes: list[str] = []

    with governor:

        @governor.governed(server="ops")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            return "refunded"

        for call in (
            lambda: issue_refund("ORD-1", 500),
            lambda: issue_refund(order_id="ORD-1", amount_cents=500),
        ):
            with pytest.raises(RefusalError) as refused:
                call()
            parked = governor._gateway.store.parked(refused.value.document["request-hash"])
            hashes.append(parked.request["args-hash"])

    assert hashes[0] == hashes[1], "the same action committed to two different argument hashes"


def test_what_the_gate_records_is_what_the_function_receives(governor: Any) -> None:
    """The defect a first integrator hit, and the worst one this module can carry.

    `BoundArguments.arguments` keys a `**kwargs` parameter under its own name, so calling
    `function(**arguments)` passed `{'extra': {'cc': ...}}` as a single keyword named `extra` —
    which `**extra` then collected under the key `'extra'`. The approver signed `cc`; the function
    received a dict called `extra` containing it. No exception, no warning, and the two records
    that are supposed to be the same thing disagreed.
    """
    seen: list[dict[str, Any]] = []

    with governor:

        # `tool=` so the action is one the fixture's policy classifies `read`: what is under test is
        # the signature, not the classification.
        @governor.governed(server="ops", tool="tail_logs")
        def send_email(to: str, subject: str = "(none)", **extra: Any) -> str:
            seen.append({"to": to, "subject": subject, "extra": extra})
            return "sent"

        assert send_email("ops@example.com", cc="boss@example.com", priority=1) == "sent"

    assert seen == [
        {
            "to": "ops@example.com",
            "subject": "(none)",
            "extra": {"cc": "boss@example.com", "priority": 1},
        }
    ], "the function did not receive the arguments the caller passed"


def test_a_positional_only_parameter_is_governable(governor: Any) -> None:
    """The same line, with a different symptom: there is no keyword spelling for a positional-only
    parameter, so `function(**arguments)` raised `TypeError` on a signature Python has had since
    3.8. A gate that cannot wrap a legal signature is a gate that gets removed from that tool."""
    seen: list[tuple[str, str]] = []

    with governor:

        @governor.governed(server="ops", tool="tail_logs")
        def run_query(query: str, /, database: str = "main") -> str:
            seen.append((query, database))
            return "0 rows"

        assert run_query("SELECT 1") == "0 rows"

    assert seen == [("SELECT 1", "main")]


def test_an_async_function_is_refused_rather_than_recorded_as_applied(governor: Any) -> None:
    """`Enforcer.call` is synchronous: it chains `applied` as soon as `forward()` returns, and for a
    coroutine function that is when the coroutine is *constructed*. Decorating one produced a chain
    that said the effect had been applied before the body ran — and said it still if the caller
    never awaited, or if the await raised. Refusing at decoration is the honest answer."""

    with pytest.raises(TypeError, match="async"):

        @governor.governed(server="ops")
        async def fetch(url: str) -> str:
            return "body"


def test_a_configuration_path_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    """`load_config` treats a missing file as a disabled gateway, which is right for the MCP server
    and wrong for a caller who named one: they got a Governor built from defaults and discovered it
    at the first call. A typo in a path is not a decision to run ungoverned."""
    from stozher_gateway.config import ConfigError

    with pytest.raises(ConfigError, match="no such configuration file"):
        Governor.from_config(tmp_path / "absent.toml")


def test_the_exception_a_caller_must_catch_is_importable_from_the_package(governor: Any) -> None:
    """`deploy/README.md` names `RefusalError` and it was importable only from a private submodule,
    which sent the first integrator into the source to find out from where."""
    import stozher_gateway

    assert stozher_gateway.RefusalError is RefusalError


def test_a_governor_that_was_never_opened_refuses_rather_than_running_ungoverned(
    governor: Any,
) -> None:
    """The failure mode worth being loud about: a decorated function that quietly runs unrecorded."""
    ran: list[str] = []

    @governor.governed(server="ops")
    def issue_refund(order_id: str) -> str:
        ran.append(order_id)
        return "refunded"

    with pytest.raises(Exception, match="not open"):
        issue_refund("ORD-1")
    assert ran == []


def test_importing_the_package_does_not_import_the_runtime() -> None:
    """`__init__.py` promises nothing runs at import. Exporting `Governor` must not break it."""
    import subprocess
    import sys

    probe = (
        "import sys, stozher_gateway;"
        "assert 'stozher_gateway.runtime' not in sys.modules, sorted(sys.modules);"
        "assert stozher_gateway.Governor is not None;"
        "assert 'stozher_gateway.runtime' in sys.modules"
    )
    done = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr

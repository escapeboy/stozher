"""`stozher-gateway` — configuration checks and the approval path.

`config check` reports actionable findings in the style of Harbormaster's `config_cli.py:75-178`:
an operator running two configuration files (ADR-0005's accepted cost) needs the second one to tell
them what is wrong, not that something is.

`approve` / `deny` are the S2 approval path. **They are not a bypass.** There is no flag here that
means "allowed": the command constructs a `gate-decision` object, signs it with a named human's key,
and stores it. The gateway then runs all of §06 §2 over it — request-hash binding, signature,
self-approval, approver membership, expiry, field-by-field action match, replay — before anything is
forwarded. What S4 replaces is the *transport and notification*, not the cryptography.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from typing import Any

from . import clock as clock_module
from . import crypto
from .canonical import object_hash
from .classify import Classifier
from .config import ConfigError, GatewayConfig, load_config, load_config_file
from .kernel_client import KernelClient, KernelUnreachableError
from .signing import SigningKey
from .store import GatewayStore

__all__ = ["main"]

#: An approval is permission to act now, not a licence (§06 §1.2).
_APPROVAL_LIFETIME_SECONDS = 900.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stozher-gateway", description=__doc__)
    parser.add_argument("--config", type=Path, default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("config", help="configuration checks")
    check.add_argument("action", choices=["check", "show"])

    sub.add_parser("pending", help="list parked requests awaiting a human")

    catalog = sub.add_parser("catalog", help="the classification catalog")
    catalog.add_argument("action", choices=["show", "policy-fragment"])

    keygen = sub.add_parser("keygen", help="write an identity seed at mode 0600")
    keygen.add_argument("--out", type=Path, required=True)

    approve = sub.add_parser("approve", help="sign an approval for a parked request")
    approve.add_argument("--request", required=True)
    approve.add_argument("--key", type=Path, required=True, help="the approver's seed file")
    approve.add_argument("--subject", required=True, help="the approver's named human subject")
    approve.add_argument(
        "--classify",
        choices=["read", "benign", "consequential", "prohibited"],
        default=None,
        help="also seed the org catalog entry for this tool, at this class",
    )

    deny = sub.add_parser("deny", help="sign a denial for a parked request")
    deny.add_argument("--request", required=True)
    deny.add_argument("--key", type=Path, required=True)
    deny.add_argument("--subject", required=True)
    deny.add_argument("--reason", required=True)

    args = parser.parse_args(argv)
    try:
        config = load_config_file(args.config) if args.config else load_config()
    except ConfigError as e:
        print(f"configuration: {e}", file=sys.stderr)
        return 2

    if args.command == "config":
        return _config(config, args.action)
    if args.command == "keygen":
        return _keygen(args.out)
    if args.command == "pending":
        return _pending(config)
    if args.command == "catalog":
        return _catalog(config, args.action)
    if args.command == "approve":
        return _decide(config, args.request, args.key, args.subject, "approve", None, args.classify)
    return _decide(config, args.request, args.key, args.subject, "deny", args.reason, None)


def _unreachable_downstreams(config: GatewayConfig) -> list[str]:
    """Findings for declared servers that cannot be enumerated.

    A downstream that is down costs the operator nothing visible at startup — some tools are simply
    absent from `tools/list`, which looks exactly like a server nobody configured. This is the check
    that turns that into a sentence, before an agent discovers it as a missing capability.

    A server that could not be *reached* and a server that is fine must never look the same, so a
    failure here is reported rather than swallowed; the enumeration is read-only and the timeout is
    the configured one, so `config check` cannot hang on a downstream that accepts and never answers.
    """
    from .background import BackgroundLoop
    from .proxy import Downstream

    findings: list[str] = []
    loop = BackgroundLoop()
    loop.start()
    try:
        for server in config.servers:
            downstream = Downstream(
                server,
                loop,
                persistent=False,
                timeout=config.gateway.downstream_timeout_seconds,
            )
            try:
                downstream.list_tools()
            except Exception as e:  # noqa: BLE001 - any failure to reach it is "unreachable"
                findings.append(f"downstream {server.name!r} cannot be enumerated: {e}")
    finally:
        loop.stop()
    return findings


def _config(config: GatewayConfig, action: str) -> int:
    if action == "show":
        print(json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    findings: list[str] = []
    if not config.gateway.enabled:
        findings.append("gateway.enabled is false — enforcement mode will not start")
    if not crypto.available():
        findings.append("the crypto extra is missing: pip install 'stozher-gateway[crypto]'")
    seed = config.identity.resolve()
    if seed is None or not seed.is_file():
        findings.append("identity.seed_file (or STOZHER_GATEWAY_SEED) does not resolve to a file")
    if config.org.policy_key is None:
        findings.append("org.policy_key is unset — no policy document can be verified")
    if not config.org.roots:
        findings.append("org.roots is empty — no approval could ever be verified")
    if config.kernel.token() is None:
        findings.append(f"{config.kernel.token_env} is unset — the kernel will refuse the gateway")
    if not config.servers:
        findings.append("no downstream servers are configured — nothing would be proxied")
    findings.extend(_unreachable_downstreams(config))
    for caller in config.callers:
        if caller.mandate_file is not None and not Path(caller.mandate_file).is_file():
            findings.append(f"caller {caller.name!r}: mandate file {caller.mandate_file} is missing")
    try:
        health = KernelClient(
            config.kernel.url, config.kernel.token(), config.kernel.timeout_seconds
        ).health()
        if health.status != 200:
            findings.append(f"the kernel answered {health.status} at {config.kernel.url}")
    except KernelUnreachableError as e:
        findings.append(f"the kernel is unreachable: {e}")
    for finding in findings:
        print(f"  - {finding}")
    if findings:
        print(f"{len(findings)} finding(s)")
        return 1
    print("ok")
    return 0


def _keygen(out: Path) -> int:
    if out.exists():
        print(f"{out} exists; refusing to overwrite key material", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    out.write_text(secrets.token_hex(32))
    out.chmod(0o600)
    print(f"wrote {out} (mode 0600)")
    return 0


def _store(config: GatewayConfig) -> GatewayStore:
    return GatewayStore(config.state_db_path())


def _catalog(config: GatewayConfig, action: str) -> int:
    """Show the catalog, or print the `by-action` map the organization publishes from it.

    The kernel evaluates §05 §3 with the org policy and the emitting component's manifest; it cannot
    see the gateway's catalog. So a catalog class only becomes authoritative — and a `read` only
    stops being treated as `consequential` by `default-unknown` — once the organization publishes
    it. This prints exactly what to publish, for the servers this deployment actually fronts.
    """
    classifier = Classifier(
        # The same map the running gateway builds — only the scopes an operator wrote down. This is
        # what `deploy/README.md` names as the source of the `by-action` map an operator publishes,
        # so a classifier here that disagrees with `runtime.py`'s prints a policy matching nothing
        # the emitter will ever emit, with no signal that it does not match. That is precisely what
        # happened when `runtime.py` was fixed and this was not.
        scopes={
            server.name: server.action_scope
            for server in config.servers
            if server.action_scope
        },
        org_seeded=_store(config).catalog_entry,
    )
    fragment: dict[str, str] = {}
    shipped = json.loads(
        (Path(__file__).parent / "catalog" / "shipped.json").read_text(encoding="utf-8")
    )
    for server in config.servers:
        entry = shipped["servers"].get(server.name)
        if entry is not None:
            for tool, classification in entry["tools"].items():
                fragment[classifier.action(server.name, tool)] = classification
    for row in _store(config).catalog():
        fragment[row["action"]] = row["class"]
    if action == "show":
        print(json.dumps({"by-action": fragment, "origin-shipped": shipped["catalog-version"]}, indent=2, sort_keys=True))
        return 0
    print(json.dumps({"by-action": dict(sorted(fragment.items()))}, indent=2))
    return 0


def _pending(config: GatewayConfig) -> int:
    for parked in _store(config).pending():
        print(
            f"{parked.request_hash}  {parked.request['action']}  "
            f"{parked.request['classification']}  first-call={parked.first_call}"
        )
    return 0


def _decide(
    config: GatewayConfig,
    request_hash: str,
    key_file: Path,
    subject: str,
    verdict: str,
    reason: str | None,
    classify: str | None,
) -> int:
    store = _store(config)
    parked = store.parked(request_hash)
    if parked is None:
        print(f"no parked request {request_hash}", file=sys.stderr)
        return 2
    approver = SigningKey(bytes.fromhex(key_file.read_text().strip()), subject)
    if not any(root.key == approver.id and root.subject == subject for root in config.org.roots):
        # An approver is a named human the organization enrolled. A key that is not in the root set
        # can sign whatever it likes; the gateway will refuse it at §06 §2 step (5) anyway, so the
        # command refuses first and says why.
        print(f"{approver.id} is not enrolled as {subject}", file=sys.stderr)
        return 2
    if approver.id == parked.request["key"]:
        print("gate-self-approval: a subject may not approve its own action", file=sys.stderr)
        return 2

    now = clock_module.now()
    decision = approver.sign(
        {
            "v": "stozher/0.1",
            "kind": "gate-decision",
            "request-hash": request_hash,
            "decision": verdict,
            "decided-at": now,
            "not-after": clock_module.shift(now, _APPROVAL_LIFETIME_SECONDS),
            "single-use": True,
            "reason": reason,
        }
    )
    seed = None
    if verdict == "approve" and classify is not None:
        seed = _seed_authorization(parked, approver, classify, now)
    store.record_decision(request_hash, decision, classify if verdict == "approve" else None, seed)
    print(f"{verdict} recorded for {request_hash} by {subject}")
    if seed is not None:
        print(f"catalog seed signed: {parked.server}/{parked.tool} -> {classify}")
    return 0


def _seed_authorization(
    parked: Any, approver: SigningKey, classification: str, now: str
) -> dict[str, Any]:
    """The second signature of §10 §4.3.

    Approving the call and classifying the tool are two decisions and two records. One human
    interaction may produce both signatures, but the catalog entry does not come into force without
    its own — otherwise "deny once" would quietly become "allow forever at the heuristic's class".
    """
    entry = {"server": parked.server, "tool": parked.tool, "class": classification}
    call_request = parked.request
    request = {
        "v": "stozher/0.1",
        "kind": "action-request",
        "requested-at": now,
        "subject": call_request["subject"],
        "key": call_request["key"],
        "component": call_request["component"],
        "mandate-ref": call_request["mandate-ref"],
        "policy-version": call_request["policy-version"],
        "classification": "consequential",
        "action": "kernel.seed_catalog_entry",
        "target": f"tool:{parked.server}/{parked.tool}",
        "args-hash": object_hash(entry),
        "nonce": secrets.token_hex(16),
        "not-after": clock_module.shift(now, _APPROVAL_LIFETIME_SECONDS),
    }
    decision = approver.sign(
        {
            "v": "stozher/0.1",
            "kind": "gate-decision",
            "request-hash": object_hash(request),
            "decision": "approve",
            "decided-at": now,
            "not-after": clock_module.shift(now, _APPROVAL_LIFETIME_SECONDS),
            "single-use": True,
            "reason": None,
        }
    )
    return {"request": request, "decision": decision}


if __name__ == "__main__":
    raise SystemExit(main())

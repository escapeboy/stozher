"""The gateway's own configuration — `stozher-gateway.toml` and `STOZHER_*` (ADR-0005).

The gateway **never reads `harbormaster.toml`**. `HarbormasterConfig` applies
`ConfigDict(extra="forbid")` to every model including itself, so an `[enforcement]` section there is
a hard boot failure for anyone running vanilla Harbormaster — uninstall the plugin, or hand the file
to a colleague, and the tool dies at startup. Owning our own file makes "a Harbormaster without a
kernel loses nothing" true by construction rather than by discipline.

Conventions are Harbormaster's, so an operator meets one set and not two: `enabled: bool = False`
gating, `*_env` naming the environment variable that holds a secret rather than the secret,
`Field(..., gt=0)` bounds, `Literal[...]` enums, `@field_validator` for cross-field rules, and the
same search-path semantics as `_config_search_paths()` (first match wins, not merged).
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .gate import Approver

__all__ = [
    "CallerConfig",
    "ConfigError",
    "GatewayConfig",
    "RootConfig",
    "ServerConfig",
    "config_search_paths",
    "load_config",
]

_FORBID_EXTRA = ConfigDict(extra="forbid")

_KEY_ID = r"^ed25519:[0-9a-f]{64}$"


class ConfigError(ValueError):
    """Configuration that cannot be used. Reported with the file that produced it."""


class RootConfig(BaseModel):
    """An enrolled human root — the set a gate decision's signer must belong to (§03 §6)."""

    model_config = _FORBID_EXTRA

    subject: str = Field(pattern=r"^human:.+")
    key: str = Field(pattern=_KEY_ID)


class CallerConfig(BaseModel):
    """A credential the gateway maps to a derived subject key and a mandate (§10 §1)."""

    model_config = _FORBID_EXTRA

    name: str
    subject: str = Field(pattern=r"^(agent|human):.+")
    #: Index of the device key at SLIP-0010 role 2'. One key per (caller, device).
    key_index: int = Field(default=0, ge=0)
    #: SHA-256 of the caller's bearer token, lowercase hex. The token itself is never in config.
    token_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    #: Path to the signed mandate object this caller acts under.
    mandate_file: Path | None = None
    mandate_kind: Literal["interactive", "standing"] = "interactive"

    @model_validator(mode="after")
    def _mandate_is_required(self) -> CallerConfig:
        # §10 §1.4: a session without a resolvable mandate is refused at connect time. Accepting
        # calls and deferring the mandate question until the first consequential one is exactly the
        # mistake the rule exists to prevent — a read performed without authority is still an effect.
        if self.mandate_file is None:
            raise ValueError(f"caller {self.name!r} needs a mandate_file")
        return self


class ServerConfig(BaseModel):
    """A downstream MCP server the gateway fronts."""

    model_config = _FORBID_EXTRA

    name: str = Field(pattern=r"^[a-z0-9_-]+$")
    transport: Literal["stdio", "streamable-http"] = "stdio"
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    token_env: str | None = None
    #: The action namespace used in envelopes: `<scope>.<tool>` (§02 §4), when the operator names
    #: one. **Absent is not "the server's name"** — absent means the classifier falls through to the
    #: shipped catalog, which knows that the server called `filesystem` spells its actions `fs.*`.
    #: Reading the two as the same thing made the catalog's branch unreachable for every proxied
    #: server, so a catalogued read never matched the baseline policy and was gated as unknown.
    action_scope: str | None = None

    @model_validator(mode="after")
    def _transport_is_complete(self) -> ServerConfig:
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"server {self.name!r}: stdio transport needs a command")
        if self.transport == "streamable-http" and not self.url:
            raise ValueError(f"server {self.name!r}: streamable-http transport needs a url")
        return self

    # There is deliberately no `scope` property here. There was one — `action_scope or name` — and
    # it read exactly like the thing to build an action identifier from, which is why two call sites
    # used it and both were wrong: falling back to the server's name is what shadowed the shipped
    # catalog. The one authority on an action namespace is `Classifier.scope`, which consults the
    # operator's map, then the catalog, then the heuristic. Deleting the property is what stops the
    # mistake being available to make a third time.


class KernelConfig(BaseModel):
    """Where the kernel is and how long the gateway is willing to wait for it."""

    model_config = _FORBID_EXTRA

    url: str = "http://127.0.0.1:8787"
    token_env: str = "STOZHER_KERNEL_TOKEN"
    #: The hot path must be O(ms) and must not block on the kernel, so this is short by design.
    timeout_seconds: float = Field(default=2.0, gt=0)
    policy_refresh_seconds: int = Field(default=30, gt=0)

    def token(self) -> str | None:
        return os.environ.get(self.token_env)


class IdentityConfig(BaseModel):
    """The seed every subject key is derived from (§01 §6)."""

    model_config = _FORBID_EXTRA

    seed_file: Path | None = None

    def resolve(self) -> Path | None:
        override = os.environ.get("STOZHER_GATEWAY_SEED")
        return Path(override) if override else self.seed_file


class OrgConfig(BaseModel):
    """Organization-local trust: the policy key and the enrolled human roots."""

    model_config = _FORBID_EXTRA

    policy_key: str | None = Field(default=None, pattern=_KEY_ID)
    roots: list[RootConfig] = Field(default_factory=list)

    def approvers(self, subjects: list[str]) -> list[Approver]:
        """The approvers permitted to sign for the named subjects (§06 §5).

        An approver is always a named human: a group, a role or a rotation may determine whom to
        notify, but never who signs. Each key is returned with the subject it was resolved *from*,
        because that is what makes the subject half of §06 §5's self-approval prohibition checkable
        at all (see :class:`~stozher_gateway.gate.Approver`).

        §06 §5's second kind of approver — a human holding a mandate whose scope includes the action
        — is **not** resolvable here: the gateway holds its own caller's mandate and nothing else,
        so it has no way to learn which humans hold which mandates. This returns the roots it can
        name and no more; a caller that asked for subjects and got back fewer must refuse rather
        than substitute a set it *can* verify (§06 §6).
        """
        return [Approver(root.key, root.subject) for root in self.roots if root.subject in subjects]

    def root_approvers(self) -> list[Approver]:
        """Every enrolled human root, each carrying its subject."""
        return [Approver(root.key, root.subject) for root in self.roots]


class DevConfig(BaseModel):
    """Local-development escapes. Off by default and impossible to enable in an org deployment."""

    model_config = _FORBID_EXTRA

    allow_unauthenticated: bool = False


class GatewaySection(BaseModel):
    """The gateway's own knobs."""

    model_config = _FORBID_EXTRA

    enabled: bool = False
    device: str = Field(default="local", pattern=r"^[A-Za-z0-9._-]{1,64}$")
    component: str = "gateway"
    state_db: Path | None = None
    #: stdio spawns one process per client connection, so long-lived downstream sessions would
    #: duplicate per session and leak threads. Opt in explicitly, the way `bridge_in_stdio` does.
    persist_downstream_in_stdio: bool = False
    #: How long to wait on a downstream server before abandoning the call and reaping it.
    downstream_timeout_seconds: float = Field(default=30.0, gt=0)
    #: Harbormaster's own tools are actions too (§10 §8): under enforcement they are classified,
    #: mandated and gated like anything else.
    govern_native_tools: bool = True
    park_timeout_seconds: float = Field(default=120.0, gt=0)
    #: Argv of a command run when a request parks — empty means nothing is run.
    #:
    #: An incident responder found nine requests sitting in the queue with nothing configured to
    #: tell anyone, and wrote: "the control that stopped this is a web page someone has to remember
    #: to open." A gate nobody is notified about is a queue, not a control.
    #:
    #: Argv rather than a shell string on purpose. The one thing this command is handed is a
    #: request hash, and a shell string would invite an operator to interpolate it into `sh -c`.
    park_notify: list[str] = Field(default_factory=list)
    #: How long the notifier may take before it is abandoned. It never delays the refusal — the
    #: caller is answered from a different thread — so this bounds the notifier's own lifetime.
    park_notify_timeout_seconds: float = Field(default=10.0, gt=0)
    #: Aggregation window bounds (§10 §5). The elapsed bound comes from policy.
    aggregate_max_events: int = Field(default=500, gt=0)
    aggregate_max_samples: int = Field(default=8, gt=0, le=16)


class GatewayConfig(BaseModel):
    """The whole file."""

    model_config = _FORBID_EXTRA

    gateway: GatewaySection = Field(default_factory=GatewaySection)
    kernel: KernelConfig = Field(default_factory=KernelConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    org: OrgConfig = Field(default_factory=OrgConfig)
    dev: DevConfig = Field(default_factory=DevConfig)
    callers: list[CallerConfig] = Field(default_factory=list)
    servers: list[ServerConfig] = Field(default_factory=list)
    #: Set by the loader; not a configurable member.
    source: Path | None = Field(default=None, exclude=True)

    @field_validator("servers")
    @classmethod
    def _server_names_are_unique(cls, servers: list[ServerConfig]) -> list[ServerConfig]:
        names = [server.name for server in servers]
        if len(set(names)) != len(names):
            raise ValueError("downstream server names must be unique")
        return servers

    @model_validator(mode="after")
    def _passthrough_is_impossible_in_an_org_deployment(self) -> GatewayConfig:
        # §10 §1.1: unauthenticated passthrough may exist for local development only, must be off by
        # default, and MUST be impossible to enable where any human root is enrolled. Enrolment is
        # the fact that makes a deployment an organization's, so it is the condition checked here.
        if self.dev.allow_unauthenticated and self.org.roots:
            raise ValueError(
                "dev.allow_unauthenticated cannot be set in a deployment with enrolled human roots "
                "(gateway-passthrough-in-org-deployment)"
            )
        return self

    def state_db_path(self) -> Path:
        """Where the local durable chain lives. `STOZHER_GATEWAY_DB` overrides everything."""
        override = os.environ.get("STOZHER_GATEWAY_DB")
        if override:
            return Path(override)
        if self.gateway.state_db is not None:
            return self.gateway.state_db
        return Path.home() / ".stozher" / "gateway.db"

    def caller(self, name: str) -> CallerConfig | None:
        return next((caller for caller in self.callers if caller.name == name), None)

    def server(self, name: str) -> ServerConfig | None:
        return next((server for server in self.servers if server.name == name), None)


def config_search_paths(explicit: Path | None = None) -> list[Path]:
    """`--config`, `$STOZHER_GATEWAY_CONFIG`, `./.stozher-gateway.toml`, then XDG (ADR-0005 §1)."""
    if explicit is not None:
        return [explicit]
    paths = []
    override = os.environ.get("STOZHER_GATEWAY_CONFIG")
    if override:
        paths.append(Path(override))
    paths.append(Path(".stozher-gateway.toml"))
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    paths.append(base / "stozher" / "gateway.toml")
    return paths


def load_config(explicit: Path | None = None) -> GatewayConfig:
    """Load the first configuration file that exists. A missing file yields a disabled gateway."""
    for path in config_search_paths(explicit):
        if path.is_file():
            return load_config_file(path)
    return GatewayConfig()


def load_config_file(path: Path) -> GatewayConfig:
    """Load and validate one file, reporting the path with any refusal."""
    try:
        with path.open("rb") as handle:
            document: dict[str, Any] = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{path}: {e}") from e
    try:
        config = GatewayConfig.model_validate(document)
    except ValidationError as e:
        raise ConfigError(f"{path}: {e}") from e
    config.source = path
    return config

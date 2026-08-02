"""Classification, per `spec/10-gateway-protocol.md` §3 — exactly this order, first match wins.

    Tier A  manifest       the upstream server ships a Stozher manifest (§08)
    Tier B  shipped        the curated catalog versioned with the product
    Tier B' org-seeded     entries created by first-call gating, and signed into force
    Tier C  heuristic      conservative, and only ever `read` or `consequential`

Two rules here are load-bearing rather than stylistic:

* **The heuristic is a pure function of the tool's name and declared schema.** It never reads a tool
  description or documentation. Those are model-authored text under the upstream server's control
  (§09 §3), and a classifier that reads them is a classifier an adversary configures.
* **The heuristic may never produce `benign` or `prohibited`.** Both are judgements: one says an
  effect does not matter, the other says nobody may ever do it. A regex is not entitled to either.

Unknown is not ungoverned. An unclassified tool is `consequential`, and §4's first-call gate parks it
regardless — unknown is expensive until a human classifies it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from importlib import resources
from typing import Any, NamedTuple

__all__ = ["Classification", "Classifier", "read_shaped"]

TIER_MANIFEST = "manifest"
TIER_SHIPPED = "shipped"
TIER_ORG_SEEDED = "org-seeded"
TIER_HEURISTIC = "heuristic"

#: A name is read-shaped only if it *starts* with one of these verbs as a whole segment.
_READ_VERB = re.compile(r"^(get|list|read|search|find|query|describe|fetch|show|count)(_|$)")

#: Argument names that carry a body to be written somewhere. Their presence makes a read-shaped name
#: irrelevant: `get_or_create(body=…)` is not a read.
_MUTATING_ARGUMENT = frozenset(
    {
        "body",
        "cmd",
        "code",
        "command",
        "content",
        "contents",
        "data",
        "diff",
        "document",
        "html",
        "markdown",
        "message",
        "patch",
        "payload",
        "script",
        "source",
        "sql",
        "statement",
        "text",
        "update",
        "updates",
        "write",
    }
)


class Classification(NamedTuple):
    """What the gateway decided, and how confident the decision was."""

    action: str
    classification: str
    tier: str
    #: What this classifier proposed, before policy's `default-unknown` escalated an unknown tool.
    #:
    #: The escalated class is what gates the call; the proposal is what a catalog entry would hold,
    #: so the approver of a first call is answering "is this tool a `read`?" and not "is
    #: `consequential` correct?" — which is the question policy already answered by not knowing.
    proposed: str = ""

    @property
    def known(self) -> bool:
        """Whether a catalog or manifest entry exists. False means §4's first call parks."""
        return self.tier != TIER_HEURISTIC


def read_shaped(tool: str, schema: Any) -> bool:
    """The Tier C test: a read-shaped name **and** a schema that declares no mutation."""
    if not _READ_VERB.match(tool):
        return False
    if not isinstance(schema, dict):
        return False  # an opaque or absent schema is never read-shaped
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return False
    if schema.get("additionalProperties") is True:
        return False  # arguments we cannot see cannot be shown to be harmless
    return all(name.lower() not in _MUTATING_ARGUMENT for name in properties)


def _load_shipped() -> dict[str, Any]:
    text = (resources.files(__package__) / "catalog" / "shipped.json").read_text(encoding="utf-8")
    document: dict[str, Any] = json.loads(text)
    return document


class Classifier:
    """Resolves (server, tool) to an action identifier, a class, and the tier that decided it."""

    def __init__(
        self,
        scopes: dict[str, str],
        manifests: dict[str, dict[str, Any]] | Callable[[], dict[str, dict[str, Any]]] | None = None,
        org_seeded: Any = None,
    ) -> None:
        #: server name → action scope, so `github`/`get_file_contents` becomes
        #: `github.get_file_contents` (§02 §4's `<component-scope>.<action>`).
        self._scopes = scopes
        #: Either a fixed mapping or a callable returning one. Tier A is the *only* tier whose
        #: source changes while the process runs — `kernel.register_component` is a gated action a
        #: human signs mid-session — so a classifier that read this once at startup would classify a
        #: freshly registered component by the shape heuristic until the next restart, which is the
        #: tier the taxonomy is least confident about and the one the registration existed to leave.
        self._manifests: Any = manifests or {}
        #: A callable `(server, tool) -> (action, class) | None`, normally the store's lookup.
        self._org_seeded = org_seeded
        self._shipped = _load_shipped()

    def scope(self, server: str) -> str:
        shipped = self._shipped["servers"].get(server)
        if server in self._scopes:
            return self._scopes[server]
        if shipped is not None:
            return str(shipped["scope"])
        return server

    def action(self, server: str, tool: str) -> str:
        return f"{self.scope(server)}.{tool}"

    def _manifest_for(self, server: str) -> dict[str, Any] | None:
        source = self._manifests() if callable(self._manifests) else self._manifests
        manifest = source.get(server) if isinstance(source, dict) else None
        return manifest if isinstance(manifest, dict) else None

    def classify(self, server: str, tool: str, schema: Any) -> Classification:
        """§10 §3's order, first match wins. Policy reclassification is applied by the caller."""
        action = self.action(server, tool)

        manifest = self._manifest_for(server)
        if manifest is not None:
            for declared in manifest.get("actions", []):
                if declared.get("action") in (action, f"{manifest.get('name')}.{tool}"):
                    return Classification(action, str(declared["class"]), TIER_MANIFEST)

        shipped = self._shipped["servers"].get(server)
        if shipped is not None and tool in shipped["tools"]:
            return Classification(action, str(shipped["tools"][tool]), TIER_SHIPPED)

        if self._org_seeded is not None:
            seeded = self._org_seeded(server, tool)
            if seeded is not None:
                return Classification(seeded[0], seeded[1], TIER_ORG_SEEDED)

        return Classification(
            action,
            "read" if read_shaped(tool, schema) else "consequential",
            TIER_HEURISTIC,
        )

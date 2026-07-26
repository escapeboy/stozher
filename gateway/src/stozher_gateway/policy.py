"""Policy pull, verification and evaluation, per `spec/05-policy-distribution.md`.

Components pull; the kernel does not push. The gateway verifies the document's signature against the
enrolled policy key before applying it, caches it persistently, and enforces the cached copy while
offline — a pull loop that fails degrades to "keep using the last verified copy", which is the
offline behaviour maxim 5 requires. It never falls back to permissive defaults: an unverifiable
policy means refusing to act, not guessing.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from .envelope import CLASSES
from .signing import verify_signed_object

__all__ = ["Decision", "Policy", "PolicyError", "class_weight"]

_WEIGHT = {"read": 0, "benign": 1, "consequential": 2, "prohibited": 3}


def class_weight(classification: str) -> int:
    """Ordering used when a window folds several actions: the strongest class wins."""
    return _WEIGHT.get(classification, len(_WEIGHT))


class PolicyError(ValueError):
    """A policy document that must not be enforced."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class Decision(NamedTuple):
    """The gate rule that matched: `allow`, `gate` (with approver subjects), or `deny`."""

    kind: str
    approvers: list[str]


class Policy:
    """A verified policy document, ready to evaluate."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document
        self.version = str(document["policy-version"])

    @classmethod
    def verified(cls, document: Any, policy_key: str | None) -> Policy:
        """Parse a document, refusing anything unsigned, wrongly signed, or not understood."""
        if not isinstance(document, dict):
            raise PolicyError("schema-type-mismatch", "a policy document must be an object")
        if document.get("v") != "stozher/0.1":
            raise PolicyError("envelope-version-unsupported", str(document.get("v")))
        if document.get("kind") != "policy":
            raise PolicyError("schema-type-mismatch", "kind must be policy")
        signer = verify_signed_object(document)
        if signer is None:
            raise PolicyError("policy-sig-invalid", "the policy signature does not verify")
        if policy_key is not None and signer != policy_key:
            # A document signed by a key that is not the organization's policy key is a document
            # from somewhere else, whatever it says about itself.
            raise PolicyError("policy-sig-invalid", f"signed by {signer}")
        for member in ("policy-version", "classification", "gate-rules", "offline", "evidence-ttl"):
            if member not in document:
                raise PolicyError("schema-missing-member", member)
        return cls(document)

    # -- §05 §3 step 1: classification ------------------------------------------------------

    def classify(self, subject: str, action: str, resource: str, proposed: str | None) -> str:
        """Apply org reclassification over whatever tier proposed a class.

        Reclassification runs in **both** directions and wins over the component's proposal: a
        component's manifest is a proposal, the classification is the organization's.
        """
        classification = self.document.get("classification", {})
        for entry in classification.get("reclassify", []):
            if entry.get("subject") not in (None, subject):
                continue
            if entry.get("action") not in (None, action):
                continue
            if entry.get("resource") not in (None, resource):
                continue
            return str(entry["class"])
        by_action = classification.get("by-action", {})
        if action in by_action:
            return str(by_action[action])
        # No org opinion. The catalog's proposal competes with `default-unknown`, and the **stronger**
        # class wins.
        #
        # This is not caution for its own sake. The kernel evaluates §05 §3 step 1 with the emitting
        # component's *manifest* as the only proposal it can see; the gateway's catalog tiers are
        # invisible to it, so a catalog that quietly downgraded an action would produce envelopes the
        # kernel refuses `policy-component-override-attempt` — an effect applied in the world and
        # missing from the audit. Taking the stronger class makes the two evaluations agree by
        # construction. To realize a catalog downgrade, the organization publishes it:
        # `stozher-gateway catalog policy-fragment` prints the `by-action` map to publish.
        unknown = str(classification.get("default-unknown", "consequential"))
        if proposed in CLASSES:
            return proposed if class_weight(proposed) > class_weight(unknown) else unknown
        return unknown

    # -- §05 §3 step 4: the gate rule --------------------------------------------------------

    def decision_for(self, classification: str) -> Decision:
        """The first matching `gate-rules` entry decides."""
        for rule in self.document.get("gate-rules", []):
            if classification in rule.get("classes", []):
                return Decision(str(rule.get("decision", "deny")), list(rule.get("approvers", [])))
        # No rule matched. The absence of a permission is not a permission.
        return Decision("deny", [])

    # -- retention, aggregation, offline ------------------------------------------------------

    def evidence_ttl(self, classification: str) -> str:
        return str(self.document.get("evidence-ttl", {}).get(classification, "P0D"))

    def aggregate_max_window(self) -> str:
        return str(self.document.get("aggregate-max-window", "PT5M"))

    def max_staleness_seconds(self) -> int:
        return int(self.document.get("max-staleness-seconds", 300))

    def offline_for(self, classification: str) -> str:
        """`allow` | `block` | `degrade` — never "proceed silently" (§05 §7)."""
        return str(self.document.get("offline", {}).get(classification, "block"))

    def max_delegation_depth(self) -> int:
        return int(self.document.get("delegation", {}).get("max-depth", 3))

    def revoke_cached(self) -> bool:
        return bool(self.document.get("revoke-cached", False))

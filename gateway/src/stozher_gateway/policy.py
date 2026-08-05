"""Policy pull, verification and evaluation, per `spec/05-policy-distribution.md`.

Components pull; the kernel does not push. The gateway verifies the document's signature against the
enrolled policy key before applying it, caches it persistently, and enforces the cached copy while
offline — a pull loop that fails degrades to "keep using the last verified copy", which is the
offline behaviour maxim 5 requires. It never falls back to permissive defaults: an unverifiable
policy means refusing to act, not guessing.
"""

from __future__ import annotations

import logging
from typing import Any, NamedTuple

from . import clock as clock_module
from .envelope import CLASSES
from .signing import verify_signed_object
from .sync import WEDGE_GRACE_DEFAULT_SECONDS

logger = logging.getLogger(__name__)

__all__ = ["Decision", "Policy", "PolicyError", "class_weight"]

_WEIGHT = {"read": 0, "benign": 1, "consequential": 2, "prohibited": 3}


def class_weight(classification: str) -> int:
    """Ordering used when a window folds several actions: the strongest class wins."""
    return _WEIGHT.get(classification, len(_WEIGHT))


def _dimension_score(pattern: Any, value: str) -> int | None:
    """How specifically `pattern` matches `value`, or `None` if it does not (§05 §3.1).

    An absent dimension is `*`. Patterns are §03 §4.1's vocabulary — exact, `*`, or a `<prefix>.*`
    segment prefix — and this build supported none of it until v0.9: it compared the three dimensions
    for string equality, so a policy reclassifying `github.*` was ignored here and honoured by the
    kernel. The emitter then applied an effect believing it was `read` and the kernel refused the
    record of it, which is an action in the world with no line in the audit.
    """
    if pattern is None or pattern == "*":
        return 0
    if not isinstance(pattern, str):
        return None
    if pattern == value:
        return 2
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        if value.startswith(prefix) and len(value) > len(prefix) and value[len(prefix)] == ".":
            return 1
    return None


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

    def classify(
        self,
        subject: str,
        action: str,
        resource: str,
        manifest_class: str | None = None,
        *,
        catalog_class: str | None = None,
    ) -> str:
        """§05 §3 step 1, plus the one emitter-side rule §10 §3 adds to it.

        `manifest_class` is what a **registered** manifest declares (§08 §1.2). The kernel can see it
        too, so it takes part in §05 §3 exactly as written: reclassify, then `by-action`, then the
        manifest, then `default-unknown`.

        `catalog_class` is what the gateway's own catalog proposed — a tier the kernel **cannot**
        see. When the organization has said nothing and the fallback is therefore `default-unknown`,
        the **stronger** of the two is taken. This is not caution for its own sake: the kernel
        evaluates step 1 with the registered manifest as the only proposal available to it, so a
        catalog that quietly downgraded an action would produce envelopes the kernel refuses
        `policy-component-override-attempt` — an effect applied in the world and missing from the
        audit. Taking the stronger class makes the two evaluations agree by construction. To realize
        a catalog downgrade the organization publishes it: `stozher-gateway catalog policy-fragment`
        prints the `by-action` map to publish.

        The two arrive as separate parameters because they were one for the whole of v0.1, and a
        registered manifest's class was silently being strengthened along with a catalog guess —
        which made this implementation disagree with §05 §3 and with the kernel.
        """
        classification = self.document.get("classification", {})
        best: tuple[int, str] | None = None
        for entry in classification.get("reclassify", []):
            total = 0
            for member, value in (("subject", subject), ("action", action), ("resource", resource)):
                score = _dimension_score(entry.get(member), value)
                if score is None:
                    break
                total += score
            else:
                # Highest specificity wins; among equals the earliest entry does, which is why the
                # comparison is strict (§05 §3.1).
                if best is None or total > best[0]:
                    best = (total, str(entry["class"]))
        if best is not None:
            return best[1]
        by_action = classification.get("by-action", {})
        if action in by_action:
            return str(by_action[action])
        if manifest_class in CLASSES:
            return str(manifest_class)
        # Nothing but the default is left, so the catalog's guess competes with it.
        unknown = str(classification.get("default-unknown", "consequential"))
        if catalog_class in CLASSES and class_weight(str(catalog_class)) > class_weight(unknown):
            return str(catalog_class)
        if catalog_class in CLASSES and str(catalog_class) != unknown:
            # DEF-15. The rule above is right and stays; the silence was the defect. An approver
            # signed a classification for this tool and it changed nothing, because the default is
            # already at least as strong — and nothing told them. Two design-partner evaluations
            # found this independently, one of them describing the signature they had just given as
            # "a silent no-op". A signed decision that has no effect must say so; otherwise the
            # approver's model of the system is wrong in the direction that matters, and they will
            # keep signing.
            logger.warning(
                "the signed catalog class %r for %s had no effect: the published policy says "
                "nothing about this action and its default-unknown is %r, which is already at "
                "least as strong. Publish it in `by-action` to make it binding — "
                "`stozher-gateway catalog policy-fragment` prints the map.",
                str(catalog_class),
                action,
                unknown,
            )
        return unknown

    def names(self, subject: str, action: str, resource: str) -> bool:
        """Whether the organization's published policy speaks about this action **by name**.

        `reclassify` matching it, or `by-action` carrying it. Not `default-unknown`, which is the
        organization saying nothing and is the whole reason §10 §4 gates a first call.

        This exists because first-call gating read only the *classifier's* tier, so an action the
        organization had explicitly published a class for still parked, and the approval seeded a
        catalog entry duplicating what policy already said. An engineer measuring the everyday cost
        published a policy classifying their tools as `read` — the escape this product documents —
        and reported that it "did not help": every call still parked, forever. The kernel evaluates
        §05 §3 step 1 from the same document, so there is nothing here for a human to decide.
        """
        classification = self.document.get("classification", {})
        if action in classification.get("by-action", {}):
            return True
        for entry in classification.get("reclassify", []):
            if all(
                _dimension_score(entry.get(member), value) is not None
                for member, value in (("subject", subject), ("action", action), ("resource", resource))
            ):
                return True
        return False

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

    def wedge_grace_seconds(self) -> float:
        """`policy.wedge-grace` in seconds (§05 §7.1), the one OPTIONAL member of §05 §1.

        Absent means the default, never means unbounded: a document that says nothing about the
        window still gets one. A malformed value is treated as absent rather than as a refusal to
        run — the enforcing decision that depends on it is already the strict one, and a component
        that would not start could not tell anyone why.
        """
        declared = self.document.get("wedge-grace")
        if not isinstance(declared, str):
            return WEDGE_GRACE_DEFAULT_SECONDS
        try:
            return clock_module.parse_duration(declared)
        except ValueError:
            return WEDGE_GRACE_DEFAULT_SECONDS

    def max_delegation_depth(self) -> int:
        return int(self.document.get("delegation", {}).get("max-depth", 3))

    def revoke_cached(self) -> bool:
        return bool(self.document.get("revoke-cached", False))

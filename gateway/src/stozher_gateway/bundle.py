"""The offline bootstrap: a root-signed policy bundle, verified before anything is trusted.

`spec/05 §7` describes what a component does with a **cached** policy when the kernel is unreachable,
and this build implements it. What it had no answer for is the call before that one: the only writer
of the policy cache was a successful pull, so a container that has never reached a kernel had no
verified policy at all and `PolicyProvider.current` raised `policy-not-published` while the session
was still being opened. Enforcement that cannot start in CI is enforcement an integrator comments
out, so the missing piece is a way *in* from cold — not another offline mode.

A bundle is one signed object carrying three things: the policy document in force, the revocation
set, and the checkpoint anchor the two were exported against. It is produced by
`stozher-kernel policy export-bundle`, in the operator's own process, from files the operator already
holds; it is verified here against the roots the deployment enrolled, before a byte of it reaches the
cache.

Three properties are the whole of why this is a bootstrap rather than a back door:

* **The signature is checked against `org.roots`, not against whoever wrote the file.** A bundle
  nobody enrolled can vouch for is refused and never cached — the same rule the policy provider
  applies to a pulled document, applied one step earlier.
* **The policy inside is re-verified against the organization's policy key** on its own terms. The
  root's signature says "this is the set I exported"; it does not stand in for the policy key, so a
  root cannot mint a policy by wrapping one.
* **`max-age` lives inside the signed body.** Staleness is therefore the root's declaration and not
  the file-holder's: editing it invalidates the signature. An expired bundle makes the component
  refuse to start. Not warn — a component running on a policy nobody can vouch for any more is the
  thing this product exists to prevent, and a warning in CI is a line nobody reads.

What a bundle can never do is let a `consequential` call succeed. §05 §7 is explicit that an action
requiring a human signature cannot acquire one offline, so a suite that needs one to pass needs a
fixture-signed approval (`gateway/README.md`, "Running an agent suite in CI"), not an offline mode.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from . import clock as clock_module
from .policy import Policy, PolicyError
from .signing import object_id, verify_signed_object
from .store import GatewayStore

__all__ = ["BUNDLE_VERSION", "BundleError", "load_policy_bundle"]

logger = logging.getLogger(__name__)

#: The bundle format this build reads. An unknown version is refused rather than read optimistically:
#: a member this code does not know about could be the one carrying a constraint.
BUNDLE_VERSION = 1

#: Every member of the signed body. `anchor` is here because "we exported no checkpoint" and "we did
#: not say" must not look the same — an absent member is a refusal, an explicit `null` is a statement.
_MEMBERS = ("exported-at", "max-age", "policy", "revocations", "anchor")


class BundleError(ValueError):
    """A bundle that must not be enforced. Carries the reason code the operator will grep for."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def load_policy_bundle(
    path: Path,
    *,
    roots: set[str],
    policy_key: str | None,
    store: GatewayStore,
    clock: clock_module.Clock,
) -> str:
    """Verify `path` and seed the local caches from it. Returns the policy version seeded.

    Nothing is written until every check has passed, so a refused bundle leaves the store exactly as
    it was — including empty. "An unverified bundle is refused, never cached" is an ordering
    property, and it is the reason the two `store.cache_*` calls are the last two statements here.

    The seeded `verified_at` is the bundle's own `exported-at`, not the moment of the load. That is
    the truthful answer to the question `PolicyProvider._is_fresh` asks — *when was this document
    last vouched for* — and it has a consequence worth stating: a component booted from a bundle
    older than `max-staleness-seconds` is **not** fresh, so §05 §7's `offline` profile governs from
    the first call rather than after a grace period the kernel never granted. Stamping the load time
    here would have made a machine that has never seen a kernel report itself as freshly online.
    """
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise BundleError("bundle-unreadable", f"{path}: {e}") from e
    if not isinstance(document, dict):
        raise BundleError("bundle-schema-type-mismatch", "a policy bundle must be an object")
    if document.get("v") != "stozher/0.1":
        raise BundleError("envelope-version-unsupported", str(document.get("v")))
    if document.get("kind") != "policy-bundle":
        raise BundleError("bundle-schema-type-mismatch", f"kind is {document.get('kind')!r}")
    if document.get("bundle-version") != BUNDLE_VERSION:
        raise BundleError("bundle-version-unsupported", str(document.get("bundle-version")))
    signer = verify_signed_object(document)
    if signer is None:
        # One byte of the policy, of the revocation set, of `max-age` or of the signature itself all
        # arrive here. The bundle is one signed object precisely so that tampering with any part of
        # it is one failure and not three separate checks somebody could forget to write.
        raise BundleError("bundle-sig-invalid", f"{path}: the bundle signature does not verify")
    if signer not in roots:
        raise BundleError(
            "bundle-signer-not-a-root",
            f"{signer} is not an enrolled root; a bundle is only as good as the key that vouches "
            "for it, and this deployment has not enrolled that one",
        )
    for member in _MEMBERS:
        if member not in document:
            raise BundleError("bundle-missing-member", member)

    exported_at = str(document["exported-at"])
    expires_at = _expiry(exported_at, str(document["max-age"]))
    now = clock.now()
    if now > expires_at:
        raise BundleError(
            "bundle-expired",
            f"{path} was exported {exported_at} with max-age {document['max-age']} and expired "
            f"{expires_at}; it is now {now}. Export a fresh bundle — a component does not run on a "
            "policy nobody can vouch for any more",
        )

    try:
        policy = Policy.verified(document["policy"], policy_key)
    except PolicyError as e:
        raise BundleError(e.code, f"the policy inside {path} is not enforceable: {e.detail}") from e
    revocations = _revocations(document["revocations"], path)

    store.cache_policy(policy.version, policy.document, exported_at)
    store.cache_revocations("", revocations, exported_at)
    # Which bundle this store was seeded from, durably. A CI container that misbehaves is otherwise
    # indistinguishable from one seeded with a different file, and the bundle is the one input to
    # the run that nothing else records.
    store.mark(f"policy-bundle:{object_id(document)}", now)
    logger.info(
        "seeded policy %s and %d revocation(s) from %s, exported %s by %s, anchor %s",
        policy.version,
        len(revocations),
        path,
        exported_at,
        signer,
        "present" if document["anchor"] is not None else "absent",
    )
    return policy.version


def _expiry(exported_at: str, max_age: str) -> str:
    """`exported-at + max-age`, refusing either half rather than defaulting it.

    A `max-age` that does not parse is not "no bound": it is a bundle whose staleness this build
    cannot evaluate, which is the same situation as an expired one.
    """
    try:
        seconds = clock_module.parse_duration(max_age)
    except ValueError as e:
        raise BundleError("bundle-bad-max-age", f"{max_age}: {e}") from e
    if seconds <= 0:
        raise BundleError("bundle-bad-max-age", f"{max_age} is not a positive duration")
    try:
        return clock_module.shift(exported_at, seconds)
    except ValueError as e:
        raise BundleError("bundle-bad-exported-at", f"{exported_at}: {e}") from e


def _revocations(listed: Any, path: Path) -> list[dict[str, Any]]:
    """Every revocation in the bundle, or a refusal — deliberately unlike the live feed.

    `RevocationFeed` drops an unverifiable revocation and keeps going, which is safe there because
    the feed's entries arrive from the kernel one at a time and dropping one can only ever cause a
    refusal to be missed. Here they arrive inside a document a **root signed as a set**, so an entry
    that does not verify means the set is not the one anybody vouched for. Refusing the bundle is
    also the cheaper failure: it happens once, on the operator's machine, rather than silently in
    every container that ever loads the file.
    """
    if not isinstance(listed, list):
        raise BundleError("bundle-schema-type-mismatch", "revocations must be a list")
    for item in listed:
        if not isinstance(item, dict) or verify_signed_object(item) is None:
            raise BundleError(
                "bundle-revocation-sig-invalid", f"{path} carries a revocation that does not verify"
            )
        if not isinstance(item.get("revokes"), str) or not isinstance(item.get("revoked-at"), str):
            raise BundleError(
                "bundle-revocation-schema", f"{path} carries a revocation missing revokes/revoked-at"
            )
    return list(listed)

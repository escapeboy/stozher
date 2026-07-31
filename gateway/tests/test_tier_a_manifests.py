"""Tier A: a registered manifest governs its own component's classification (§08, §10 §3).

`Classifier` has consulted manifests since S2 and **nothing ever loaded one**, so a component we did
not write always fell through to the shipped table, the org's seeded catalogue, or the shape
heuristic. The heuristic is the tier the four-class taxonomy is least confident about, and leaving it
is the whole reason a third party registers a manifest at all — so tier A existing in the classifier
and never being reachable made registration decorative.

The negative half matters as much: a manifest must not be able to *widen* anything. What it declares
is a proposal (§05 §3); policy decides, and the kernel recomputes the class independently for the
envelope it stores. A test that only showed the class changing would equally describe a gateway that
had handed classification to the component being governed.
"""

from __future__ import annotations

from typing import Any

from stozher_gateway.classify import (
    TIER_HEURISTIC,
    TIER_MANIFEST,
    TIER_ORG_SEEDED,
    Classifier,
)
from stozher_gateway.manifests import ManifestFeed


def manifest(name: str, action: str, klass: str) -> dict[str, Any]:
    return {
        "v": "stozher/0.1",
        "kind": "manifest",
        "name": name,
        "version": "1.0.0",
        "actions": [{"action": f"{name}.{action}", "class": klass}],
    }


class _Response:
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self.body = body
        self.etag = None


class _Kernel:
    """A kernel client whose answer the test chooses, and which counts how often it is asked."""

    def __init__(self, response: Any) -> None:
        self._response = response
        self.calls = 0

    def manifests(self) -> Any:
        self.calls += 1
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def test_a_registered_manifest_decides_the_class_instead_of_the_heuristic() -> None:
    heuristic = Classifier(scopes={"notes": "notes"})
    without = heuristic.classify("notes", "write_note", {})
    assert without.tier == TIER_HEURISTIC, without
    # The shape heuristic reads `write_note` as consequential. That is a guess, and being right by
    # accident is exactly what makes an unreachable tier A hard to notice.
    assert without.classification == "consequential"

    declared = Classifier(
        scopes={"notes": "notes"},
        manifests={"notes": manifest("notes", "write_note", "prohibited")},
    )
    with_manifest = declared.classify("notes", "write_note", {})
    assert with_manifest.tier == TIER_MANIFEST
    assert with_manifest.classification == "prohibited"
    assert with_manifest.action == "notes.write_note"


def test_a_manifest_cannot_widen_what_the_org_already_decided() -> None:
    """The manifest is consulted first, so this is the assertion that keeps it honest.

    A component declaring its own destructive action `read` must not thereby make it `read`
    everywhere. It cannot: what the classifier produces is a *proposal*, policy applies its own
    `reclassify` rules over the result (§05 §3), and the kernel recomputes the class independently
    for the envelope it stores — the gateway's answer never reaches the audit trail unchallenged.
    This test pins the seam rather than the whole chain: the tier is reported as `manifest`, so a
    reader of the record can always see that the component spoke for itself.
    """
    declared = Classifier(
        scopes={"notes": "notes"},
        manifests={"notes": manifest("notes", "delete_everything", "read")},
        org_seeded=lambda server, tool: ("notes.delete_everything", "prohibited"),
    )
    result = declared.classify("notes", "delete_everything", {})
    assert result.classification == "read"
    assert result.tier == TIER_MANIFEST, (
        "the tier must say a manifest decided this, or nothing downstream can tell a component's "
        "own claim from the organisation's"
    )

    # And with no manifest, the org's catalogue is what answers.
    seeded = Classifier(
        scopes={"notes": "notes"},
        org_seeded=lambda server, tool: ("notes.delete_everything", "prohibited"),
    )
    assert seeded.classify("notes", "delete_everything", {}).tier == TIER_ORG_SEEDED


def test_the_classifier_reads_the_feed_on_every_call_so_a_registration_lands_mid_session() -> None:
    """`kernel.register_component` is a gated action a human signs while the gateway is running.

    A classifier that snapshotted the manifests at construction would keep classifying a freshly
    registered component by the shape heuristic until someone restarted the process — which is the
    tier the registration existed to leave.
    """
    live: dict[str, dict[str, Any]] = {}
    classifier = Classifier(scopes={"notes": "notes"}, manifests=lambda: live)

    assert classifier.classify("notes", "write_note", {}).tier == TIER_HEURISTIC
    live["notes"] = manifest("notes", "write_note", "benign")
    after = classifier.classify("notes", "write_note", {})
    assert after.tier == TIER_MANIFEST
    assert after.classification == "benign"


def test_the_feed_keeps_what_it_has_when_the_kernel_is_unreachable() -> None:
    """Maxim 5: a component goes on enforcing while the kernel is unreachable.

    Losing the manifests would silently demote every governed component to the shape heuristic — a
    *quieter* failure than refusing, and a worse one, because the calls keep succeeding under a class
    nobody chose.
    """
    from stozher_gateway.kernel_client import KernelUnreachableError

    kernel = _Kernel(_Response(200, {"manifests": [manifest("notes", "write_note", "benign")]}))
    feed = ManifestFeed(kernel, refresh_seconds=0)  # type: ignore[arg-type]
    assert set(feed.current()) == {"notes"}

    kernel._response = KernelUnreachableError("connection refused")
    assert set(feed.current()) == {"notes"}, "an unreachable kernel emptied the manifest set"


def test_a_refusal_or_a_malformed_answer_is_not_read_as_an_empty_set() -> None:
    kernel = _Kernel(_Response(200, {"manifests": [manifest("notes", "write_note", "benign")]}))
    feed = ManifestFeed(kernel, refresh_seconds=0)  # type: ignore[arg-type]
    assert set(feed.current()) == {"notes"}

    for answer in (_Response(503, {}), _Response(401, {"error": "x"}), _Response(200, "not-json")):
        kernel._response = answer
        assert set(feed.current()) == {"notes"}, f"{answer.status} was read as 'no manifests'"


def test_a_manifest_without_a_usable_name_is_skipped_rather_than_keyed_by_nothing() -> None:
    kernel = _Kernel(
        _Response(
            200,
            {
                "manifests": [
                    manifest("notes", "write_note", "benign"),
                    {"kind": "manifest", "version": "1.0.0"},  # no name
                    {"name": "", "version": "1.0.0"},  # empty name
                    "not-an-object",
                ]
            },
        )
    )
    feed = ManifestFeed(kernel, refresh_seconds=0)  # type: ignore[arg-type]
    assert set(feed.current()) == {"notes"}

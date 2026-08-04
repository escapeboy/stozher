"""Every test an ADR cites must exist — the enforceable half of the citation-rot rule.

`docs/CONTRIBUTING.md` says code citations anchor by name rather than by line number, because line
numbers rot silently. Names rot too, just more slowly: on 2026-08-04 two ADRs were found citing
`concurrency.rs::one_approval_cannot_be_consumed_twice_however_the_requests_race`, a test no longer
called that. The property it named was bound the whole time by `s6_one_approval_cannot_be_spent_twice`
— nothing was broken except the reader's ability to check.

That is the third instance in three days of a record describing a state of affairs that had stopped
being true (`docs/spec-debt.md`, five claims; ADR-0032 §5, its own gap overstated; ADR-0030 §6, a
residual bound days earlier). The common cause is structural rather than careless: **the artifact and
the record of the artifact are changed by different acts, and only the first one has a test.** This
file gives the second one a test.

# What this can and cannot catch

It catches a citation that no longer resolves — a renamed, moved or deleted test still being offered
as evidence. That is the failure that makes a decision record unfalsifiable, which is worse than an
absent one, because a reader who follows it and finds nothing cannot tell "removed" from "renamed".

It does **not** catch the other half: a table saying *"No test"* about a claim that has since been
bound. Nothing mechanical distinguishes an honest gap from a stale one — that stays a reading duty,
and `docs/spec-debt.md` records it as the rule to apply at the end of any run that pays into a
ledger. Stated here so this file is not mistaken for full cover.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

#: `some_file.rs::a_test_name` / `tests/test_x.py::test_y` as the ADRs write them.
CITATION = re.compile(r"([A-Za-z0-9_./-]+\.(?:rs|py))::([a-z0-9_]+)")

#: Where the tests being cited actually live.
SOURCE_ROOTS = ("kernel", "gateway", "console")

EXCLUDED = ("/target/", "/.venv/", "/__pycache__/", "/node_modules/")


def _sources() -> dict[str, str]:
    """Every Rust and Python source in the tree, keyed by basename.

    Keyed by basename rather than by path because that is how the ADRs cite: `concurrency.rs::x`,
    not the full path from the repository root. A basename collision would make this check weaker,
    never wrong — it would search both files.
    """
    bodies: dict[str, str] = {}
    for root in SOURCE_ROOTS:
        base = REPO / root
        if not base.is_dir():
            continue
        for path in list(base.rglob("*.rs")) + list(base.rglob("*.py")):
            if any(part in str(path) for part in EXCLUDED):
                continue
            bodies[path.name] = bodies.get(path.name, "") + path.read_text(
                encoding="utf-8", errors="ignore"
            )
    return bodies


#: Reports written by someone outside this repository, preserved verbatim.
#:
#: Their citations are to *their* tree — a reviewer's scratch worktree, a partner's install — and
#: resolving them here is neither possible nor the point. The alternative was to edit an external
#: report so it would pass our lint, which would make it no longer the document they wrote. A
#: preserved outside opinion is evidence; an edited one is a summary of it.
EXTERNAL_REPORTS = ("docs/validation/security-review-", "docs/validation/design-partners/")


def _citations() -> list[tuple[Path, str, str]]:
    found: list[tuple[Path, str, str]] = []
    for doc in sorted((REPO / "docs").rglob("*.md")):
        relative = doc.relative_to(REPO).as_posix()
        if any(relative.startswith(prefix) for prefix in EXTERNAL_REPORTS):
            continue
        for filename, name in CITATION.findall(doc.read_text(encoding="utf-8")):
            found.append((doc.relative_to(REPO), Path(filename).name, name))
    return found


def test_every_test_an_adr_cites_still_exists() -> None:
    sources = _sources()
    citations = _citations()

    # A guard against the check quietly becoming vacuous: if the regex stops matching — because the
    # ADRs adopt a different citation style, say — this test would pass while asserting nothing.
    assert len(citations) > 40, f"only {len(citations)} citations found; the pattern may have rotted"

    unresolved = []
    for doc, filename, name in citations:
        body = sources.get(filename)
        if body is None:
            unresolved.append(f"{doc}: cites {filename}::{name}, and no such file is in the tree")
        elif f"fn {name}" not in body and f"def {name}" not in body:
            unresolved.append(f"{doc}: cites {filename}::{name}, and {filename} has no such test")

    assert not unresolved, "decision records cite tests that do not exist:\n  " + "\n  ".join(
        unresolved
    )


@pytest.mark.parametrize("known", ["console_evidence_and_approver.rs", "test_enforcement.py"])
def test_the_source_index_finds_both_languages(known: str) -> None:
    """The check is worthless if it silently indexes only one side of the repository."""
    assert known in _sources(), f"{known} is not in the source index, so its citations go unchecked"

"""`docs/open-defects.md` and the `open_defect` marker must agree.

A defect recorded with no executable evidence is a claim. A quarantined test for a defect nobody
recorded is orphaned evidence that the next person deletes because they cannot tell what it is for.
Both drift silently, because neither shows up as a failure anywhere else — the register is prose and
the quarantine is excluded from the default run by construction.

So this test is the binding, and it is deliberately in the *default* suite: it is the one thing about
the quarantine that must go red the moment the two disagree. It asserts a correspondence, never a
count — a run that adds a second reproduction for an open defect must not have to edit this file.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTER = REPO / "docs" / "open-defects.md"
#: The register's status column, and what each status obliges. `open` is the only one that must have
#: evidence: a closed defect's test is unquarantined and green, and a defect that turned out not to
#: exist has nothing to reproduce.
NEEDS_EVIDENCE = {"open"}
#: `observed` (added 2026-08-04 for DEF-7) is the status for something real that happened and whose
#: mechanism is not yet established, so no honest reproduction exists to quarantine. It would be a
#: loophole in the rule above — a way to record a defect while owing nothing — except that it owes
#: something else, and `test_an_observed_defect_says_where_the_observation_lives` collects it: a row
#: at this status MUST cite where a reader can go and look. "We saw it and could not pin it" is a
#: legitimate state; "we saw it" with no pointer is the claim the register exists to forbid.
NEEDS_A_POINTER = {"observed"}

_ROW = re.compile(r"^\|\s*(DEF-\d+)\s*\|\s*([a-z ]+?)\s*\|", re.MULTILINE)
#: Both spellings, because the two languages cannot use the same one: a Python identifier may not
#: contain a hyphen (`test_def4_…`), while the Rust attribute is a string and carries it
#: (`#[ignore = "DEF-4 open"]`). Matching only the hyphenated form silently found the Rust evidence
#: and none of the Python, which read as "DEF-4 has no reproduction" when it has three.
_DEF_ID = re.compile(r"DEF-?(\d+)")


def _ids(text: str) -> set[str]:
    return {f"DEF-{number}" for number in _DEF_ID.findall(text.upper())}


def _registered() -> dict[str, str]:
    """Every `DEF-n` in the register's table, mapped to its status."""
    return {row[0]: row[1] for row in _ROW.findall(REGISTER.read_text())}


def _quarantined_python() -> set[str]:
    """The `DEF-n` ids named by tests the `open_defect` marker selects.

    Collected by running pytest rather than by grepping for the decorator: the marker can be applied
    at module level, by a decorator, or by `pytestmark`, and a grep that knew only one of those would
    pass while the quarantine drifted.
    """
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", str(REPO / "gateway" / "tests"),
         "-m", "open_defect", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=300,
    )
    return _ids(collected.stdout)


def _quarantined_rust() -> set[str]:
    """The `DEF-n` ids named by `#[ignore = "DEF-n open"]` in the kernel's test crate."""
    ids: set[str] = set()
    for source in (REPO / "kernel" / "stozher-kernel" / "tests").glob("*.rs"):
        for line in source.read_text().splitlines():
            if "#[ignore" in line:
                ids |= _ids(line)
    return ids


def test_every_open_defect_in_the_register_has_executable_evidence() -> None:
    register = _registered()
    assert register, f"no DEF rows parsed out of {REGISTER} — the table's shape changed"
    evidence = _quarantined_python() | _quarantined_rust()
    missing = {
        defect
        for defect, status in register.items()
        if status in NEEDS_EVIDENCE and defect not in evidence
    }
    assert not missing, (
        f"{sorted(missing)} recorded as open in docs/open-defects.md with no quarantined test. "
        "A defect with no executable evidence is a claim; either write the reproduction or change "
        "its status in the register."
    )


def test_every_quarantined_test_names_a_defect_the_register_records() -> None:
    register = _registered()
    orphans = (_quarantined_python() | _quarantined_rust()) - set(register)
    assert not orphans, (
        f"{sorted(orphans)} have quarantined tests and no row in docs/open-defects.md. "
        "Orphaned evidence gets deleted by whoever cannot tell what it is for."
    )


def test_a_defect_that_is_not_open_carries_no_quarantined_test() -> None:
    """The paired negative, and the one that keeps the quarantine honest.

    Without it, the two tests above are satisfied by marking everything `open_defect` forever: a
    defect that has been fixed, or that turned out not to exist, would keep a red test in the
    quarantine and nobody would notice it had stopped meaning anything. DEF-3 (closed) and DEF-5
    (investigated, not found) are both in the register precisely so this has something to check.
    """
    evidence = _quarantined_python() | _quarantined_rust()
    stale = {
        defect
        for defect, status in _registered().items()
        if status not in NEEDS_EVIDENCE and defect in evidence
    }
    assert not stale, (
        f"{sorted(stale)} are not open in docs/open-defects.md but still have a quarantined test. "
        "A fixed defect's test belongs in the default suite; a defect that does not exist has "
        "nothing to reproduce."
    )


def test_an_observed_defect_says_where_the_observation_lives() -> None:
    """`observed` owes a pointer, since it does not owe a reproduction.

    The status exists so that "something real happened and I could not pin it" has somewhere to be
    written down rather than being rounded to "flake" — which is what nearly happened to DEF-6, and
    DEF-6 was a real high-severity defect. But a status that obliges nothing is a way to record a
    defect for free, and a register that accepts free rows stops being evidence. So this one obliges
    the other half: a reader must be able to go and look at what was seen.
    """
    text = REGISTER.read_text(encoding="utf-8")
    register = _registered()
    observed = [defect for defect, status in register.items() if status in NEEDS_A_POINTER]

    for defect in observed:
        # The row itself, not the whole file: a pointer three sections away is not a pointer the
        # reader of the table has.
        row = next(
            line for line in text.splitlines() if line.startswith(f"| {defect} ")
        )
        # A run identifier, **or** a preserved report in the tree. The second was added on
        # 2026-08-04, when an external review and four design-partner evaluations produced
        # observations whose home is a document rather than a CI run. Requiring a six-digit number
        # would have pushed those rows to a status that fits them worse — and the obligation this
        # test exists to enforce is "a reader can go and look", which a committed report satisfies
        # at least as well as a run id, and outlives it: GitHub expires logs.
        pointer = re.search(r"\b\d{6,}\b", row) or re.search(r"(docs/)?validation/[\w./-]+", row)
        assert pointer, (
            f"{defect} is recorded as `observed` and its row cites no run identifier, log, or "
            "preserved report. An observation nobody else can go and look at is the claim this "
            "register forbids."
        )

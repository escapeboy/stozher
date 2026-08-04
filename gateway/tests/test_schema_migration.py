"""The gateway's store can be upgraded, and the classification that makes it safe is not folklore.

`docs/product-completion-design.md` §4.1 wrote this design for both halves. The kernel got it on
2026-08-02; the gateway kept `CREATE TABLE IF NOT EXISTS` and no version, which is
forward-compatible only until the first additive column, at which point an existing deployment has
no way to receive it.

The test that matters here is not "migrations run" — it is
`test_the_classification_covers_every_table_the_database_holds`. A set of table names in a Python
module is a comment unless something binds it to the tables that actually exist; without that, the
next table added is unclassified, and the first person to write a step that drops a projection finds
out at an audit which side of the line it was on.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from stozher_gateway import migrate
from stozher_gateway.store import _SCHEMA, GatewayStore


def _tables(path: Path) -> set[str]:
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    finally:
        connection.close()
    return {row[0] for row in rows}


def _user_version(path: Path) -> int:
    connection = sqlite3.connect(path)
    try:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])
    finally:
        connection.close()


def test_the_registry_is_well_formed() -> None:
    """Ordered, contiguous, starting at 1 and ending at the version this build writes."""
    versions = [step.to_version for step in migrate.MIGRATIONS]
    assert versions == sorted(versions), "the registry is out of order"
    assert versions == list(range(1, len(versions) + 1)), "the registry has a gap"
    assert versions[-1] == migrate.SCHEMA_VERSION, (
        "the last step and SCHEMA_VERSION disagree; a store would be stamped a version no step "
        "produced"
    )
    assert all(step.name for step in migrate.MIGRATIONS), "a step with no name reads as nothing"


def test_the_classification_covers_every_table_the_database_holds(tmp_path: Path) -> None:
    """The binding. Every table is on exactly one side, and reality decides the list.

    A table added without a line here fails this, which is the only thing that stops the two sets
    becoming a stale comment about a schema that has moved on.
    """
    GatewayStore(tmp_path / "gateway.db")
    held = _tables(tmp_path / "gateway.db")

    classified = migrate.PRESERVED_TABLES | migrate.REBUILDABLE_TABLES
    assert held - classified == set(), (
        f"unclassified table(s): {sorted(held - classified)} — decide whether each may be dropped "
        "and recomputed, or must survive an upgrade"
    )
    assert classified - held == set(), (
        f"classified but absent: {sorted(classified - held)} — the classification is describing a "
        "schema that no longer exists"
    )
    assert not migrate.PRESERVED_TABLES & migrate.REBUILDABLE_TABLES, (
        "a table cannot be both droppable and required"
    )
    assert migrate.CHAIN_BEARING_TABLES <= migrate.PRESERVED_TABLES, (
        "a chain-bearing table classified as rebuildable would license dropping the audit trail"
    )


def test_the_single_use_ledger_is_not_rebuildable() -> None:
    """Named on its own because it is the one that looks like a cache and is not.

    `gate_seen` holds no chain and no signature, so a reader classifying by shape would put it with
    the caches. Dropping it un-spends every single-use approval this component has consumed, which
    is DEF-7 by another route.
    """
    assert "gate_seen" in migrate.PRESERVED_TABLES
    assert "gate_seen" not in migrate.REBUILDABLE_TABLES


def test_an_unstamped_store_is_upgraded_in_place_and_keeps_its_rows(tmp_path: Path) -> None:
    """The actual upgrade path: a store from before this file existed, opened by a build that has it.

    Built by hand from the raw schema so that it is genuinely a pre-migration store — `user_version`
    0, real rows, no stamp.
    """
    path = tmp_path / "gateway.db"
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_SCHEMA)
        connection.execute(
            "INSERT INTO gate_seen (request_hash, used_at) VALUES (?, ?)",
            ("a" * 64, "2026-08-04T00:00:00.000Z"),
        )
        connection.commit()
    finally:
        connection.close()
    assert _user_version(path) == 0

    GatewayStore(path)

    assert _user_version(path) == migrate.SCHEMA_VERSION
    store = GatewayStore(path)
    assert store.gate_seen("a" * 64), "the spent-approval ledger did not survive the upgrade"


def test_a_store_written_by_a_newer_gateway_is_refused(tmp_path: Path) -> None:
    """Refused, not tolerated. An older build writing under a newer schema fails at read time on the
    newer build, which is the wrong place to find out."""
    path = tmp_path / "gateway.db"
    GatewayStore(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"PRAGMA user_version = {migrate.SCHEMA_VERSION + 1}")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(migrate.SchemaAheadError):
        GatewayStore(path)


def test_opening_an_already_current_store_applies_nothing(tmp_path: Path) -> None:
    """Idempotence, stated as "no steps ran" rather than "it did not crash"."""
    path = tmp_path / "gateway.db"
    GatewayStore(path)

    connection = sqlite3.connect(path)
    try:
        assert migrate.run(connection) == [], "a current store re-ran its migrations"
    finally:
        connection.close()

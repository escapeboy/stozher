"""Forward-only schema migration for the gateway's store — `docs/product-completion-design.md` §4.1.

The kernel got this on 2026-08-02 (`kernel/stozher-kernel/src/migrate.rs`, schema version 7). The
gateway did not, and re-applied `CREATE TABLE IF NOT EXISTS` on every open — forward-compatible by
accident, in the sense that the first additive column would ship with no mechanism to reach an
existing database. Half a system that can evolve its schema is a deployment that cannot be upgraded.

# Why this is not a normal migration runner

The same constraint the kernel has, for the same reason: `envelopes` is append-only and hash-chained,
and §10 §7 makes this the gateway's *durable* record — the copy that exists before the kernel has
seen anything. A migration that rewrites a chain-bearing row invalidates every hash link after it.

* **Chain-bearing tables are additive-only.** New columns must be nullable or defaulted; nothing may
  rewrite `id`, `seq`, `envelope_json` or the stream a row belongs to. A change that cannot be
  expressed additively is a new stream or a new envelope kind, never a rewrite.
* **Projections are rebuildable; everything else is not.** [`REBUILDABLE_TABLES`] may be dropped and
  refetched. [`PRESERVED_TABLES`] may not — and that set is wider than "the chain": `gate_seen` is
  the single-use approval ledger, and dropping it re-opens every approval this component has already
  spent, which is the exact defect (DEF-7) that cost this project a week.
* **The version is stamped last, and steps are idempotent.** `sqlite3.executescript` issues an
  implicit commit before it runs, so a step cannot be rolled back by wrapping the run — claiming
  "one transaction" here would be a comment that is not true of the code. What holds instead: a step
  that raises leaves `user_version` unchanged, so the next boot re-applies from the same point, and
  every step must therefore be written to survive being applied twice. The kernel's runner does get
  a real transaction; this one does not, and says so rather than implying it.
* **A store written by a newer gateway is refused, not opened.** Downgrading in place would mean an
  older build writing rows a newer schema owns.

# What "version 1" is

The baseline is the schema as it stood before there was a version at all. A fresh file and an
existing pre-migration store both report `PRAGMA user_version = 0`, and applying the baseline to
either is idempotent — every statement in it is `CREATE ... IF NOT EXISTS`. So the first boot of a
gateway that has this file stamps an existing store 1 and changes nothing else, which is the upgrade
path rather than a special case of it.

There is deliberately no `down`. A downgrade would have to discard rows, and the rows in question
are an audit trail.
"""

from __future__ import annotations

import sqlite3
from typing import Final

__all__ = [
    "CHAIN_BEARING_TABLES",
    "MIGRATIONS",
    "PRESERVED_TABLES",
    "REBUILDABLE_TABLES",
    "SCHEMA_VERSION",
    "Migration",
    "SchemaAheadError",
    "run",
    "version",
]

#: The schema version this build writes and expects.
SCHEMA_VERSION: Final = 1

#: Append-only and hash-linked. Never rewritten, never dropped, additive columns only.
CHAIN_BEARING_TABLES: Final = frozenset({"envelopes"})

#: Local caches of something the kernel or a signed bundle is authoritative for. Safe to drop and
#: refetch — losing one costs a round trip, and a stale one fails closed anyway (`_policy`).
REBUILDABLE_TABLES: Final = frozenset({"policy_cache", "revocation_cache"})

#: Everything that is neither chained nor refetchable, and therefore must survive an upgrade.
#:
#: `gate_seen` is the reason this set exists separately from `CHAIN_BEARING_TABLES`: it holds no
#: chain and no signature, and dropping it would silently un-spend every single-use approval this
#: component has consumed. `intents` is the write-ahead record — losing one means an effect that was
#: applied and can never be accounted for. `parked` holds requests a human has not answered yet.
PRESERVED_TABLES: Final = frozenset(
    {"envelopes", "intents", "parked", "catalog", "gate_seen", "marks", "wedges"}
)


class SchemaAheadError(RuntimeError):
    """The store was written by a newer gateway than this one.

    Raised rather than tolerated: an older build opening a newer store would write rows under a
    schema it does not know, and the first symptom would be at read time on the newer build.
    """


class Migration:
    """One forward-only step, ordered by the version it leaves the store at."""

    def __init__(self, to_version: int, name: str, sql: str) -> None:
        self.to_version = to_version
        self.name = name
        self.sql = sql


def _baseline() -> str:
    # Imported here rather than at module scope: `store` imports this module, and the baseline is
    # the schema `store` already holds — one definition, not a second copy to drift from.
    from .store import _SCHEMA

    return _SCHEMA


#: The registry. Ordered and contiguous, asserted by `test_the_registry_is_well_formed`.
MIGRATIONS: Final[list[Migration]] = [
    Migration(1, "baseline — the schema as it stood before there was a version", ""),
]


def version(connection: sqlite3.Connection) -> int:
    """The store's current schema version. `0` means "never stamped", not "empty"."""
    return int(connection.execute("PRAGMA user_version").fetchone()[0])


def run(connection: sqlite3.Connection) -> list[int]:
    """Bring the store up to `SCHEMA_VERSION`. Returns the versions applied, in order.

    Raises `SchemaAheadError` when the store is ahead of this build.
    """
    current = version(connection)
    if current > SCHEMA_VERSION:
        raise SchemaAheadError(
            f"the store is at schema version {current} and this gateway writes {SCHEMA_VERSION}; "
            "it was written by a newer build and will not be opened by this one"
        )
    if current == SCHEMA_VERSION:
        return []

    applied: list[int] = []
    for step in MIGRATIONS:
        if step.to_version <= current:
            continue
        # The baseline carries no SQL of its own: it *is* the store's schema, which `GatewayStore`
        # applies on every open and which is idempotent. Stamping it is the whole step.
        connection.executescript(step.sql or _baseline())
        applied.append(step.to_version)
    # `PRAGMA user_version` takes no parameter binding — the value is interpolated, and it is an int
    # from this module's own registry, never from input.
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return applied

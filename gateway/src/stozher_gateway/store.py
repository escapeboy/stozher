"""The gateway's local durable state: its own chain, parked requests, and the org-seeded catalog.

§10 §7: the gateway MUST NOT keep the only copy of an emitted envelope in memory — local durable
chaining before the effect reaches the audit is required. So an envelope is written here first and
pushed to the kernel afterwards; a kernel that is briefly unreachable costs latency on the push, not
records.

Shape follows `dispatcher_metrics_store.py:31-67`: a lazy singleton, a **short-lived connection per
call** (so an outbound HTTP call can never deadlock against a held handle), WAL, `timeout=5.0`, and
`0o700`/`0o600` permissions. The path takes a `STOZHER_GATEWAY_DB` override resolved in one place,
because Harbormaster's own import-time stores are the hazard this pattern exists to avoid.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

__all__ = ["GatewayStore", "Parked"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS envelopes (
    stream        TEXT    NOT NULL,
    seq           INTEGER NOT NULL,
    id            TEXT    NOT NULL UNIQUE,
    envelope_json TEXT    NOT NULL,
    payloads_json TEXT    NOT NULL DEFAULT '[]',
    created_at    TEXT    NOT NULL,
    pushed_at     TEXT,
    push_error    TEXT,
    PRIMARY KEY (stream, seq)
);
CREATE INDEX IF NOT EXISTS envelopes_unpushed ON envelopes (pushed_at) WHERE pushed_at IS NULL;

CREATE TABLE IF NOT EXISTS parked (
    request_hash  TEXT PRIMARY KEY,
    request_json  TEXT NOT NULL,
    server        TEXT NOT NULL,
    tool          TEXT NOT NULL,
    proposed_class TEXT NOT NULL,
    arg_schema_json TEXT NOT NULL DEFAULT 'null',
    first_call    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    decision_json TEXT,
    catalog_class TEXT,
    seed_json     TEXT,
    consumed_at   TEXT
);

CREATE TABLE IF NOT EXISTS catalog (
    server     TEXT NOT NULL,
    tool       TEXT NOT NULL,
    action     TEXT NOT NULL,
    class      TEXT NOT NULL,
    origin     TEXT NOT NULL,
    seeded_at  TEXT NOT NULL,
    envelope_id TEXT,
    PRIMARY KEY (server, tool)
);

CREATE TABLE IF NOT EXISTS policy_cache (
    version      TEXT PRIMARY KEY,
    document_json TEXT NOT NULL,
    verified_at  TEXT NOT NULL,
    is_current   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS gate_seen (
    request_hash TEXT PRIMARY KEY,
    used_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS marks (
    key TEXT PRIMARY KEY,
    at  TEXT NOT NULL
);
"""


class Parked:
    """A request waiting for a human's signature."""

    def __init__(self, row: sqlite3.Row) -> None:
        self.request_hash: str = row["request_hash"]
        self.request: dict[str, Any] = json.loads(row["request_json"])
        self.server: str = row["server"]
        self.tool: str = row["tool"]
        self.proposed_class: str = row["proposed_class"]
        self.arg_schema: Any = json.loads(row["arg_schema_json"])
        self.first_call: bool = bool(row["first_call"])
        self.created_at: str = row["created_at"]
        self.decision: dict[str, Any] | None = (
            json.loads(row["decision_json"]) if row["decision_json"] else None
        )
        self.catalog_class: str | None = row["catalog_class"]
        self.seed: dict[str, Any] | None = json.loads(row["seed_json"]) if row["seed_json"] else None
        self.consumed_at: str | None = row["consumed_at"]


class GatewayStore:
    """SQLite-backed local state. One short-lived connection per call."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._shared: sqlite3.Connection | None = None
        if str(path) == ":memory:":
            # An in-memory database dies with its connection, so tests keep one open. Production
            # never takes this branch.
            self._shared = sqlite3.connect(":memory:", check_same_thread=False)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
        if str(path) != ":memory:" and path.exists():
            os.chmod(path, 0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._shared is not None:
                self._shared.row_factory = sqlite3.Row
                yield self._shared
                self._shared.commit()
                return
            connection = sqlite3.connect(self.path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                yield connection
                connection.commit()
            finally:
                connection.close()

    # -- the local chain ------------------------------------------------------------------

    def head(self, stream: str) -> tuple[int, str | None]:
        """The next free `seq` and the `prev-hash` it must carry."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT seq, id FROM envelopes WHERE stream = ? ORDER BY seq DESC LIMIT 1",
                (stream,),
            ).fetchone()
        if row is None:
            return 0, None
        return int(row["seq"]) + 1, str(row["id"])

    def append(
        self,
        stream: str,
        seq: int,
        envelope_id: str,
        envelope: dict[str, Any],
        payloads: list[dict[str, Any]],
        created_at: str,
    ) -> None:
        """Durably record an envelope before it is pushed anywhere."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO envelopes (stream, seq, id, envelope_json, payloads_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (stream, seq, envelope_id, json.dumps(envelope), json.dumps(payloads), created_at),
            )

    def unpushed(self, limit: int = 64) -> list[tuple[str, dict[str, Any], list[dict[str, Any]]]]:
        """Envelopes not yet accepted by the kernel, in chain order per stream."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, envelope_json, payloads_json FROM envelopes WHERE pushed_at IS NULL "
                "ORDER BY stream, seq LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            (row["id"], json.loads(row["envelope_json"]), json.loads(row["payloads_json"]))
            for row in rows
        ]

    def mark_pushed(self, envelope_id: str, at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE envelopes SET pushed_at = ?, push_error = NULL WHERE id = ?",
                (at, envelope_id),
            )

    def mark_push_error(self, envelope_id: str, detail: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE envelopes SET push_error = ? WHERE id = ?", (detail, envelope_id)
            )

    def pending_push_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM envelopes WHERE pushed_at IS NULL"
            ).fetchone()
        return int(row["n"])

    # -- parked requests ------------------------------------------------------------------

    def park(
        self,
        request_hash: str,
        request: dict[str, Any],
        server: str,
        tool: str,
        proposed_class: str,
        arg_schema: Any,
        first_call: bool,
        created_at: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO parked (request_hash, request_json, server, tool, "
                "proposed_class, arg_schema_json, first_call, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_hash,
                    json.dumps(request),
                    server,
                    tool,
                    proposed_class,
                    json.dumps(arg_schema),
                    int(first_call),
                    created_at,
                ),
            )

    def decided_for(self, request_fields: dict[str, Any]) -> Parked | None:
        """A parked request that carries a decision and describes exactly this call.

        The lookup is by the request's own identity fields — subject, key, component, mandate,
        policy version, class, action, target, args-hash. A decision found here still goes through
        §06 §2 in full before anything acts on it; matching rows is how the approval is *located*,
        never how it is trusted.
        """
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM parked WHERE decision_json IS NOT NULL AND consumed_at IS NULL "
                "ORDER BY created_at"
            ).fetchall()
        for row in rows:
            request = json.loads(row["request_json"])
            if all(request.get(name) == value for name, value in request_fields.items()):
                return Parked(row)
        return None

    def seeded_pending(self) -> list[Parked]:
        """Decided requests carrying a catalog seed. The seed is about *future* calls of the tool,
        so it is applied when the decision exists, not when the original call happens to be retried.
        """
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM parked WHERE seed_json IS NOT NULL ORDER BY created_at"
            ).fetchall()
        return [Parked(row) for row in rows]

    def consume(self, request_hash: str, at: str) -> None:
        """Mark a parked request used, so a later call parks afresh rather than reusing it."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE parked SET consumed_at = ? WHERE request_hash = ?", (at, request_hash)
            )

    def parked(self, request_hash: str) -> Parked | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM parked WHERE request_hash = ?", (request_hash,)
            ).fetchone()
        return Parked(row) if row is not None else None

    def pending(self) -> list[Parked]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM parked WHERE decision_json IS NULL ORDER BY created_at"
            ).fetchall()
        return [Parked(row) for row in rows]

    def record_decision(
        self,
        request_hash: str,
        decision: dict[str, Any],
        catalog_class: str | None,
        seed: dict[str, Any] | None = None,
    ) -> None:
        """Store a signed gate decision against its request.

        This is transport, not authority: the decision is verified through §06 §2 before anything
        acts on it, and a row here that fails verification permits nothing.
        """
        with self._connect() as connection:
            connection.execute(
                "UPDATE parked SET decision_json = ?, catalog_class = ?, seed_json = ? "
                "WHERE request_hash = ?",
                (
                    json.dumps(decision),
                    catalog_class,
                    json.dumps(seed) if seed is not None else None,
                    request_hash,
                ),
            )

    # -- the org-seeded catalog (Tier B') ---------------------------------------------------

    def catalog_entry(self, server: str, tool: str) -> tuple[str, str] | None:
        """`(action, class)` for an org-seeded entry, or None."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT action, class FROM catalog WHERE server = ? AND tool = ?", (server, tool)
            ).fetchone()
        return (row["action"], row["class"]) if row is not None else None

    def seed_catalog(
        self,
        server: str,
        tool: str,
        action: str,
        classification: str,
        seeded_at: str,
        envelope_id: str,
    ) -> None:
        """Record an org-seeded entry. `envelope_id` is the signed record that put it in force."""
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO catalog (server, tool, action, class, origin, seeded_at, "
                "envelope_id) VALUES (?, ?, ?, ?, 'org-seeded', ?, ?)",
                (server, tool, action, classification, seeded_at, envelope_id),
            )

    def catalog(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM catalog ORDER BY server, tool").fetchall()
        return [dict(row) for row in rows]

    # -- policy cache ---------------------------------------------------------------------

    def cache_policy(self, version: str, document: dict[str, Any], verified_at: str) -> None:
        """Persist a **verified** policy document. A component must enforce it while offline."""
        with self._connect() as connection:
            connection.execute("UPDATE policy_cache SET is_current = 0")
            connection.execute(
                "INSERT OR REPLACE INTO policy_cache (version, document_json, verified_at, "
                "is_current) VALUES (?, ?, ?, 1)",
                (version, json.dumps(document), verified_at),
            )

    def cached_policy(self) -> tuple[dict[str, Any], str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document_json, verified_at FROM policy_cache WHERE is_current = 1"
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["document_json"]), row["verified_at"]

    # -- gate replay ----------------------------------------------------------------------

    def mark(self, key: str, at: str) -> None:
        """Record that a one-time step (publishing a mandate, say) has been done."""
        with self._connect() as connection:
            connection.execute("INSERT OR IGNORE INTO marks (key, at) VALUES (?, ?)", (key, at))

    def marked(self, key: str) -> bool:
        with self._connect() as connection:
            row = connection.execute("SELECT 1 FROM marks WHERE key = ?", (key,)).fetchone()
        return row is not None

    def gate_seen(self, request_hash: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM gate_seen WHERE request_hash = ?", (request_hash,)
            ).fetchone()
        return row is not None

    def record_gate_use(self, request_hash: str, at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO gate_seen (request_hash, used_at) VALUES (?, ?)",
                (request_hash, at),
            )

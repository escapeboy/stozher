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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

__all__ = ["GatewayStore", "Parked", "Wedge"]

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

-- The write-ahead record of an effect, written before the effect is applied and closed once the
-- effect's envelope is chained (§09 §4.1, `emitter-must-persist-before-apply`). A row that outlives
-- its call is a crash marker: the downstream may have run and nothing was chained for it.
CREATE TABLE IF NOT EXISTS intents (
    intent_id     TEXT PRIMARY KEY,
    stream        TEXT NOT NULL,
    subject_key   TEXT NOT NULL,
    body_json     TEXT NOT NULL,
    payloads_json TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    resolved_at   TEXT
);
CREATE INDEX IF NOT EXISTS intents_open ON intents (stream) WHERE resolved_at IS NULL;

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

CREATE TABLE IF NOT EXISTS revocation_cache (
    epoch          TEXT PRIMARY KEY,
    documents_json TEXT NOT NULL,
    verified_at    TEXT NOT NULL,
    is_current     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS gate_seen (
    request_hash TEXT PRIMARY KEY,
    used_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS marks (
    key TEXT PRIMARY KEY,
    at  TEXT NOT NULL
);

-- A stream the kernel is refusing (§05 §7.1). One row per wedged stream, and it is the component's
-- own answer to "is anything I emit reaching the audit" — the reason code the kernel gave, when it
-- first gave it, and how many effects were served under the grace window since. It outlives the
-- process on purpose: a restart is not a recovery, and a wedge that cleared itself on a restart
-- would make the state unobservable to exactly the operator who restarts things to see what happens.
CREATE TABLE IF NOT EXISTS wedges (
    stream           TEXT PRIMARY KEY,
    envelope_id      TEXT NOT NULL,
    seq              INTEGER NOT NULL,
    reason_code      TEXT NOT NULL,
    detail           TEXT NOT NULL,
    first_refused_at TEXT NOT NULL,
    grace_served     INTEGER NOT NULL DEFAULT 0
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


class Wedge:
    """A stream the kernel is refusing, and the reason it gave (§05 §7.1)."""

    def __init__(self, row: sqlite3.Row) -> None:
        self.stream: str = row["stream"]
        self.envelope_id: str = row["envelope_id"]
        self.seq: int = int(row["seq"])
        self.reason_code: str = row["reason_code"]
        self.detail: str = row["detail"]
        self.first_refused_at: str = row["first_refused_at"]
        #: How many `read`/`benign` effects were served under the grace window (§05 §7.1 clause 4).
        self.grace_served: int = int(row["grace_served"])


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
    def _connect(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """One short-lived connection. `immediate` takes SQLite's writer lock up front.

        A `BEGIN IMMEDIATE` acquires the RESERVED lock before the first read, which is what makes a
        read-modify-write atomic *against other processes* and not merely against other threads.
        """
        with self._lock:
            if self._shared is not None:
                self._shared.row_factory = sqlite3.Row
                if immediate:
                    self._shared.execute("BEGIN IMMEDIATE")
                try:
                    yield self._shared
                    self._shared.commit()
                except BaseException:
                    self._shared.rollback()
                    raise
                return
            connection = sqlite3.connect(self.path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                if immediate:
                    connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            finally:
                connection.close()

    # -- the local chain ------------------------------------------------------------------

    def append_next(
        self,
        stream: str,
        build: Callable[[int, str | None], tuple[str, dict[str, Any]]],
        payloads: list[dict[str, Any]],
        created_at: str,
    ) -> str:
        """Take this stream's next `seq`, build the envelope for it and store it, atomically.

        Reading the head and inserting at it is one read-modify-write, and it must be atomic against
        every writer of this stream — not just every thread. A stream name is config-derived
        (`gw:<device>:<caller>`) and stdio spawns one process per client connection, so two
        connections of the same caller are two processes sharing one stream and one database file.
        An in-process lock says nothing about the other process: both read the same head, both build
        at that `seq`, and one loses `PRIMARY KEY (stream, seq)` — a `chain-write-failed` raised
        *after* the effect was already forwarded, which is the outcome §06 §6 spends the whole
        write-ahead design avoiding.

        Serializing on SQLite's own writer lock is preferred over a second lock of our own: the
        database is already the thing both processes share, an advisory file lock would be a
        parallel mechanism that can disagree with it, and a per-connection stream suffix would fix
        it by changing stream identity — which is spec-visible (§07) and would fragment one caller's
        audit trail into a chain per connection.

        `build` runs inside that transaction and MUST NOT touch this store: the lock guarding it is
        not reentrant. It is given the `seq` and `prev-hash` to chain at, and returns the envelope's
        id and body.
        """
        with self._connect(immediate=True) as connection:
            row = connection.execute(
                "SELECT seq, id FROM envelopes WHERE stream = ? ORDER BY seq DESC LIMIT 1",
                (stream,),
            ).fetchone()
            seq, prev = (0, None) if row is None else (int(row["seq"]) + 1, str(row["id"]))
            envelope_id, envelope = build(seq, prev)
            connection.execute(
                "INSERT INTO envelopes (stream, seq, id, envelope_json, payloads_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (stream, seq, envelope_id, json.dumps(envelope), json.dumps(payloads), created_at),
            )
        return envelope_id

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

    def mark_pushed(self, envelope_id: str, at: str, error: str | None = None) -> None:
        """Close the push of one envelope: accepted (`error` is None) or refused.

        One statement, and it writes the reason rather than erasing it. It used to be
        `SET pushed_at = ?, push_error = NULL`, run immediately after the refusal path had written
        the kernel's reason code into `push_error` — so the reason survived exactly one statement,
        the row became indistinguishable from an accepted one, and `pending_push_count()` reported
        a healthy queue while every envelope in it had been rejected. §05 §7.1 clause 2 now forbids
        erasing it on any later transition of the row, and this is the transition that was doing it.
        """
        with self._connect() as connection:
            connection.execute(
                "UPDATE envelopes SET pushed_at = ?, push_error = ? WHERE id = ?",
                (at, error, envelope_id),
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

    def refused_push_count(self) -> int:
        """Envelopes the kernel answered "no" to. Never zero while a stream is wedged."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM envelopes WHERE push_error IS NOT NULL "
                "AND pushed_at IS NOT NULL"
            ).fetchone()
        return int(row["n"])

    # -- refused streams (§05 §7.1) ---------------------------------------------------------

    def record_wedge(
        self, stream: str, envelope_id: str, seq: int, reason_code: str, detail: str, at: str
    ) -> None:
        """Record that the kernel refused this stream at this position.

        `INSERT OR IGNORE`: the *first* refusal is the one the grace window is measured from, so a
        second refusal on the same stream must not move `first_refused_at`. A wedge that could be
        re-graced by re-offering bytes would not be bounded (§05 §7.1 clause 4).
        """
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO wedges (stream, envelope_id, seq, reason_code, detail, "
                "first_refused_at) VALUES (?, ?, ?, ?, ?, ?)",
                (stream, envelope_id, seq, reason_code, detail, at),
            )

    def wedge(self, stream: str) -> Wedge | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM wedges WHERE stream = ?", (stream,)
            ).fetchone()
        return Wedge(row) if row is not None else None

    def wedges(self) -> list[Wedge]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM wedges ORDER BY stream").fetchall()
        return [Wedge(row) for row in rows]

    def clear_wedge(self, stream: str) -> None:
        """The kernel accepted something on this stream again — and that is the only thing that
        ends the state (§05 §7.2 rule 2). Not a timer, not a restart, not a new session."""
        with self._connect() as connection:
            connection.execute("DELETE FROM wedges WHERE stream = ?", (stream,))

    def note_grace_use(self, stream: str) -> int:
        """Count one effect served under the grace window. Returns the running total."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE wedges SET grace_served = grace_served + 1 WHERE stream = ?", (stream,)
            )
            row = connection.execute(
                "SELECT grace_served FROM wedges WHERE stream = ?", (stream,)
            ).fetchone()
        return int(row["grace_served"]) if row is not None else 0

    # -- write-ahead records ----------------------------------------------------------------

    def record_intent(
        self,
        intent_id: str,
        stream: str,
        subject_key: str,
        body: dict[str, Any],
        payloads: list[dict[str, Any]],
        created_at: str,
    ) -> None:
        """Durably record an effect **before** it is applied. `synchronous=FULL` makes it an fsync."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO intents (intent_id, stream, subject_key, body_json, payloads_json, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    intent_id,
                    stream,
                    subject_key,
                    json.dumps(body),
                    json.dumps(payloads),
                    created_at,
                ),
            )

    def resolve_intent(self, intent_id: str, at: str) -> None:
        """Close a write-ahead record: its effect's envelope is now in the chain."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE intents SET resolved_at = ? WHERE intent_id = ?", (at, intent_id)
            )

    def open_intents(
        self, stream: str, subject_key: str
    ) -> list[tuple[str, dict[str, Any], list[dict[str, Any]]]]:
        """Write-ahead records whose call never chained an envelope, oldest first."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT intent_id, body_json, payloads_json FROM intents WHERE resolved_at IS NULL "
                "AND stream = ? AND subject_key = ? ORDER BY created_at, rowid",
                (stream, subject_key),
            ).fetchall()
        return [
            (row["intent_id"], json.loads(row["body_json"]), json.loads(row["payloads_json"]))
            for row in rows
        ]

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
        """Decided requests carrying an **answered** catalog seed. The seed is about *future* calls
        of the tool, so it is applied when the decision exists, not when the original call happens
        to be retried.

        The decision is required in the query, not merely hoped for. Since a first call parks its
        seed request alongside the call, `seed_json` exists from the moment of parking and carries
        a null decision until an approver answers it — a row selected on the column's presence
        alone would be a request nobody has answered, offered to `_seed_catalog` as authority.
        """
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM parked WHERE seed_json IS NOT NULL "
                "AND json_extract(seed_json, '$.decision') IS NOT NULL ORDER BY created_at"
            ).fetchall()
        return [Parked(row) for row in rows]

    def park_seed(self, request_hash: str, seed_request: dict[str, Any], catalog_class: str) -> None:
        """Record the catalog-seed request parked beside a first call, before anyone answers it.

        §10 §4.3 makes classifying the tool a second decision with its own signature. Until
        2026-08-02 that second request existed only inside the gateway's own `decide --classify`,
        so an operator approving through the console — the path `deploy/README.md` teaches — never
        produced one, the catalog stayed empty forever, and every call of the tool parked again.
        Parking the seed request here is what lets the same approval command answer both.
        """
        with self._connect() as connection:
            connection.execute(
                "UPDATE parked SET seed_json = ?, catalog_class = ? WHERE request_hash = ?",
                (json.dumps({"request": seed_request, "decision": None}), catalog_class, request_hash),
            )

    def attach_seed_decision(self, request_hash: str, decision: dict[str, Any]) -> None:
        """Fill in the answer to a parked seed request, leaving the request it commits to intact."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT seed_json FROM parked WHERE request_hash = ?", (request_hash,)
            ).fetchone()
            if row is None or not row["seed_json"]:
                return
            seed = json.loads(row["seed_json"])
            seed["decision"] = decision
            connection.execute(
                "UPDATE parked SET seed_json = ? WHERE request_hash = ?",
                (json.dumps(seed), request_hash),
            )

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

    def record_gate_decision(self, request_hash: str, decision: dict[str, Any]) -> None:
        """Store the answer to the *call*, touching neither the catalog class nor the seed.

        `record_decision` below writes all three, which is right for `decide --classify` where one
        invocation produces every part. It is wrong for a decision collected from the kernel: that
        path passed `None` for the other two and so erased the seed request parked beside the call.
        """
        with self._connect() as connection:
            connection.execute(
                "UPDATE parked SET decision_json = ? WHERE request_hash = ?",
                (json.dumps(decision), request_hash),
            )

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

    # -- revocation cache -------------------------------------------------------------------

    def cache_revocations(
        self, epoch: str, documents: list[dict[str, Any]], verified_at: str
    ) -> None:
        """Persist a **verified** revocation set. It must be enforced while offline (maxim 5)."""
        with self._connect() as connection:
            connection.execute("UPDATE revocation_cache SET is_current = 0")
            connection.execute(
                "INSERT OR REPLACE INTO revocation_cache (epoch, documents_json, verified_at, "
                "is_current) VALUES (?, ?, ?, 1)",
                (epoch, json.dumps(documents), verified_at),
            )

    def cached_revocations(self) -> tuple[str, list[dict[str, Any]], str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT epoch, documents_json, verified_at FROM revocation_cache WHERE is_current = 1"
            ).fetchone()
        if row is None:
            return None
        return row["epoch"], json.loads(row["documents_json"]), row["verified_at"]

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

"""SQLite persistence for sessions, requests, events and captured submissions.

A single connection guarded by a lock: write volume of a honeypot is modest and
this keeps behaviour identical on Windows and Linux. WAL mode lets the admin UI
read while the decoy writes.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from aitarpit.events import Event, Severity

SCHEMA_VERSION = 1

# Deletable element type -> (table, timestamp column). Fixed, never user-supplied,
# so interpolating the table/column names into SQL is safe. Order defines display order.
DELETABLE_ELEMENTS: dict[str, tuple[str, str]] = {
    "sessions": ("sessions", "last_seen"),
    "requests": ("requests", "ts"),
    "events": ("events", "ts"),
    "submissions": ("submissions", "ts"),
    "honeytokens": ("honeytokens", "created"),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    src_ip          TEXT NOT NULL,
    user_agent      TEXT NOT NULL DEFAULT '',
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    requests        INTEGER NOT NULL DEFAULT 0,
    bytes_out       INTEGER NOT NULL DEFAULT 0,
    held_seconds    REAL NOT NULL DEFAULT 0,
    classification  TEXT NOT NULL DEFAULT 'unknown',
    score           REAL NOT NULL DEFAULT 0,
    techniques      TEXT NOT NULL DEFAULT '[]',
    data            TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    ts           REAL NOT NULL,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    query        TEXT NOT NULL DEFAULT '',
    status       INTEGER NOT NULL,
    bytes_out    INTEGER NOT NULL DEFAULT 0,
    duration_ms  REAL NOT NULL DEFAULT 0,
    technique    TEXT,
    headers      TEXT,
    body         TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id, ts);

CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    type        TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    session_id  TEXT,
    technique   TEXT,
    src_ip      TEXT,
    message     TEXT NOT NULL,
    data        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, ts);

CREATE TABLE IF NOT EXISTS submissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    session_id  TEXT,
    technique   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    content     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS honeytokens (
    token       TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    session_id  TEXT,
    technique   TEXT,
    created     REAL NOT NULL,
    used_count  INTEGER NOT NULL DEFAULT 0,
    last_used   REAL
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
            )

    # ------------------------------------------------------------------ helpers
    def _exec(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def _all(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ sessions
    def upsert_session(self, s: dict) -> None:
        row = dict(s)
        row["techniques"] = json.dumps(sorted(row.get("techniques") or []))
        row["data"] = json.dumps(row.get("data") or {})
        with self._lock:
            self._conn.execute(
                """INSERT INTO sessions(id, src_ip, user_agent, first_seen, last_seen, requests, bytes_out,
                                        held_seconds, classification, score, techniques, data)
                   VALUES (:id, :src_ip, :user_agent, :first_seen, :last_seen, :requests, :bytes_out,
                           :held_seconds, :classification, :score, :techniques, :data)
                   ON CONFLICT(id) DO UPDATE SET
                       last_seen=excluded.last_seen, requests=excluded.requests, bytes_out=excluded.bytes_out,
                       held_seconds=excluded.held_seconds, classification=excluded.classification,
                       score=excluded.score, techniques=excluded.techniques, data=excluded.data""",
                row,
            )

    @staticmethod
    def _decode_session(row: dict) -> dict:
        row["techniques"] = json.loads(row.get("techniques") or "[]")
        row["data"] = json.loads(row.get("data") or "{}")
        return row

    def get_session(self, session_id: str) -> dict | None:
        rows = self._all("SELECT * FROM sessions WHERE id = ?", [session_id])
        return self._decode_session(rows[0]) if rows else None

    def list_sessions(self, since: float | None = None, limit: int = 200) -> list[dict]:
        if since is None:
            rows = self._all("SELECT * FROM sessions ORDER BY last_seen DESC LIMIT ?", [limit])
        else:
            rows = self._all("SELECT * FROM sessions WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?", [since, limit])
        return [self._decode_session(r) for r in rows]

    # ------------------------------------------------------------------ requests
    def add_request(self, r: dict) -> None:
        row = {
            "session_id": r["session_id"],
            "ts": r.get("ts", time.time()),
            "method": r["method"],
            "path": r["path"],
            "query": r.get("query", ""),
            "status": r["status"],
            "bytes_out": r.get("bytes_out", 0),
            "duration_ms": r.get("duration_ms", 0.0),
            "technique": r.get("technique"),
            "headers": json.dumps(r["headers"]) if r.get("headers") is not None else None,
            "body": r.get("body"),
        }
        with self._lock:
            self._conn.execute(
                """INSERT INTO requests(session_id, ts, method, path, query, status, bytes_out, duration_ms,
                                        technique, headers, body)
                   VALUES (:session_id, :ts, :method, :path, :query, :status, :bytes_out, :duration_ms,
                           :technique, :headers, :body)""",
                row,
            )

    def list_requests(self, session_id: str, limit: int = 1000) -> list[dict]:
        rows = self._all("SELECT * FROM requests WHERE session_id = ? ORDER BY ts ASC LIMIT ?", [session_id, limit])
        for r in rows:
            r["headers"] = json.loads(r["headers"]) if r.get("headers") else None
        return rows

    # ------------------------------------------------------------------ events
    def add_event(self, e: Event) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO events(id, ts, type, severity, session_id, technique, src_ip, message, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (e.id, e.ts, e.type, int(e.severity), e.session_id, e.technique, e.src_ip, e.message,
                 json.dumps(e.data, default=str)),
            )

    def list_events(
        self,
        since: float | None = None,
        session_id: str | None = None,
        min_severity: Severity = Severity.INFO,
        limit: int = 500,
    ) -> list[dict]:
        clauses, params = ["severity >= ?"], [int(min_severity)]
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        params.append(limit)
        rows = self._all(f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?", params)
        for r in rows:
            r["data"] = json.loads(r["data"] or "{}")
            r["severity"] = Severity(r["severity"]).label
        return rows

    # ------------------------------------------------------------------ submissions
    def add_submission(self, technique: str, kind: str, content: str, session_id: str | None = None) -> None:
        self._exec(
            "INSERT INTO submissions(ts, session_id, technique, kind, content) VALUES (?, ?, ?, ?, ?)",
            [time.time(), session_id, technique, kind, content],
        )

    def list_submissions(self, session_id: str | None = None, limit: int = 200) -> list[dict]:
        if session_id:
            return self._all("SELECT * FROM submissions WHERE session_id = ? ORDER BY ts DESC LIMIT ?", [session_id, limit])
        return self._all("SELECT * FROM submissions ORDER BY ts DESC LIMIT ?", [limit])

    # ------------------------------------------------------------------ honeytokens
    def add_honeytoken(self, token: str, kind: str, session_id: str | None, technique: str | None) -> None:
        self._exec(
            "INSERT OR IGNORE INTO honeytokens(token, kind, session_id, technique, created) VALUES (?, ?, ?, ?, ?)",
            [token, kind, session_id, technique, time.time()],
        )

    def get_honeytoken(self, token: str) -> dict | None:
        """Look up a honeytoken without counting a use.

        Args:
            token: The token presented.

        Returns:
            The honeytoken row, or None when it was never issued.
        """
        rows = self._all("SELECT * FROM honeytokens WHERE token = ?", [token])
        return rows[0] if rows else None

    def use_honeytoken(self, token: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM honeytokens WHERE token = ?", (token,)).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE honeytokens SET used_count = used_count + 1, last_used = ? WHERE token = ?", (time.time(), token)
            )
            return dict(row)

    # ------------------------------------------------------------------ maintenance
    def prune(self, max_age_days: float) -> dict[str, int]:
        """Delete data older than a retention window.

        Removes events by their own timestamp and sessions by ``last_seen``,
        together with the requests and submissions of the removed sessions.

        Args:
            max_age_days: Retention window in days; rows older than this are deleted.

        Returns:
            The number of rows deleted, keyed by table (events, sessions, requests, submissions).
        """
        cutoff = time.time() - max_age_days * 86400.0
        old_sessions = "SELECT id FROM sessions WHERE last_seen < ?"
        with self._lock:
            c = self._conn
            requests = c.execute(f"DELETE FROM requests WHERE session_id IN ({old_sessions})", (cutoff,)).rowcount
            submissions = c.execute(f"DELETE FROM submissions WHERE session_id IN ({old_sessions})", (cutoff,)).rowcount
            sessions = c.execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,)).rowcount
            events = c.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
        return {"events": events, "sessions": sessions, "requests": requests, "submissions": submissions}

    def _size_bytes(self) -> int:
        """On-disk size of the database, including the WAL and shared-memory files.

        Returns:
            Total size in bytes, or 0 for an in-memory database.
        """
        total = 0
        if self.path != ":memory:":
            base = Path(self.path)
            for suffix in ("", "-wal", "-shm"):
                sidecar = base.with_name(base.name + suffix)
                if sidecar.exists():
                    total += sidecar.stat().st_size
        return total

    def db_metrics(self) -> dict:
        """Database size and per-element row counts for the admin database panel.

        Returns:
            A dict with ``size_bytes``, ``schema_version``, ``path`` and ``counts``
            (row count keyed by element type, in :data:`DELETABLE_ELEMENTS` order).
        """
        with self._lock:
            counts = {
                name: self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for name, (table, _col) in DELETABLE_ELEMENTS.items()
            }
        return {
            "size_bytes": self._size_bytes(),
            "schema_version": SCHEMA_VERSION,
            "path": self.path,
            "counts": counts,
        }

    def reset(self) -> dict[str, int]:
        """Delete every stored record, keeping the schema and meta table.

        Returns:
            The number of rows deleted, keyed by element type.
        """
        with self._lock:
            c = self._conn
            deleted = {name: c.execute(f"DELETE FROM {table}").rowcount
                       for name, (table, _col) in DELETABLE_ELEMENTS.items()}
        return deleted

    def delete_before(self, element: str, cutoff: float) -> dict[str, int]:
        """Delete stored elements of one type older than a cutoff timestamp.

        Deleting ``sessions`` cascades to the requests and submissions of the
        removed sessions so no orphan rows remain.

        Args:
            element: The element type, a key of :data:`DELETABLE_ELEMENTS`.
            cutoff: Epoch seconds; rows whose timestamp column is strictly less
                than this are deleted.

        Returns:
            The number of rows deleted, keyed by table.

        Raises:
            ValueError: When ``element`` is not a known element type.
        """
        if element not in DELETABLE_ELEMENTS:
            raise ValueError(f"Unknown element type '{element}'")
        table, col = DELETABLE_ELEMENTS[element]
        with self._lock:
            c = self._conn
            if element == "sessions":
                old = "SELECT id FROM sessions WHERE last_seen < ?"
                requests = c.execute(f"DELETE FROM requests WHERE session_id IN ({old})", (cutoff,)).rowcount
                submissions = c.execute(f"DELETE FROM submissions WHERE session_id IN ({old})", (cutoff,)).rowcount
                sessions = c.execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,)).rowcount
                deleted = {"sessions": sessions, "requests": requests, "submissions": submissions}
            else:
                n = c.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)).rowcount
                deleted = {element: n}
        return deleted

    # ------------------------------------------------------------------ stats
    def stats(self, since: float | None = None) -> dict:
        since = since or 0.0
        with self._lock:
            c = self._conn
            sessions = c.execute("SELECT COUNT(*) FROM sessions WHERE last_seen >= ?", (since,)).fetchone()[0]
            reqs, bytes_out = c.execute(
                "SELECT COUNT(*), COALESCE(SUM(bytes_out), 0) FROM requests WHERE ts >= ?", (since,)
            ).fetchone()
            held = c.execute("SELECT COALESCE(SUM(held_seconds), 0) FROM sessions WHERE last_seen >= ?", (since,)).fetchone()[0]
            by_sev = {
                Severity(s).label: n
                for s, n in c.execute("SELECT severity, COUNT(*) FROM events WHERE ts >= ? GROUP BY severity", (since,))
            }
            by_tech = {
                t: n
                for t, n in c.execute(
                    "SELECT technique, COUNT(*) FROM events WHERE ts >= ? AND technique IS NOT NULL GROUP BY technique",
                    (since,),
                )
            }
        return {
            "sessions": sessions,
            "requests": reqs,
            "bytes_out": bytes_out,
            "held_seconds": held,
            "events_by_severity": by_sev,
            "events_by_technique": by_tech,
        }

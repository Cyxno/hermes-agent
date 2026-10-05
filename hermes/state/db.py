"""SQLite persistence (WAL) with versioned migrations.

One database file per Hermes instance; backup = file copy. Migrations run at
startup: detect schema version, back up the file when migrating, apply, validate.
On failure Hermes stops safely rather than continuing on corrupt state (spec §46).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import time
from typing import Any

from ..log import info, warning

MIGRATIONS: list[str] = [
    # v1 — initial schema
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        entity TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        state TEXT NOT NULL,
        first_seen REAL NOT NULL,
        last_seen REAL,
        confirmed_at REAL,
        resolved_at REAL,
        notification_sent INTEGER NOT NULL DEFAULT 0,
        occurrences INTEGER NOT NULL DEFAULT 1,
        flap_count INTEGER NOT NULL DEFAULT 0,
        last_notified_at REAL,
        last_notified_severity TEXT,
        suppressed INTEGER NOT NULL DEFAULT 0,
        root_incident TEXT,
        evidence TEXT,
        ai_summary TEXT,
        updated_at REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state);
    CREATE TABLE IF NOT EXISTS incident_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        ts REAL NOT NULL,
        from_state TEXT,
        to_state TEXT,
        reason TEXT,
        severity TEXT,
        meta TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);
    CREATE TABLE IF NOT EXISTS signals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        category TEXT NOT NULL,
        entity TEXT NOT NULL,
        severity TEXT NOT NULL,
        value REAL,
        source TEXT,
        evidence TEXT,
        incident_id TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts);
    CREATE TABLE IF NOT EXISTS metric_state (
        metric TEXT PRIMARY KEY,
        value REAL,
        band TEXT,
        breached_since REAL,
        pending_since REAL,
        good_samples INTEGER NOT NULL DEFAULT 0,
        updated_at REAL
    );
    CREATE TABLE IF NOT EXISTS cursors (name TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value REAL NOT NULL DEFAULT 0, updated_at REAL);
    CREATE TABLE IF NOT EXISTS transients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        fingerprint TEXT NOT NULL,
        category TEXT NOT NULL,
        entity TEXT NOT NULL,
        severity TEXT NOT NULL,
        meta TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_transients_fp ON transients(fingerprint, ts);
    CREATE TABLE IF NOT EXISTS desired_state (
        entity TEXT PRIMARY KEY,
        state TEXT NOT NULL,
        origin TEXT,
        updated_at REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS entity_meta (
        entity TEXT PRIMARY KEY,
        compose_project TEXT,
        image TEXT,
        management_type TEXT,
        updated_at REAL
    );
    CREATE TABLE IF NOT EXISTS action_audit (
        id TEXT PRIMARY KEY,
        ts REAL NOT NULL,
        initiator TEXT NOT NULL,
        incident_id TEXT,
        capability TEXT NOT NULL,
        target TEXT NOT NULL,
        args TEXT,
        reason TEXT,
        policy_decision TEXT NOT NULL,
        ai_involved INTEGER NOT NULL DEFAULT 0,
        ai_model TEXT,
        preconditions TEXT,
        result TEXT,
        verification TEXT,
        mode TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        action_class TEXT NOT NULL,
        target TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        chat_id TEXT
    );
    CREATE TABLE IF NOT EXISTS baselines (
        metric TEXT PRIMARY KEY,
        mean REAL, stdev REAL, p95 REAL, samples INTEGER,
        updated_at REAL
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        incident_id TEXT,
        severity TEXT,
        kind TEXT,
        message TEXT,
        message_id TEXT,
        delivered INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_retry REAL,
        meta TEXT
    );
    CREATE TABLE IF NOT EXISTS ai_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        incident_id TEXT,
        tier INTEGER,
        model TEXT,
        purpose TEXT,
        prompt_chars INTEGER,
        response_chars INTEGER,
        confidence REAL,
        result TEXT,
        meta TEXT
    );
    CREATE TABLE IF NOT EXISTS remediations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        incident_id TEXT,
        runbook TEXT,
        outcome TEXT,
        detail TEXT
    );
    """,
]


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA synchronous=NORMAL")

    # -- migrations -------------------------------------------------------
    def schema_version(self) -> int:
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchone()
        if not row:
            return 0
        ver = self.conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        return int(ver["v"] or 0)

    def migrate(self) -> None:
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at REAL)"
        )
        current = self.schema_version()
        target = len(MIGRATIONS)
        if current >= target:
            return
        if current > 0:
            backup = f"{self.path}.pre-migrate-{int(time.time())}"
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            shutil.copy2(self.path, backup)
            warning("db", "database backed up before migration", backup=backup)
        for version in range(current, target):
            sql = MIGRATIONS[version]
            self.conn.executescript(sql)
            self.conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version + 1, time.time()),
            )
            self.conn.commit()
            info("db", "migration applied", version=version + 1)

    # -- helpers ----------------------------------------------------------
    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        return cur

    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, params))

    def one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def get_cursor(self, name: str) -> str | None:
        row = self.one("SELECT value FROM cursors WHERE name=?", (name,))
        return row["value"] if row else None

    def set_cursor(self, name: str, value: str) -> None:
        self.execute(
            "INSERT INTO cursors(name, value) VALUES(?,?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            (name, value),
        )

    def get_counter(self, name: str) -> float:
        row = self.one("SELECT value FROM counters WHERE name=?", (name,))
        return float(row["value"]) if row else 0.0

    def bump_counter(self, name: str, delta: float = 1) -> float:
        self.execute(
            "INSERT INTO counters(name, value, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET value=value+excluded.value, updated_at=excluded.updated_at",
            (name, delta, time.time()),
        )
        return self.get_counter(name)

    def close(self) -> None:
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:  # pragma: no cover
            pass
        self.conn.close()


def json_dumps(data: Any) -> str:
    import json

    return json.dumps(data, separators=(",", ":"), default=str)


def json_loads(raw: str | None, default: Any = None) -> Any:
    import json

    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default

"""SQLite によるイベント・確認履歴の保存。"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    TEXT NOT NULL,
    msg_id       TEXT NOT NULL,
    account_id   TEXT,
    provider     TEXT NOT NULL,
    kind         TEXT NOT NULL,
    device       TEXT,
    device_id    TEXT,
    location     TEXT,
    occurred_at  TEXT NOT NULL,
    subject      TEXT,
    severity     TEXT NOT NULL,
    note         TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    UNIQUE(source_id, msg_id)
);
CREATE INDEX IF NOT EXISTS idx_events_account ON events(account_id, occurred_at);
CREATE TABLE IF NOT EXISTS reviews (
    account_id  TEXT NOT NULL,
    reviewed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_status (
    source_id   TEXT PRIMARY KEY,
    last_ok     TEXT,
    last_error  TEXT,
    last_try    TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur

    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    # --- events ---
    def has_message(self, source_id: str, msg_id: str) -> bool:
        return bool(self._all(
            "SELECT 1 FROM events WHERE source_id=? AND msg_id=?", (source_id, msg_id)))

    def add_event(self, **e) -> int | None:
        """追加できたら id、既に存在すれば None。"""
        cols = ["source_id", "msg_id", "account_id", "provider", "kind", "device", "device_id",
                "location", "occurred_at", "subject", "severity", "note"]
        vals = tuple(e.get(c) for c in cols) + (now_iso(),)
        cur = self._exec(
            f"INSERT OR IGNORE INTO events ({','.join(cols)}, created_at) "
            f"VALUES ({','.join('?' * (len(cols) + 1))})", vals)
        return cur.lastrowid if cur.rowcount else None

    def events(self, account_id: str | None = None, limit: int = 200) -> list[dict]:
        if account_id:
            return self._all("SELECT * FROM events WHERE account_id=? "
                             "ORDER BY occurred_at DESC LIMIT ?", (account_id, limit))
        return self._all("SELECT * FROM events ORDER BY occurred_at DESC LIMIT ?", (limit,))

    def open_alerts(self) -> list[dict]:
        return self._all("SELECT * FROM events WHERE acknowledged=0 AND severity!='info' "
                         "ORDER BY occurred_at DESC")

    def acknowledge(self, event_id: int) -> bool:
        return self._exec("UPDATE events SET acknowledged=1 WHERE id=?", (event_id,)).rowcount > 0

    # --- reviews（各社の画面で手動確認した記録） ---
    def mark_reviewed(self, account_id: str) -> str:
        ts = now_iso()
        self._exec("INSERT INTO reviews VALUES (?, ?)", (account_id, ts))
        return ts

    def last_reviews(self) -> dict[str, str]:
        rows = self._all("SELECT account_id, MAX(reviewed_at) AS t FROM reviews GROUP BY account_id")
        return {r["account_id"]: r["t"] for r in rows}

    # --- source status ---
    def set_source_status(self, source_id: str, error: str | None) -> None:
        ts = now_iso()
        if error:
            self._exec("INSERT INTO source_status(source_id,last_error,last_try) VALUES(?,?,?) "
                       "ON CONFLICT(source_id) DO UPDATE SET last_error=excluded.last_error, "
                       "last_try=excluded.last_try", (source_id, error, ts))
        else:
            self._exec("INSERT INTO source_status(source_id,last_ok,last_error,last_try) "
                       "VALUES(?,?,NULL,?) ON CONFLICT(source_id) DO UPDATE SET "
                       "last_ok=excluded.last_ok, last_error=NULL, last_try=excluded.last_try",
                       (source_id, ts, ts))

    def source_statuses(self) -> dict[str, dict]:
        return {r["source_id"]: r for r in self._all("SELECT * FROM source_status")}

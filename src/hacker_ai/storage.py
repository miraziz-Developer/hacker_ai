from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    allowed INTEGER NOT NULL,
    details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'needs-review',
    target TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""


class Storage:
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.executescript(SCHEMA)

    def audit(
        self,
        action: str,
        *,
        target: str | None = None,
        allowed: bool,
        details: dict[str, Any] | None = None,
    ) -> int:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            cursor = connection.execute(
                "INSERT INTO audit_log(created_at, action, target, allowed, details) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    action,
                    target,
                    int(allowed),
                    json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
                ),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return an audit row ID")
            return int(cursor.lastrowid)

    def audit_entries(self, limit: int = 50) -> list[dict[str, Any]]:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def save_finding(self, target: str, payload: dict[str, Any]) -> int:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            cursor = connection.execute(
                "INSERT INTO findings(created_at, target, payload) VALUES (?, ?, ?)",
                (datetime.now(UTC).isoformat(), target, json.dumps(payload, ensure_ascii=False)),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return a finding row ID")
            return int(cursor.lastrowid)

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

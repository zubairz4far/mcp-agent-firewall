from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.models import EvaluationResult
from app.policy import canonical_payload


class AuditStore:
    """Privacy-minimized audit log: hashes request bodies instead of persisting raw arguments."""

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    client_name TEXT,
                    method TEXT NOT NULL,
                    tool_name TEXT,
                    decision TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    signals_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    traceparent TEXT
                )
                """
            )

    def append(
        self,
        *,
        body: dict[str, Any],
        result: EvaluationResult,
        client_name: str | None,
        traceparent: str | None,
    ) -> None:
        digest = hashlib.sha256(canonical_payload(body)).hexdigest()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    created_at, client_name, method, tool_name, decision, risk,
                    reasons_json, signals_json, payload_sha256, traceparent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(UTC).isoformat(),
                    client_name,
                    result.method,
                    result.tool_name,
                    result.decision.value,
                    result.risk.value,
                    json.dumps(result.reasons),
                    json.dumps(result.signals),
                    digest,
                    traceparent,
                ),
            )

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 200))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

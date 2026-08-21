from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.approval import ApprovalClaims
from app.models import EvaluationResult
from app.policy import canonical_payload


class AuditStore:
    """Privacy-minimized audit and approval-consumption store."""

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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_receipts (
                    jti TEXT PRIMARY KEY,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    protocol_version TEXT NOT NULL,
                    method TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    consumed_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_expires_at "
                "ON approval_receipts(expires_at)"
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

    def register_approval(self, claims: ApprovalClaims) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approval_receipts (
                    jti, issued_at, expires_at, request_sha256, protocol_version,
                    method, tool_name, policy_version, approver, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    claims.jti,
                    claims.issued_at,
                    claims.expires_at,
                    claims.request_sha256,
                    claims.protocol_version,
                    claims.method,
                    claims.tool_name,
                    claims.policy_version,
                    claims.approver,
                ),
            )

    def consume_approval(self, claims: ApprovalClaims, *, now: int | None = None) -> bool:
        current_time = int(time.time()) if now is None else int(now)
        consumed_at = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE approval_receipts
                SET consumed_at = ?
                WHERE jti = ?
                  AND request_sha256 = ?
                  AND protocol_version = ?
                  AND method = ?
                  AND tool_name = ?
                  AND policy_version = ?
                  AND consumed_at IS NULL
                  AND expires_at > ?
                """,
                (
                    consumed_at,
                    claims.jti,
                    claims.request_sha256,
                    claims.protocol_version,
                    claims.method,
                    claims.tool_name,
                    claims.policy_version,
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 200))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

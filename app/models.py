from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class McpEnvelope(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class EvaluationInput(BaseModel):
    protocol_version: str = "2026-07-28"
    mcp_method: str
    mcp_name: str | None = None
    body: McpEnvelope


class EvaluationResult(BaseModel):
    decision: Decision
    risk: RiskLevel
    reasons: list[str]
    signals: list[str] = Field(default_factory=list)
    tool_name: str | None = None
    method: str
    requires_human_approval: bool = False
    policy_version: str

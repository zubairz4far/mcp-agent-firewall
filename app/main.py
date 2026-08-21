from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from app.approval import (
    ApprovalError,
    ApprovalIssueRequest,
    ApprovalIssueResponse,
    ApprovalReceiptService,
    response_from_issued,
)
from app.audit import AuditStore
from app.models import Decision, EvaluationInput, McpEnvelope
from app.policy import PolicyConfig, PolicyEngine
from app.rate_limit import SlidingWindowRateLimiter

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = os.getenv("POLICY_PATH", str(ROOT / "config" / "policy.example.yaml"))
AUDIT_DB_PATH = os.getenv("AUDIT_DB_PATH", str(ROOT / "data" / "audit.db"))
UPSTREAM_MCP_URL = os.getenv("UPSTREAM_MCP_URL", "").strip()
APPROVAL_SIGNING_KEY = os.getenv("APPROVAL_SIGNING_KEY", "")
APPROVAL_ISSUER_TOKEN = os.getenv("APPROVAL_ISSUER_TOKEN", "")
APPROVAL_DEFAULT_TTL_SECONDS = int(os.getenv("APPROVAL_DEFAULT_TTL_SECONDS", "300"))
APPROVAL_MAX_TTL_SECONDS = int(os.getenv("APPROVAL_MAX_TTL_SECONDS", "900"))
AUDIT_READ_TOKEN = os.getenv("AUDIT_READ_TOKEN", "")
UPSTREAM_BEARER_TOKEN = os.getenv("UPSTREAM_BEARER_TOKEN", "")
MAX_REQUESTS_PER_MINUTE = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "120"))
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "65536"))

policy = PolicyConfig.load(POLICY_PATH)
engine = PolicyEngine(policy)
audit = AuditStore(AUDIT_DB_PATH)
rate_limiter = SlidingWindowRateLimiter(MAX_REQUESTS_PER_MINUTE)
approval_receipts = ApprovalReceiptService(
    APPROVAL_SIGNING_KEY,
    default_ttl_seconds=APPROVAL_DEFAULT_TTL_SECONDS,
    max_ttl_seconds=APPROVAL_MAX_TTL_SECONDS,
)

app = FastAPI(title="MCP Agent Firewall", version="0.2.0")


def _client_name(body: dict[str, Any]) -> str | None:
    meta = body.get("params", {}).get("_meta", {}) if isinstance(body.get("params"), dict) else {}
    info = meta.get("io.modelcontextprotocol/clientInfo", {}) if isinstance(meta, dict) else {}
    name = info.get("name") if isinstance(info, dict) else None
    return str(name)[:120] if name else None


def _traceparent(body: dict[str, Any]) -> str | None:
    params = body.get("params", {})
    meta = params.get("_meta", {}) if isinstance(params, dict) else {}
    if isinstance(meta, dict):
        value = meta.get("traceparent")
        return str(value)[:256] if value else None
    return None


def _evaluation_input(
    body: dict[str, Any],
    protocol_version: str,
    mcp_method: str,
    mcp_name: str | None,
) -> EvaluationInput:
    envelope = McpEnvelope.model_validate(body)
    return EvaluationInput(
        protocol_version=protocol_version,
        mcp_method=mcp_method,
        mcp_name=mcp_name,
        body=envelope,
    )


def _approval_error_response(
    body: dict[str, Any],
    result: Any,
    approval_error: str,
) -> JSONResponse:
    data = result.model_dump(mode="json")
    data["approval_error"] = approval_error
    return JSONResponse(
        status_code=428,
        content={
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "error": {
                "code": -32041,
                "message": "Valid human approval receipt required",
                "data": data,
            },
        },
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "policy_version": policy.version,
        "approval_mode": "signed_receipts" if approval_receipts.configured else "disabled",
    }


@app.post("/v1/evaluate")
def evaluate(payload: EvaluationInput) -> dict[str, Any]:
    return engine.evaluate(payload).model_dump(mode="json")


@app.post("/v1/approvals/issue", response_model=ApprovalIssueResponse)
def issue_approval(
    payload: ApprovalIssueRequest,
    operator_token: str | None = Header(default=None, alias="X-Operator-Token"),
) -> ApprovalIssueResponse:
    if (
        not APPROVAL_ISSUER_TOKEN
        or not operator_token
        or not secrets.compare_digest(operator_token, APPROVAL_ISSUER_TOKEN)
    ):
        raise HTTPException(status_code=403, detail="approval_issuer_access_denied")

    result = engine.evaluate(payload.request)
    if result.decision != Decision.APPROVAL_REQUIRED:
        raise HTTPException(status_code=409, detail="request_does_not_require_human_approval")

    try:
        receipt, claims = approval_receipts.issue(
            payload.request,
            policy_version=policy.version,
            approver=payload.approver,
            ttl_seconds=payload.ttl_seconds,
        )
    except ApprovalError as exc:
        status_code = 503 if exc.code == "approval_signing_not_configured" else 400
        raise HTTPException(status_code=status_code, detail=exc.code) from exc

    audit.register_approval(claims)
    return response_from_issued(receipt, claims)


@app.get("/v1/audit")
def recent_audit(
    limit: int = 50,
    operator_token: str | None = Header(default=None, alias="X-Operator-Token"),
) -> dict[str, Any]:
    if not AUDIT_READ_TOKEN or operator_token != AUDIT_READ_TOKEN:
        raise HTTPException(status_code=403, detail="audit_access_denied")
    return {"events": audit.recent(limit)}


@app.post("/mcp")
async def proxy_mcp(
    request: Request,
    mcp_protocol_version: str = Header(alias="MCP-Protocol-Version"),
    mcp_method: str = Header(alias="Mcp-Method"),
    mcp_name: str | None = Header(default=None, alias="Mcp-Name"),
    human_approval: str | None = Header(default=None, alias="X-Human-Approval"),
) -> Response:
    client_key = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_key):
        raise HTTPException(status_code=429, detail="gateway_rate_limit_exceeded")

    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="request_body_too_large")

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid_json") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="json_rpc_body_must_be_object")

    try:
        evaluation_input = _evaluation_input(
            body,
            protocol_version=mcp_protocol_version,
            mcp_method=mcp_method,
            mcp_name=mcp_name,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid_mcp_envelope") from exc

    result = engine.evaluate(evaluation_input)
    client_name = _client_name(body)
    traceparent = _traceparent(body)
    audit.append(body=body, result=result, client_name=client_name, traceparent=traceparent)

    if result.decision == Decision.DENY:
        return JSONResponse(
            status_code=403,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32040,
                    "message": "Blocked by MCP Agent Firewall",
                    "data": result.model_dump(mode="json"),
                },
            },
        )

    approval_claims = None
    if result.decision == Decision.APPROVAL_REQUIRED:
        if not human_approval:
            return _approval_error_response(body, result, "approval_receipt_required")
        try:
            approval_claims = approval_receipts.verify(
                human_approval,
                evaluation_input,
                policy_version=policy.version,
            )
        except ApprovalError as exc:
            return _approval_error_response(body, result, exc.code)

    if not UPSTREAM_MCP_URL:
        return JSONResponse(
            status_code=503,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32042,
                    "message": "Policy allowed the call but no upstream MCP server is configured",
                    "data": result.model_dump(mode="json"),
                },
            },
        )

    if approval_claims is not None and not audit.consume_approval(approval_claims):
        return JSONResponse(
            status_code=409,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32043,
                    "message": "Approval receipt is unknown, expired, or already consumed",
                },
            },
        )

    forward_headers = {
        "MCP-Protocol-Version": mcp_protocol_version,
        "Mcp-Method": mcp_method,
        "content-type": "application/json",
    }
    if mcp_name:
        forward_headers["Mcp-Name"] = mcp_name
    if UPSTREAM_BEARER_TOKEN:
        forward_headers["authorization"] = f"Bearer {UPSTREAM_BEARER_TOKEN}"

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        upstream = await client.post(UPSTREAM_MCP_URL, content=raw, headers=forward_headers)
    response_headers = {}
    if content_type := upstream.headers.get("content-type"):
        response_headers["content-type"] = content_type
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
    )

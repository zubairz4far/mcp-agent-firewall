from __future__ import annotations

import os
import secrets
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from opentelemetry.trace import SpanKind

from app.approval import (
    ApprovalError,
    ApprovalIssueRequest,
    ApprovalIssueResponse,
    ApprovalReceiptService,
    approval_request_hash,
    response_from_issued,
)
from app.audit import AuditStore
from app.models import Decision, EvaluationInput, McpEnvelope
from app.observability import configure_observability, status_family
from app.output_containment import OutputAction, OutputContainment
from app.policy import PolicyConfig, PolicyEngine
from app.rate_limit import SlidingWindowRateLimiter
from app.tool_catalog import (
    ToolCatalogError,
    TrustedToolCatalog,
    decode_mcp_header_value,
)

SERVICE_VERSION = "0.5.0"
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
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "262144"))

DEFAULT_CATALOG_PATH = ROOT / "config" / "trusted_tools.example.json"
DEFAULT_CATALOG_PIN_PATH = ROOT / "config" / "trusted_tools.example.sha256"
TRUSTED_TOOL_CATALOG_PATH = os.getenv("TRUSTED_TOOL_CATALOG_PATH", str(DEFAULT_CATALOG_PATH))
configured_catalog_pin = os.getenv("TRUSTED_TOOL_CATALOG_SHA256", "").strip()
if configured_catalog_pin:
    TRUSTED_TOOL_CATALOG_SHA256 = configured_catalog_pin
elif Path(TRUSTED_TOOL_CATALOG_PATH).resolve() == DEFAULT_CATALOG_PATH.resolve():
    TRUSTED_TOOL_CATALOG_SHA256 = DEFAULT_CATALOG_PIN_PATH.read_text(encoding="utf-8").strip()
else:
    TRUSTED_TOOL_CATALOG_SHA256 = ""

policy = PolicyConfig.load(POLICY_PATH)
engine = PolicyEngine(policy)
audit = AuditStore(AUDIT_DB_PATH)
rate_limiter = SlidingWindowRateLimiter(MAX_REQUESTS_PER_MINUTE)
approval_receipts = ApprovalReceiptService(
    APPROVAL_SIGNING_KEY,
    default_ttl_seconds=APPROVAL_DEFAULT_TTL_SECONDS,
    max_ttl_seconds=APPROVAL_MAX_TTL_SECONDS,
)
output_containment = OutputContainment(MAX_RESPONSE_BYTES)
tool_catalog = TrustedToolCatalog.load(
    TRUSTED_TOOL_CATALOG_PATH,
    expected_sha256=TRUSTED_TOOL_CATALOG_SHA256,
)
if tool_catalog.protocol_version != policy.protocol_version:
    raise RuntimeError("trusted tool catalog protocol version does not match policy")

observability = configure_observability(service_version=SERVICE_VERSION)
app = FastAPI(title="MCP Agent Firewall", version=SERVICE_VERSION)


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


def _tool_name_and_arguments(payload: EvaluationInput) -> tuple[str, dict[str, Any]]:
    if payload.body.method != "tools/call":
        raise ToolCatalogError("tool_contract_not_applicable")
    name = payload.body.params.get("name")
    arguments = payload.body.params.get("arguments", {})
    if not isinstance(name, str) or not name:
        raise ToolCatalogError("tool_name_missing")
    if not isinstance(arguments, dict):
        raise ToolCatalogError("tool_arguments_must_be_object")
    return name, arguments


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


def _catalog_error_response(body: dict[str, Any], error: ToolCatalogError) -> JSONResponse:
    data = error.data()
    if error.code == "tool_not_in_trusted_catalog":
        status_code = 403
        code = -32044
        message = "Tool is not present in the pinned trusted catalog"
    elif error.code.startswith("mcp_param_") or error.code.startswith("mcp_header_"):
        status_code = 400
        code = -32020
        message = "MCP parameter header mismatch"
    elif error.code in {"trusted_schema_runtime_error", "trusted_catalog_pin_mismatch"}:
        status_code = 503
        code = -32045
        message = "Trusted tool catalog validation unavailable"
    else:
        status_code = 400
        code = -32602
        message = "Tool arguments do not satisfy the pinned trusted schema"
    return JSONResponse(
        status_code=status_code,
        content={
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "error": {"code": code, "message": message, "data": data},
        },
    )


def _request_outcome_from_status(status_code: int) -> str:
    family = status_family(status_code)
    return {
        "2xx": "upstream_success",
        "3xx": "upstream_redirect",
        "4xx": "upstream_client_error",
        "5xx": "upstream_server_error",
    }.get(family, "upstream_other")


def _output_outcome(action: OutputAction, signals: tuple[str, ...]) -> str:
    if action == OutputAction.BLOCK:
        return "blocked"
    return "flagged" if signals else "clean"


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "policy_version": policy.version,
        "approval_mode": "signed_receipts" if approval_receipts.configured else "disabled",
        "tool_catalog_version": tool_catalog.catalog_version,
        "tool_catalog_sha256": tool_catalog.digest,
        "output_containment": "enabled",
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "telemetry_mode": observability.mode,
        "telemetry_exporting": observability.exporting,
    }


@app.post("/v1/evaluate")
def evaluate(payload: EvaluationInput) -> dict[str, Any]:
    return engine.evaluate(payload).model_dump(mode="json")


@app.post("/v1/approvals/issue", response_model=ApprovalIssueResponse)
def issue_approval(
    payload: ApprovalIssueRequest,
    operator_token: str | None = Header(default=None, alias="X-Operator-Token"),
) -> ApprovalIssueResponse:
    with observability.stage(
        "mcp.approval.issue",
        attributes={
            "mcp.method": payload.request.mcp_method,
            "firewall.policy.version": policy.version,
            "firewall.catalog.version": tool_catalog.catalog_version,
        },
    ) as issue_span:
        if (
            not APPROVAL_ISSUER_TOKEN
            or not operator_token
            or not secrets.compare_digest(operator_token, APPROVAL_ISSUER_TOKEN)
        ):
            observability.record_approval(phase="issue", outcome="access_denied", span=issue_span)
            raise HTTPException(status_code=403, detail="approval_issuer_access_denied")

        result = engine.evaluate(payload.request)
        if result.decision != Decision.APPROVAL_REQUIRED:
            observability.record_approval(phase="issue", outcome="not_required", span=issue_span)
            raise HTTPException(status_code=409, detail="request_does_not_require_human_approval")

        with observability.stage(
            "mcp.schema.validate",
            attributes={"firewall.schema.phase": "issue"},
        ) as schema_span:
            try:
                tool_name, arguments = _tool_name_and_arguments(payload.request)
                tool_catalog.validate_arguments(tool_name, arguments)
            except ToolCatalogError as exc:
                observability.record_schema(
                    check="arguments",
                    outcome="rejected",
                    phase="issue",
                    span=schema_span,
                )
                schema_span.set_attribute("error.type", exc.code)
                observability.record_approval(
                    phase="issue",
                    outcome="schema_rejected",
                    span=issue_span,
                )
                raise HTTPException(status_code=400, detail=exc.data()) from exc
            observability.record_schema(
                check="arguments",
                outcome="accepted",
                phase="issue",
                span=schema_span,
            )

        try:
            receipt, claims = approval_receipts.issue(
                payload.request,
                policy_version=policy.version,
                approver=payload.approver,
                ttl_seconds=payload.ttl_seconds,
            )
        except ApprovalError as exc:
            observability.record_approval(phase="issue", outcome="rejected", span=issue_span)
            issue_span.set_attribute("error.type", exc.code)
            status_code = 503 if exc.code == "approval_signing_not_configured" else 400
            raise HTTPException(status_code=status_code, detail=exc.code) from exc

        audit.register_approval(claims)
        observability.record_approval(phase="issue", outcome="issued", span=issue_span)
        return response_from_issued(receipt, claims)


@app.get("/v1/audit")
def recent_audit(
    limit: int = 50,
    operator_token: str | None = Header(default=None, alias="X-Operator-Token"),
) -> dict[str, Any]:
    if not AUDIT_READ_TOKEN or operator_token != AUDIT_READ_TOKEN:
        raise HTTPException(status_code=403, detail="audit_access_denied")
    return {"events": audit.recent(limit)}


@app.get("/v1/audit/output")
def recent_output_audit(
    limit: int = 50,
    operator_token: str | None = Header(default=None, alias="X-Operator-Token"),
) -> dict[str, Any]:
    if not AUDIT_READ_TOKEN or operator_token != AUDIT_READ_TOKEN:
        raise HTTPException(status_code=403, detail="audit_access_denied")
    return {"events": audit.recent_outputs(limit)}


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
        decoded_mcp_name = decode_mcp_header_value(mcp_name) if mcp_name is not None else None
    except ToolCatalogError as exc:
        return _catalog_error_response(body, exc)

    try:
        evaluation_input = _evaluation_input(
            body,
            protocol_version=mcp_protocol_version,
            mcp_method=mcp_method,
            mcp_name=decoded_mcp_name,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid_mcp_envelope") from exc

    with observability.request_span(
        headers=dict(request.headers),
        method=evaluation_input.mcp_method,
        protocol_version=evaluation_input.protocol_version,
        tool_name=evaluation_input.mcp_name,
        request_sha256=approval_request_hash(evaluation_input),
        policy_version=policy.version,
        catalog_version=tool_catalog.catalog_version,
    ) as request_span:
        with observability.stage("mcp.policy.evaluate") as policy_span:
            result = engine.evaluate(evaluation_input)
            observability.record_policy(
                decision=result.decision.value,
                risk=result.risk.value,
                method=evaluation_input.mcp_method,
                span=policy_span,
            )
        request_span.set_attribute("firewall.decision", result.decision.value)
        request_span.set_attribute("firewall.risk", result.risk.value)

        client_name = _client_name(body)
        traceparent = request.headers.get("traceparent") or _traceparent(body)
        audit.append(
            body=body,
            result=result,
            client_name=client_name,
            traceparent=traceparent[:256] if traceparent else None,
        )

        if result.decision == Decision.DENY:
            request_span.set_attribute("firewall.outcome", "blocked_policy")
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

        custom_mcp_headers: list[tuple[str, str]] = []
        if evaluation_input.body.method == "tools/call":
            schema_check = "arguments"
            with observability.stage(
                "mcp.schema.validate",
                attributes={"firewall.schema.phase": "dispatch"},
            ) as schema_span:
                try:
                    tool_name, arguments = _tool_name_and_arguments(evaluation_input)
                    tool_catalog.validate_arguments(tool_name, arguments)
                    observability.record_schema(
                        check="arguments",
                        outcome="accepted",
                        phase="dispatch",
                        span=schema_span,
                    )
                    schema_check = "headers"
                    custom_mcp_headers = tool_catalog.validate_mcp_param_headers(
                        tool_name,
                        arguments,
                        request.headers.raw,
                    )
                    observability.record_schema(
                        check="headers",
                        outcome="accepted",
                        phase="dispatch",
                        span=schema_span,
                    )
                except ToolCatalogError as exc:
                    observability.record_schema(
                        check=schema_check,
                        outcome="rejected",
                        phase="dispatch",
                        span=schema_span,
                    )
                    schema_span.set_attribute("error.type", exc.code)
                    request_span.set_attribute("firewall.outcome", "schema_rejected")
                    return _catalog_error_response(body, exc)

        approval_claims = None
        if result.decision == Decision.APPROVAL_REQUIRED:
            with observability.stage("mcp.approval.verify") as approval_span:
                if not human_approval:
                    observability.record_approval(
                        phase="verify",
                        outcome="missing",
                        span=approval_span,
                    )
                    request_span.set_attribute("firewall.outcome", "approval_missing")
                    return _approval_error_response(body, result, "approval_receipt_required")
                try:
                    approval_claims = approval_receipts.verify(
                        human_approval,
                        evaluation_input,
                        policy_version=policy.version,
                    )
                except ApprovalError as exc:
                    observability.record_approval(
                        phase="verify",
                        outcome="rejected",
                        span=approval_span,
                    )
                    approval_span.set_attribute("error.type", exc.code)
                    request_span.set_attribute("firewall.outcome", "approval_rejected")
                    return _approval_error_response(body, result, exc.code)
                observability.record_approval(
                    phase="verify",
                    outcome="accepted",
                    span=approval_span,
                )

        if not UPSTREAM_MCP_URL:
            request_span.set_attribute("firewall.outcome", "no_upstream")
            return JSONResponse(
                status_code=503,
                content={
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {
                        "code": -32042,
                        "message": (
                            "Policy allowed the call but no upstream MCP server is configured"
                        ),
                        "data": result.model_dump(mode="json"),
                    },
                },
            )

        if approval_claims is not None:
            with observability.stage("mcp.approval.consume") as consume_span:
                consumed = audit.consume_approval(approval_claims)
                observability.record_approval(
                    phase="consume",
                    outcome="consumed" if consumed else "rejected",
                    span=consume_span,
                )
            if not consumed:
                request_span.set_attribute("firewall.outcome", "approval_replay_rejected")
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

        forward_header_items = [
            ("MCP-Protocol-Version", mcp_protocol_version),
            ("Mcp-Method", mcp_method),
            ("content-type", "application/json"),
        ]
        if mcp_name:
            forward_header_items.append(("Mcp-Name", mcp_name))
        forward_header_items.extend(custom_mcp_headers)
        if UPSTREAM_BEARER_TOKEN:
            forward_header_items.append(("authorization", f"Bearer {UPSTREAM_BEARER_TOKEN}"))
        forward_headers = httpx.Headers(forward_header_items)

        started = time.perf_counter()
        with observability.stage("mcp.upstream.dispatch", kind=SpanKind.CLIENT) as upstream_span:
            for header_name, header_value in observability.trace_context_headers().items():
                forward_headers[header_name] = header_value
            try:
                async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
                    upstream = await client.post(
                        UPSTREAM_MCP_URL,
                        content=raw,
                        headers=forward_headers,
                    )
            except Exception as exc:
                observability.record_upstream(
                    status_code=None,
                    duration_seconds=time.perf_counter() - started,
                    span=upstream_span,
                )
                upstream_span.set_attribute("error.type", type(exc).__name__)
                request_span.set_attribute("firewall.outcome", "upstream_transport_error")
                raise
            observability.record_upstream(
                status_code=upstream.status_code,
                duration_seconds=time.perf_counter() - started,
                span=upstream_span,
            )

        content_type = upstream.headers.get("content-type")
        with observability.stage("mcp.output.inspect") as output_span:
            inspection = output_containment.inspect(upstream.content, content_type)
            output_outcome = _output_outcome(inspection.action, inspection.signals)
            observability.record_output(
                outcome=output_outcome,
                signals=inspection.signals,
                span=output_span,
            )
        audit.append_output(
            method=evaluation_input.mcp_method,
            tool_name=evaluation_input.mcp_name,
            outcome=output_outcome,
            signals=inspection.signals,
            content=upstream.content,
        )

        if inspection.action == OutputAction.BLOCK:
            request_span.set_attribute("firewall.outcome", "output_blocked")
            return JSONResponse(
                status_code=502,
                content={
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {
                        "code": -32046,
                        "message": "Upstream MCP response blocked by output containment",
                        "data": inspection.public_data(),
                    },
                },
                headers={
                    "Mcp-Firewall-Untrusted-Content": "true",
                    "Mcp-Firewall-Output-Inspection": "blocked",
                },
            )

        request_span.set_attribute(
            "firewall.outcome",
            _request_outcome_from_status(upstream.status_code),
        )
        response_headers = {
            "Mcp-Firewall-Untrusted-Content": "true",
            "Mcp-Firewall-Output-Inspection": output_outcome,
        }
        if inspection.signals:
            response_headers["Mcp-Firewall-Output-Signals"] = ",".join(inspection.signals)
        if content_type:
            response_headers["content-type"] = content_type
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=response_headers,
        )

from pathlib import Path

import pytest

from app.approval import ApprovalError, ApprovalReceiptService
from app.audit import AuditStore
from app.models import EvaluationInput, McpEnvelope


def approval_request(path: str = "/tmp/example.txt") -> EvaluationInput:
    return EvaluationInput(
        protocol_version="2026-07-28",
        mcp_method="tools/call",
        mcp_name="delete_file",
        body=McpEnvelope(
            jsonrpc="2.0",
            id=1,
            method="tools/call",
            params={"name": "delete_file", "arguments": {"path": path}},
        ),
    )


def service() -> ApprovalReceiptService:
    return ApprovalReceiptService(
        "k" * 32,
        default_ttl_seconds=60,
        max_ttl_seconds=300,
    )


def test_receipt_round_trip_binds_exact_request_and_policy():
    request = approval_request()
    receipt, claims = service().issue(
        request,
        policy_version="1",
        approver="operator@example.com",
        now=1000,
    )
    verified = service().verify(receipt, request, policy_version="1", now=1010)
    assert verified.jti == claims.jti
    assert verified.request_sha256 == claims.request_sha256
    assert verified.tool_name == "delete_file"


def test_tampered_signature_is_rejected():
    request = approval_request()
    receipt, _ = service().issue(request, policy_version="1", approver="operator", now=1000)
    prefix, payload, signature = receipt.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    tampered = f"{prefix}.{payload}.{replacement}{signature[1:]}"

    with pytest.raises(ApprovalError) as exc_info:
        service().verify(tampered, request, policy_version="1", now=1010)
    assert exc_info.value.code == "approval_signature_invalid"


def test_receipt_cannot_authorize_modified_request():
    original = approval_request("/tmp/a.txt")
    modified = approval_request("/tmp/b.txt")
    receipt, _ = service().issue(original, policy_version="1", approver="operator", now=1000)

    with pytest.raises(ApprovalError) as exc_info:
        service().verify(receipt, modified, policy_version="1", now=1010)
    assert exc_info.value.code == "approval_request_mismatch"


def test_expired_receipt_is_rejected():
    request = approval_request()
    receipt, _ = service().issue(
        request,
        policy_version="1",
        approver="operator",
        ttl_seconds=30,
        now=1000,
    )

    with pytest.raises(ApprovalError) as exc_info:
        service().verify(receipt, request, policy_version="1", now=1030)
    assert exc_info.value.code == "approval_expired"


def test_policy_version_change_invalidates_receipt():
    request = approval_request()
    receipt, _ = service().issue(request, policy_version="1", approver="operator", now=1000)

    with pytest.raises(ApprovalError) as exc_info:
        service().verify(receipt, request, policy_version="2", now=1010)
    assert exc_info.value.code == "approval_policy_version_mismatch"


def test_receipt_consumption_is_atomic_and_one_time(tmp_path: Path):
    request = approval_request()
    receipt_service = service()
    _, claims = receipt_service.issue(
        request,
        policy_version="1",
        approver="operator",
        now=1000,
    )
    store = AuditStore(str(tmp_path / "audit.db"))
    store.register_approval(claims)

    assert store.consume_approval(claims, now=1010) is True
    assert store.consume_approval(claims, now=1010) is False


def test_weak_signing_key_is_rejected():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        ApprovalReceiptService("too-short")

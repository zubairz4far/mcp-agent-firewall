import os
from pathlib import Path

os.environ.setdefault("AUDIT_DB_PATH", "/tmp/mcp-agent-firewall-test.db")
os.environ.setdefault(
    "POLICY_PATH", str(Path(__file__).resolve().parents[1] / "config" / "policy.example.yaml")
)
os.environ.setdefault("APPROVAL_SIGNING_KEY", "test-signing-key-32-bytes-minimum!!")
os.environ.setdefault("APPROVAL_ISSUER_TOKEN", "test-issuer-token")
os.environ.setdefault("APPROVAL_DEFAULT_TTL_SECONDS", "60")
os.environ.setdefault("APPROVAL_MAX_TTL_SECONDS", "300")

from fastapi.testclient import TestClient

from app import main as main_module
from app.main import app

client = TestClient(app)


def headers(tool: str) -> dict[str, str]:
    return {
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
    }


def body(tool: str, args: dict, *, request_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }


def approval_payload(tool: str, args: dict) -> dict:
    return {
        "request": {
            "protocol_version": "2026-07-28",
            "mcp_method": "tools/call",
            "mcp_name": tool,
            "body": body(tool, args),
        },
        "approver": "test-operator",
        "ttl_seconds": 60,
    }


def issue_receipt(tool: str, args: dict) -> str:
    response = client.post(
        "/v1/approvals/issue",
        headers={"X-Operator-Token": "test-issuer-token"},
        json=approval_payload(tool, args),
    )
    assert response.status_code == 200
    return response.json()["receipt"]


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["approval_mode"] == "signed_receipts"


def test_denied_tool_returns_403():
    response = client.post("/mcp", headers=headers("shell"), json=body("shell", {}))
    assert response.status_code == 403
    assert response.json()["error"]["data"]["decision"] == "deny"


def test_approval_required_returns_428_without_receipt():
    response = client.post(
        "/mcp", headers=headers("delete_file"), json=body("delete_file", {"path": "/tmp/a"})
    )
    assert response.status_code == 428
    assert response.json()["error"]["data"]["approval_error"] == "approval_receipt_required"


def test_allowed_without_upstream_returns_503_but_policy_allows():
    response = client.post("/mcp", headers=headers("search"), json=body("search", {"q": "x"}))
    assert response.status_code == 503
    assert response.json()["error"]["data"]["decision"] == "allow"


def test_header_mismatch_fails_closed():
    h = headers("search")
    h["Mcp-Name"] = "delete_file"
    response = client.post("/mcp", headers=h, json=body("search", {"q": "x"}))
    assert response.status_code == 403


def test_audit_endpoint_fails_closed_without_operator_token():
    response = client.get("/v1/audit")
    assert response.status_code == 403


def test_evaluate_endpoint_returns_approval_required():
    payload = {
        "protocol_version": "2026-07-28",
        "mcp_method": "tools/call",
        "mcp_name": "send_email",
        "body": {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "a@example.com"}},
        },
    }
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 200
    assert response.json()["decision"] == "approval_required"


def test_approval_issue_requires_operator_token():
    response = client.post(
        "/v1/approvals/issue",
        json=approval_payload("delete_file", {"path": "/tmp/a"}),
    )
    assert response.status_code == 403


def test_approval_issue_rejects_request_that_does_not_require_approval():
    response = client.post(
        "/v1/approvals/issue",
        headers={"X-Operator-Token": "test-issuer-token"},
        json=approval_payload("search", {"q": "safe"}),
    )
    assert response.status_code == 409


def test_signed_receipt_is_bound_to_exact_request():
    receipt = issue_receipt("delete_file", {"path": "/tmp/a"})
    h = headers("delete_file")
    h["X-Human-Approval"] = receipt
    response = client.post(
        "/mcp",
        headers=h,
        json=body("delete_file", {"path": "/tmp/b"}),
    )
    assert response.status_code == 428
    assert response.json()["error"]["data"]["approval_error"] == "approval_request_mismatch"


def test_valid_receipt_is_consumed_once_at_dispatch(monkeypatch):
    class FakeResponse:
        status_code = 200
        content = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
        headers = {"content-type": "application/json"}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, *, content, headers):
            assert url == "https://upstream.example/mcp"
            assert headers["Mcp-Name"] == "delete_file"
            return FakeResponse()

    monkeypatch.setattr(main_module, "UPSTREAM_MCP_URL", "https://upstream.example/mcp")
    monkeypatch.setattr(main_module.httpx, "AsyncClient", FakeAsyncClient)

    request_body = body("delete_file", {"path": "/tmp/a"})
    receipt = issue_receipt("delete_file", {"path": "/tmp/a"})
    h = headers("delete_file")
    h["X-Human-Approval"] = receipt

    first = client.post("/mcp", headers=h, json=request_body)
    assert first.status_code == 200

    replay = client.post("/mcp", headers=h, json=request_body)
    assert replay.status_code == 409
    assert "already consumed" in replay.json()["error"]["message"]

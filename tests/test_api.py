import os
from pathlib import Path

os.environ.setdefault("AUDIT_DB_PATH", "/tmp/mcp-agent-firewall-test.db")
os.environ.setdefault(
    "POLICY_PATH", str(Path(__file__).resolve().parents[1] / "config" / "policy.example.yaml")
)

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def headers(tool: str) -> dict[str, str]:
    return {
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
    }


def body(tool: str, args: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }


def test_health():
    response = client.get("/health")
    assert response.status_code == 200


def test_denied_tool_returns_403():
    response = client.post("/mcp", headers=headers("shell"), json=body("shell", {}))
    assert response.status_code == 403
    assert response.json()["error"]["data"]["decision"] == "deny"


def test_approval_required_returns_428_without_token():
    response = client.post(
        "/mcp", headers=headers("delete_file"), json=body("delete_file", {"path": "/tmp/a"})
    )
    assert response.status_code == 428


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

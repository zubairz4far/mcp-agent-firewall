from __future__ import annotations

import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("AUDIT_DB_PATH", "/tmp/mcp-agent-firewall-otel-test.db")
os.environ.setdefault("POLICY_PATH", str(ROOT / "config" / "policy.example.yaml"))
os.environ.setdefault("APPROVAL_SIGNING_KEY", "test-signing-key-32-bytes-minimum!!")
os.environ.setdefault("APPROVAL_ISSUER_TOKEN", "test-issuer-token")
os.environ.setdefault("APPROVAL_DEFAULT_TTL_SECONDS", "60")
os.environ.setdefault("APPROVAL_MAX_TTL_SECONDS", "300")
os.environ.setdefault(
    "TRUSTED_TOOL_CATALOG_PATH",
    str(ROOT / "config" / "trusted_tools.example.json"),
)
os.environ.setdefault(
    "TRUSTED_TOOL_CATALOG_SHA256",
    (ROOT / "config" / "trusted_tools.example.sha256").read_text().strip(),
)

from fastapi.testclient import TestClient  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import (  # noqa: E402
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import SpanKind  # noqa: E402

from app import main as main_module  # noqa: E402
from app.observability import (  # noqa: E402
    FirewallObservability,
    method_family,
    status_family,
)


class CaptureSpanExporter(SpanExporter):
    def __init__(self) -> None:
        self.spans: list[Any] = []

    def export(self, spans: tuple[Any, ...]) -> SpanExportResult:
        self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


class CaptureInstrument:
    def __init__(self, name: str) -> None:
        self.name = name
        self.measurements: list[tuple[float | int, dict[str, Any]]] = []

    def add(self, value: int, attributes: dict[str, Any]) -> None:
        self.measurements.append((value, dict(attributes)))

    def record(self, value: float, attributes: dict[str, Any]) -> None:
        self.measurements.append((value, dict(attributes)))


class CaptureMeter:
    def __init__(self) -> None:
        self.instruments: dict[str, CaptureInstrument] = {}

    def create_counter(self, name: str, **_: Any) -> CaptureInstrument:
        instrument = CaptureInstrument(name)
        self.instruments[name] = instrument
        return instrument

    def create_histogram(self, name: str, **_: Any) -> CaptureInstrument:
        instrument = CaptureInstrument(name)
        self.instruments[name] = instrument
        return instrument


def build_observability() -> tuple[FirewallObservability, CaptureSpanExporter, CaptureMeter]:
    exporter = CaptureSpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    meter = CaptureMeter()
    observability = FirewallObservability(provider.get_tracer("test"), meter, mode="test")
    return observability, exporter, meter


def headers(tool: str) -> dict[str, str]:
    return {
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
    }


def body(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }


def test_method_and_status_dimensions_are_bounded():
    assert method_family("tools/call") == "tools"
    assert method_family("attacker/" + "x" * 500) == "other"
    assert status_family(200) == "2xx"
    assert status_family(404) == "4xx"
    assert status_family(503) == "5xx"
    assert status_family(799) == "other"


def test_real_mcp_request_does_not_leak_argument_value_to_telemetry(monkeypatch):
    observability, exporter, meter = build_observability()
    monkeypatch.setattr(main_module, "observability", observability)
    monkeypatch.setattr(main_module, "UPSTREAM_MCP_URL", "")
    client = TestClient(main_module.app)

    sentinel = "SUPER_SECRET_SENTINEL_9f24d7"
    request_headers = headers("search")
    request_headers["traceparent"] = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    response = client.post(
        "/mcp",
        headers=request_headers,
        json=body("search", {"q": sentinel}),
    )

    assert response.status_code == 503
    assert {span.name for span in exporter.spans} >= {
        "mcp.firewall.request",
        "mcp.policy.evaluate",
        "mcp.schema.validate",
    }

    telemetry_text = " ".join(
        [str(span.attributes) + str(span.events) for span in exporter.spans]
        + [str(instrument.measurements) for instrument in meter.instruments.values()]
    )
    assert sentinel not in telemetry_text

    root = next(span for span in exporter.spans if span.name == "mcp.firewall.request")
    assert root.context.trace_id == int("4bf92f3577b34da6a3ce929d0e0e4736", 16)
    assert root.parent is not None
    assert root.parent.span_id == int("00f067aa0ba902b7", 16)


def test_metric_dimensions_never_include_tool_name_or_request_hash(monkeypatch):
    observability, _, meter = build_observability()
    monkeypatch.setattr(main_module, "observability", observability)
    monkeypatch.setattr(main_module, "UPSTREAM_MCP_URL", "")
    client = TestClient(main_module.app)

    response = client.post("/mcp", headers=headers("search"), json=body("search", {"q": "safe"}))
    assert response.status_code == 503

    allowed_dimensions = {
        "mcp.firewall.policy.decisions": {"decision", "risk", "method_family"},
        "mcp.firewall.schema.validations": {"check", "outcome", "phase"},
        "mcp.firewall.approval.events": {"phase", "outcome"},
        "mcp.firewall.upstream.duration": {"outcome"},
    }
    for name, instrument in meter.instruments.items():
        for _, attributes in instrument.measurements:
            assert set(attributes) <= allowed_dimensions[name]
            assert "tool_name" not in attributes
            assert "request_sha256" not in attributes


def test_missing_approval_emits_bounded_approval_event(monkeypatch):
    observability, exporter, meter = build_observability()
    monkeypatch.setattr(main_module, "observability", observability)
    monkeypatch.setattr(main_module, "UPSTREAM_MCP_URL", "")
    client = TestClient(main_module.app)

    response = client.post(
        "/mcp",
        headers=headers("delete_file"),
        json=body("delete_file", {"path": "/tmp/a"}),
    )
    assert response.status_code == 428
    assert any(span.name == "mcp.approval.verify" for span in exporter.spans)
    measurements = meter.instruments["mcp.firewall.approval.events"].measurements
    assert any(attrs == {"phase": "verify", "outcome": "missing"} for _, attrs in measurements)


def test_upstream_span_is_client_and_injects_current_trace_context(monkeypatch):
    observability, exporter, meter = build_observability()
    monkeypatch.setattr(main_module, "observability", observability)
    monkeypatch.setattr(main_module, "UPSTREAM_MCP_URL", "https://upstream.example/mcp")
    client = TestClient(main_module.app)
    captured_headers: dict[str, str] = {}

    class FakeResponse:
        status_code = 200
        content = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
        headers = {"content-type": "application/json"}

    class FakeAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
            return False

        async def post(self, url: str, *, content: bytes, headers: Any) -> FakeResponse:
            assert url == "https://upstream.example/mcp"
            captured_headers.update(dict(headers))
            return FakeResponse()

    monkeypatch.setattr(main_module.httpx, "AsyncClient", FakeAsyncClient)
    request_headers = headers("search")
    request_headers["traceparent"] = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    response = client.post(
        "/mcp",
        headers=request_headers,
        json=body("search", {"q": "safe"}),
    )

    assert response.status_code == 200
    upstream_span = next(span for span in exporter.spans if span.name == "mcp.upstream.dispatch")
    assert upstream_span.kind == SpanKind.CLIENT
    assert captured_headers.get("traceparent")
    assert captured_headers["traceparent"].startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    measurements = meter.instruments["mcp.firewall.upstream.duration"].measurements
    assert any(attrs == {"outcome": "2xx"} for _, attrs in measurements)

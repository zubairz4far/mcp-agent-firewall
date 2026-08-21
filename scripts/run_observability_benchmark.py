from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("AUDIT_DB_PATH", "/tmp/mcp-agent-firewall-otel-benchmark.db")
os.environ.setdefault("POLICY_PATH", str(ROOT / "config" / "policy.example.yaml"))
os.environ.setdefault("APPROVAL_SIGNING_KEY", "benchmark-signing-key-32-bytes-min!!")
os.environ.setdefault("APPROVAL_ISSUER_TOKEN", "benchmark-issuer-token")
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
from app.observability import FirewallObservability  # noqa: E402


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
    observability = FirewallObservability(
        provider.get_tracer("benchmark"),
        meter,
        mode="test",
    )
    return observability, exporter, meter


def headers(tool: str) -> dict[str, str]:
    return {
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": tool,
    }


def body(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def main() -> int:
    observability, exporter, meter = build_observability()
    original_observability = main_module.observability
    original_upstream = main_module.UPSTREAM_MCP_URL
    original_async_client = main_module.httpx.AsyncClient
    main_module.observability = observability
    client = TestClient(main_module.app)

    sentinel = "ULTRA_PRIVATE_SENTINEL_b819c7"
    parent_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    parent_span_id = "00f067aa0ba902b7"
    traceparent = f"00-{parent_trace_id}-{parent_span_id}-01"

    try:
        main_module.UPSTREAM_MCP_URL = ""
        search_headers = headers("search")
        search_headers["traceparent"] = traceparent
        search_response = client.post(
            "/mcp",
            headers=search_headers,
            json=body("search", {"q": sentinel}),
        )

        approval_response = client.post(
            "/mcp",
            headers=headers("delete_file"),
            json=body("delete_file", {"path": "/tmp/example"}),
        )

        captured_upstream_headers: dict[str, str] = {}

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
                captured_upstream_headers.update(dict(headers))
                return FakeResponse()

        main_module.httpx.AsyncClient = FakeAsyncClient
        main_module.UPSTREAM_MCP_URL = "https://upstream.example/mcp"
        upstream_headers = headers("search")
        upstream_headers["traceparent"] = traceparent
        upstream_response = client.post(
            "/mcp",
            headers=upstream_headers,
            json=body("search", {"q": "safe"}),
        )

        span_names = {span.name for span in exporter.spans}
        telemetry_text = " ".join(
            [str(span.attributes) + str(span.events) for span in exporter.spans]
            + [str(instrument.measurements) for instrument in meter.instruments.values()]
        )
        request_spans = [span for span in exporter.spans if span.name == "mcp.firewall.request"]
        parent_preserved = any(
            span.context.trace_id == int(parent_trace_id, 16)
            and span.parent is not None
            and span.parent.span_id == int(parent_span_id, 16)
            for span in request_spans
        )

        allowed_dimensions = {
            "mcp.firewall.policy.decisions": {"decision", "risk", "method_family"},
            "mcp.firewall.schema.validations": {"check", "outcome", "phase"},
            "mcp.firewall.approval.events": {"phase", "outcome"},
            "mcp.firewall.output.inspections": {"outcome", "signal_class"},
            "mcp.firewall.upstream.duration": {"outcome"},
        }
        dimensions_bounded = True
        for name, instrument in meter.instruments.items():
            for _, attributes in instrument.measurements:
                if not set(attributes) <= allowed_dimensions[name]:
                    dimensions_bounded = False

        upstream_span = next(
            (span for span in exporter.spans if span.name == "mcp.upstream.dispatch"),
            None,
        )
        upstream_metric = meter.instruments["mcp.firewall.upstream.duration"].measurements
        output_metric = meter.instruments["mcp.firewall.output.inspections"].measurements

        approval_stage_ok = (
            approval_response.status_code == 428 and "mcp.approval.verify" in span_names
        )
        upstream_span_ok = upstream_span is not None and upstream_span.kind == SpanKind.CLIENT

        cases = [
            ("search_request_reached_no_upstream_gate", search_response.status_code == 503),
            ("secret_sentinel_absent_from_telemetry", sentinel not in telemetry_text),
            ("w3c_parent_context_preserved", parent_preserved),
            ("policy_stage_emitted", "mcp.policy.evaluate" in span_names),
            ("schema_stage_emitted", "mcp.schema.validate" in span_names),
            ("approval_stage_emitted", approval_stage_ok),
            ("metric_dimensions_bounded", dimensions_bounded),
            ("upstream_request_succeeds", upstream_response.status_code == 200),
            ("upstream_span_is_client", upstream_span_ok),
            ("output_inspection_stage_emitted", "mcp.output.inspect" in span_names),
            (
                "output_marked_untrusted",
                upstream_response.headers.get("Mcp-Firewall-Untrusted-Content") == "true",
            ),
            (
                "upstream_trace_context_injected",
                captured_upstream_headers.get("traceparent", "").startswith(
                    f"00-{parent_trace_id}-"
                ),
            ),
            (
                "upstream_2xx_metric_emitted",
                any(attrs == {"outcome": "2xx"} for _, attrs in upstream_metric),
            ),
            (
                "clean_output_metric_emitted",
                any(
                    attrs == {"outcome": "clean", "signal_class": "none"}
                    for _, attrs in output_metric
                ),
            ),
        ]

        failed = [case_id for case_id, ok in cases if not ok]
        summary = {
            "suite": "observability_privacy_v2",
            "cases": len(cases),
            "passed": len(cases) - len(failed),
            "exact_security_decision_accuracy": (len(cases) - len(failed)) / len(cases),
            "unsafe_telemetry_leaks": 0 if sentinel not in telemetry_text else 1,
            "failed": failed,
        }
        print(json.dumps(summary, indent=2))
        return 1 if failed or summary["unsafe_telemetry_leaks"] else 0
    finally:
        main_module.observability = original_observability
        main_module.UPSTREAM_MCP_URL = original_upstream
        main_module.httpx.AsyncClient = original_async_client


if __name__ == "__main__":
    raise SystemExit(main())

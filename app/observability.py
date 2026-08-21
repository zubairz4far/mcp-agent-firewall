from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.metrics import Meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, SpanKind, Tracer
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

INSTRUMENTATION_SCOPE = "mcp-agent-firewall"
_METHOD_FAMILIES = frozenset({"server", "tools", "resources", "prompts"})


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def method_family(method: str) -> str:
    prefix = method.split("/", 1)[0] if method else ""
    return prefix if prefix in _METHOD_FAMILIES else "other"


def status_family(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "other"


class FirewallObservability:
    """Manual, privacy-minimized telemetry for the firewall control plane.

    Metric dimensions are deliberately low-cardinality. Tool names and request
    fingerprints are trace-only attributes and raw request arguments are never
    accepted by this API.
    """

    def __init__(self, tracer: Tracer, meter: Meter, *, mode: str):
        self.tracer = tracer
        self.meter = meter
        self.mode = mode
        self.policy_decisions = meter.create_counter(
            "mcp.firewall.policy.decisions",
            unit="{decision}",
            description="Deterministic firewall policy decisions",
        )
        self.schema_validations = meter.create_counter(
            "mcp.firewall.schema.validations",
            unit="{validation}",
            description="Pinned trusted-schema and MCP header validation outcomes",
        )
        self.approval_events = meter.create_counter(
            "mcp.firewall.approval.events",
            unit="{event}",
            description="Signed human approval lifecycle outcomes",
        )
        self.upstream_duration = meter.create_histogram(
            "mcp.firewall.upstream.duration",
            unit="s",
            description="Time spent dispatching an allowed request to the upstream MCP server",
        )

    @property
    def exporting(self) -> bool:
        return self.mode == "otlp_http"

    def extract_parent(self, headers: Mapping[str, str]) -> Context:
        return TraceContextTextMapPropagator().extract(carrier=headers)

    def trace_context_headers(self) -> dict[str, str]:
        carrier: dict[str, str] = {}
        TraceContextTextMapPropagator().inject(carrier=carrier)
        return carrier

    @contextmanager
    def request_span(
        self,
        *,
        headers: Mapping[str, str],
        method: str,
        protocol_version: str,
        tool_name: str | None,
        request_sha256: str,
        policy_version: str,
        catalog_version: str,
    ) -> Iterator[Span]:
        parent = self.extract_parent(headers)
        attributes: dict[str, Any] = {
            "mcp.method": method,
            "mcp.method_family": method_family(method),
            "mcp.protocol.version": protocol_version,
            "mcp.request.sha256": request_sha256,
            "firewall.policy.version": policy_version,
            "firewall.catalog.version": catalog_version,
        }
        if tool_name:
            attributes["mcp.tool.name"] = tool_name
        with self.tracer.start_as_current_span(
            "mcp.firewall.request",
            context=parent,
            kind=SpanKind.SERVER,
            attributes=attributes,
        ) as span:
            yield span

    @contextmanager
    def stage(
        self,
        name: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        kind: SpanKind = SpanKind.INTERNAL,
    ) -> Iterator[Span]:
        with self.tracer.start_as_current_span(
            name,
            kind=kind,
            attributes=dict(attributes or {}),
        ) as span:
            yield span

    def record_policy(
        self,
        *,
        decision: str,
        risk: str,
        method: str,
        span: Span | None = None,
    ) -> None:
        attributes = {
            "decision": decision,
            "risk": risk,
            "method_family": method_family(method),
        }
        self.policy_decisions.add(1, attributes)
        target = span or trace.get_current_span()
        target.set_attribute("firewall.decision", decision)
        target.set_attribute("firewall.risk", risk)

    def record_schema(
        self,
        *,
        check: str,
        outcome: str,
        phase: str,
        span: Span | None = None,
    ) -> None:
        self.schema_validations.add(
            1,
            {"check": check, "outcome": outcome, "phase": phase},
        )
        target = span or trace.get_current_span()
        target.set_attribute("firewall.schema.check", check)
        target.set_attribute("firewall.schema.outcome", outcome)
        target.set_attribute("firewall.schema.phase", phase)

    def record_approval(self, *, phase: str, outcome: str, span: Span | None = None) -> None:
        self.approval_events.add(1, {"phase": phase, "outcome": outcome})
        target = span or trace.get_current_span()
        target.set_attribute("firewall.approval.phase", phase)
        target.set_attribute("firewall.approval.outcome", outcome)

    def record_upstream(
        self,
        *,
        status_code: int | None,
        duration_seconds: float,
        span: Span,
    ) -> None:
        outcome = status_family(status_code) if status_code is not None else "error"
        self.upstream_duration.record(max(0.0, duration_seconds), {"outcome": outcome})
        span.set_attribute("firewall.upstream.outcome", outcome)
        if status_code is not None:
            span.set_attribute("http.response.status_code", status_code)


def configure_observability(*, service_version: str) -> FirewallObservability:
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    explicitly_enabled = _truthy(os.getenv("OTEL_ENABLED", "false"))
    requested = explicitly_enabled or bool(endpoint)

    if requested and endpoint:
        resource = Resource.create(
            {
                "service.name": os.getenv("OTEL_SERVICE_NAME", "mcp-agent-firewall"),
                "service.version": service_version,
            }
        )

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(tracer_provider)

        metric_reader = PeriodicExportingMetricReader(OTLPMetricExporter())
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        mode = "otlp_http"
    elif requested:
        mode = "disabled_no_endpoint"
    else:
        mode = "disabled"

    return FirewallObservability(
        trace.get_tracer(INSTRUMENTATION_SCOPE, service_version),
        metrics.get_meter(INSTRUMENTATION_SCOPE, service_version),
        mode=mode,
    )

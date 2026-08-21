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
MAX_TRACE_ATTRIBUTE_CHARS = 256
_METHOD_FAMILIES = frozenset({"server", "tools", "resources", "prompts"})
_POLICY_DECISIONS = frozenset({"allow", "deny", "approval_required"})
_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
_SCHEMA_CHECKS = frozenset({"arguments", "headers"})
_SCHEMA_OUTCOMES = frozenset({"accepted", "rejected"})
_SCHEMA_PHASES = frozenset({"issue", "dispatch"})
_APPROVAL_PHASES = frozenset({"issue", "verify", "consume"})
_APPROVAL_OUTCOMES = frozenset(
    {
        "access_denied",
        "not_required",
        "schema_rejected",
        "rejected",
        "issued",
        "missing",
        "verified",
        "consumed",
        "replayed",
    }
)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bounded_label(value: str, allowed: frozenset[str]) -> str:
    return value if value in allowed else "other"


def trace_attribute(value: str | None) -> str:
    """Bound caller/config-derived trace strings without echoing control characters."""
    if not value:
        return ""
    sanitized = "".join(char if 0x20 <= ord(char) <= 0x7E else "?" for char in str(value))
    return sanitized[:MAX_TRACE_ATTRIBUTE_CHARS]


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
        # W3C TraceContext only. Caller baggage is intentionally ignored.
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
            "mcp.method": trace_attribute(method),
            "mcp.method_family": method_family(method),
            "mcp.protocol.version": trace_attribute(protocol_version),
            "mcp.request.sha256": request_sha256[:64],
            "firewall.policy.version": trace_attribute(policy_version),
            "firewall.catalog.version": trace_attribute(catalog_version),
        }
        if tool_name:
            attributes["mcp.tool.name"] = trace_attribute(tool_name)
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
        safe_attributes = {
            str(key)[:MAX_TRACE_ATTRIBUTE_CHARS]: (
                trace_attribute(value) if isinstance(value, str) else value
            )
            for key, value in (attributes or {}).items()
        }
        with self.tracer.start_as_current_span(
            name,
            kind=kind,
            attributes=safe_attributes,
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
        safe_decision = _bounded_label(decision, _POLICY_DECISIONS)
        safe_risk = _bounded_label(risk, _RISK_LEVELS)
        attributes = {
            "decision": safe_decision,
            "risk": safe_risk,
            "method_family": method_family(method),
        }
        self.policy_decisions.add(1, attributes)
        target = span or trace.get_current_span()
        target.set_attribute("firewall.decision", safe_decision)
        target.set_attribute("firewall.risk", safe_risk)

    def record_schema(
        self,
        *,
        check: str,
        outcome: str,
        phase: str,
        span: Span | None = None,
    ) -> None:
        safe_check = _bounded_label(check, _SCHEMA_CHECKS)
        safe_outcome = _bounded_label(outcome, _SCHEMA_OUTCOMES)
        safe_phase = _bounded_label(phase, _SCHEMA_PHASES)
        self.schema_validations.add(
            1,
            {"check": safe_check, "outcome": safe_outcome, "phase": safe_phase},
        )
        target = span or trace.get_current_span()
        target.set_attribute("firewall.schema.check", safe_check)
        target.set_attribute("firewall.schema.outcome", safe_outcome)
        target.set_attribute("firewall.schema.phase", safe_phase)

    def record_approval(self, *, phase: str, outcome: str, span: Span | None = None) -> None:
        safe_phase = _bounded_label(phase, _APPROVAL_PHASES)
        safe_outcome = _bounded_label(outcome, _APPROVAL_OUTCOMES)
        self.approval_events.add(1, {"phase": safe_phase, "outcome": safe_outcome})
        target = span or trace.get_current_span()
        target.set_attribute("firewall.approval.phase", safe_phase)
        target.set_attribute("firewall.approval.outcome", safe_outcome)

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
                "service.name": trace_attribute(
                    os.getenv("OTEL_SERVICE_NAME", "mcp-agent-firewall")
                ),
                "service.version": trace_attribute(service_version),
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

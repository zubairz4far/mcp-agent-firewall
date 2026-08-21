from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.metrics import Meter
from opentelemetry.propagate import extract
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, Status, StatusCode

SERVICE_NAME = "mcp-agent-firewall"
INSTRUMENTATION_NAME = "mcp-agent-firewall.telemetry"
KNOWN_METHODS = {
    "server/discover",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
}
KNOWN_DECISIONS = {"allow", "deny", "approval_required", "unknown"}
KNOWN_OUTCOMES = {
    "allowed",
    "denied",
    "approval_required",
    "approval_invalid",
    "schema_rejected",
    "rate_limited",
    "invalid_request",
    "upstream_unconfigured",
    "upstream_success",
    "upstream_error",
    "internal_error",
}
KNOWN_STAGES = {
    "transport",
    "policy",
    "schema",
    "approval",
    "upstream",
    "complete",
}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bounded(value: str | None, allowed: set[str], fallback: str = "unknown") -> str:
    if value is None:
        return fallback
    normalized = str(value).strip()
    return normalized if normalized in allowed else fallback


def metric_method(method: str | None) -> str:
    return _bounded(method, KNOWN_METHODS, "unknown")


def metric_decision(decision: str | None) -> str:
    return _bounded(decision, KNOWN_DECISIONS)


def metric_outcome(outcome: str | None) -> str:
    return _bounded(outcome, KNOWN_OUTCOMES)


def metric_stage(stage: str | None) -> str:
    return _bounded(stage, KNOWN_STAGES)


def tool_class(tool_name: str | None) -> str:
    if not tool_name:
        return "none"
    prefixes = (
        ("read_", "read"),
        ("get_", "read"),
        ("list_", "read"),
        ("inspect_", "read"),
        ("search", "read"),
        ("send_", "write"),
        ("create_", "write"),
        ("update_", "write"),
        ("delete_", "write"),
        ("purchase_", "write"),
        ("transfer_", "write"),
        ("deploy_", "write"),
        ("shell", "dangerous"),
        ("exec", "dangerous"),
        ("run_command", "dangerous"),
        ("credential_", "dangerous"),
        ("secret_", "dangerous"),
    )
    for prefix, category in prefixes:
        if tool_name == prefix or tool_name.startswith(prefix):
            return category
    return "other"


def trace_context(traceparent: str | None) -> Context | None:
    if not traceparent:
        return None
    # Only W3C trace context is extracted. Baggage from an untrusted caller is not accepted.
    return extract({"traceparent": traceparent})


@dataclass
class RequestObservation:
    span: Span
    started_at: float
    method: str
    tool_category: str


class Telemetry:
    def __init__(self) -> None:
        self.enabled = _env_bool("OTEL_ENABLED", False)
        self.endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
        self.service_name = os.getenv("OTEL_SERVICE_NAME", SERVICE_NAME).strip() or SERVICE_NAME

        self._tracer_provider: TracerProvider | None = None
        self._meter_provider: MeterProvider | None = None

        if self.enabled:
            if not self.endpoint:
                raise RuntimeError("OTEL_ENABLED requires OTEL_EXPORTER_OTLP_ENDPOINT")
            self._configure_sdk()
            self.tracer = self._tracer_provider.get_tracer(INSTRUMENTATION_NAME)
            self.meter = self._meter_provider.get_meter(INSTRUMENTATION_NAME)
        else:
            self.tracer = trace.get_tracer(INSTRUMENTATION_NAME)
            self.meter = metrics.get_meter(INSTRUMENTATION_NAME)

        self._create_instruments(self.meter)

    def _configure_sdk(self) -> None:
        resource = Resource.create(
            {
                "service.name": self.service_name,
                "service.version": "0.4.0",
            }
        )
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{self.endpoint.rstrip('/')}/v1/traces"))
        )
        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=f"{self.endpoint.rstrip('/')}/v1/metrics")
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider

    def _create_instruments(self, meter: Meter) -> None:
        self.request_count = meter.create_counter(
            "mcp.firewall.requests",
            unit="{request}",
            description="MCP requests observed by the firewall",
        )
        self.request_duration = meter.create_histogram(
            "mcp.firewall.request.duration",
            unit="s",
            description="End-to-end firewall request duration",
        )
        self.decision_count = meter.create_counter(
            "mcp.firewall.policy.decisions",
            unit="{decision}",
            description="Deterministic firewall policy decisions",
        )
        self.security_reject_count = meter.create_counter(
            "mcp.firewall.security.rejects",
            unit="{request}",
            description="Requests rejected by a firewall security stage",
        )
        self.upstream_duration = meter.create_histogram(
            "mcp.firewall.upstream.duration",
            unit="s",
            description="Latency of upstream MCP dispatches",
        )

    @contextmanager
    def request_span(
        self,
        *,
        method: str | None,
        tool_name: str | None,
        policy_version: str,
        catalog_version: str,
        traceparent: str | None = None,
    ) -> Iterator[RequestObservation]:
        metric_method_name = metric_method(method)
        category = tool_class(tool_name)
        context = trace_context(traceparent)
        attributes: dict[str, Any] = {
            "mcp.method": metric_method_name,
            "mcp.tool.class": category,
            "mcp.policy.version": policy_version,
            "mcp.catalog.version": catalog_version,
        }
        if tool_name:
            # Tool name is useful on traces but intentionally never used as a metric label.
            attributes["mcp.tool.name"] = tool_name[:256]

        with self.tracer.start_as_current_span(
            "mcp.firewall.request",
            context=context,
            attributes=attributes,
        ) as span:
            observation = RequestObservation(
                span=span,
                started_at=time.perf_counter(),
                method=metric_method_name,
                tool_category=category,
            )
            try:
                yield observation
            except Exception as exc:
                span.set_status(Status(StatusCode.ERROR, "internal_error"))
                span.set_attribute("mcp.outcome", "internal_error")
                # Record exception type only; messages may contain argument data.
                span.set_attribute("error.type", type(exc).__name__[:120])
                self.finish(observation, outcome="internal_error")
                raise

    def record_decision(self, observation: RequestObservation, decision: str) -> None:
        bounded = metric_decision(decision)
        observation.span.set_attribute("mcp.policy.decision", bounded)
        self.decision_count.add(
            1,
            {
                "mcp.method": observation.method,
                "mcp.tool.class": observation.tool_category,
                "mcp.policy.decision": bounded,
            },
        )

    def reject(self, observation: RequestObservation, *, stage: str, outcome: str) -> None:
        bounded_stage = metric_stage(stage)
        bounded_outcome = metric_outcome(outcome)
        observation.span.set_attribute("mcp.security.stage", bounded_stage)
        observation.span.set_attribute("mcp.outcome", bounded_outcome)
        observation.span.set_status(Status(StatusCode.ERROR, bounded_outcome))
        self.security_reject_count.add(
            1,
            {
                "mcp.method": observation.method,
                "mcp.tool.class": observation.tool_category,
                "mcp.security.stage": bounded_stage,
                "mcp.outcome": bounded_outcome,
            },
        )

    def record_upstream(
        self,
        observation: RequestObservation,
        *,
        duration_seconds: float,
        status_code: int,
    ) -> None:
        status_class = f"{status_code // 100}xx" if 100 <= status_code <= 599 else "other"
        outcome = "upstream_success" if 200 <= status_code < 400 else "upstream_error"
        observation.span.set_attribute("http.response.status_code", status_code)
        observation.span.set_attribute("mcp.upstream.outcome", outcome)
        self.upstream_duration.record(
            max(duration_seconds, 0.0),
            {
                "mcp.method": observation.method,
                "mcp.tool.class": observation.tool_category,
                "http.response.status_class": status_class,
            },
        )

    def finish(self, observation: RequestObservation, *, outcome: str) -> None:
        bounded_outcome = metric_outcome(outcome)
        duration = max(time.perf_counter() - observation.started_at, 0.0)
        observation.span.set_attribute("mcp.outcome", bounded_outcome)
        if bounded_outcome in {"allowed", "upstream_success"}:
            observation.span.set_status(Status(StatusCode.OK))
        self.request_count.add(
            1,
            {
                "mcp.method": observation.method,
                "mcp.tool.class": observation.tool_category,
                "mcp.outcome": bounded_outcome,
            },
        )
        self.request_duration.record(
            duration,
            {
                "mcp.method": observation.method,
                "mcp.tool.class": observation.tool_category,
                "mcp.outcome": bounded_outcome,
            },
        )


telemetry = Telemetry()

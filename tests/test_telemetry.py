from __future__ import annotations

import pytest
from opentelemetry.trace import get_current_span

from app.telemetry import (
    Telemetry,
    metric_decision,
    metric_method,
    metric_outcome,
    metric_stage,
    tool_class,
    trace_context,
)


def test_known_mcp_method_is_preserved_for_metrics():
    assert metric_method("tools/call") == "tools/call"


def test_untrusted_mcp_method_is_collapsed_for_metrics():
    assert metric_method("tools/call/tenant-123456") == "unknown"


def test_untrusted_decision_is_collapsed_for_metrics():
    assert metric_decision("allow-user-secret-value") == "unknown"


def test_untrusted_outcome_is_collapsed_for_metrics():
    assert metric_outcome("database-password-is-here") == "unknown"


def test_untrusted_stage_is_collapsed_for_metrics():
    assert metric_stage("customer-specific-stage-991") == "unknown"


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("read_document", "read"),
        ("get_user", "read"),
        ("search", "read"),
        ("delete_file", "write"),
        ("transfer_money", "write"),
        ("shell", "dangerous"),
        ("credential_export", "dangerous"),
        ("customer_tool_739187", "other"),
        (None, "none"),
    ],
)
def test_tool_names_collapse_to_bounded_metric_classes(tool_name: str | None, expected: str):
    assert tool_class(tool_name) == expected


def test_valid_w3c_traceparent_is_extracted():
    context = trace_context("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    assert context is not None
    span_context = get_current_span(context).get_span_context()
    assert span_context.is_valid
    assert span_context.is_remote


def test_malformed_traceparent_does_not_create_valid_parent():
    context = trace_context("secret-user-input-not-a-traceparent")
    assert context is not None
    assert not get_current_span(context).get_span_context().is_valid


def test_telemetry_disabled_does_not_require_endpoint(monkeypatch):
    monkeypatch.setenv("OTEL_ENABLED", "false")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    instance = Telemetry()
    assert instance.enabled is False


def test_telemetry_enabled_requires_explicit_endpoint(monkeypatch):
    monkeypatch.setenv("OTEL_ENABLED", "true")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    with pytest.raises(RuntimeError, match="OTEL_EXPORTER_OTLP_ENDPOINT"):
        Telemetry()


def test_disabled_request_span_accepts_no_raw_arguments(monkeypatch):
    monkeypatch.setenv("OTEL_ENABLED", "false")
    instance = Telemetry()
    with instance.request_span(
        method="tools/call",
        tool_name="read_document",
        policy_version="0.1",
        catalog_version="test",
    ) as observation:
        instance.record_decision(observation, "allow")
        instance.finish(observation, outcome="upstream_success")

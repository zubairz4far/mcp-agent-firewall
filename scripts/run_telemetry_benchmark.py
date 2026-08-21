from __future__ import annotations

import json

from app.telemetry import metric_decision, metric_method, metric_outcome, metric_stage, tool_class


def main() -> int:
    cases = [
        ("known_method", metric_method("tools/call") == "tools/call"),
        ("unknown_method_collapsed", metric_method("tools/call/customer-9281") == "unknown"),
        ("decision_secret_collapsed", metric_decision("allow-secret-token") == "unknown"),
        ("outcome_secret_collapsed", metric_outcome("customer@example.com") == "unknown"),
        ("stage_secret_collapsed", metric_stage("tenant-445") == "unknown"),
        ("read_tool_class", tool_class("read_document") == "read"),
        ("write_tool_class", tool_class("delete_file") == "write"),
        ("dangerous_tool_class", tool_class("credential_export") == "dangerous"),
        ("unknown_tool_collapsed", tool_class("tenant_specific_tool_111") == "other"),
        ("missing_tool_collapsed", tool_class(None) == "none"),
    ]
    passed = sum(1 for _, ok in cases if ok)
    summary = {
        "suite": "telemetry_privacy_v1",
        "cases": len(cases),
        "passed": passed,
        "unsafe_false_accepts": len(cases) - passed,
        "details": [{"id": case_id, "ok": ok} for case_id, ok in cases],
        "note": "Synthetic low-cardinality/privacy regression suite; not a production observability claim.",
    }
    print(json.dumps(summary, indent=2))
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())

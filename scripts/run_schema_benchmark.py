from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from pathlib import Path

from app.policy import canonical_payload
from app.tool_catalog import ToolCatalogError, TrustedToolCatalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "config" / "trusted_tools.example.json"
CATALOG_PIN = (ROOT / "config" / "trusted_tools.example.sha256").read_text().strip()


def rejected(callback) -> bool:
    try:
        callback()
    except ToolCatalogError:
        return True
    return False


def temporary_catalog(schema: dict) -> tuple[tempfile.TemporaryDirectory, Path, str]:
    tmp = tempfile.TemporaryDirectory()
    document = {
        "catalog_version": "benchmark",
        "protocol_version": "2026-07-28",
        "tools": [{"name": "benchmark_tool", "inputSchema": schema}],
    }
    path = Path(tmp.name) / "catalog.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    digest = hashlib.sha256(canonical_payload(document)).hexdigest()
    return tmp, path, digest


def main() -> int:
    catalog = TrustedToolCatalog.load(CATALOG_PATH, expected_sha256=CATALOG_PIN)
    cases: list[tuple[str, bool, bool]] = []

    valid_args = {"region": "us-west1", "window_minutes": 15}
    cases.append(
        (
            "valid_schema_and_header",
            not rejected(
                lambda: (
                    catalog.validate_arguments("read_metrics", valid_args),
                    catalog.validate_mcp_param_headers(
                        "read_metrics",
                        valid_args,
                        [(b"mcp-param-region", b"us-west1")],
                    ),
                )
            ),
            False,
        )
    )
    cases.append(
        (
            "missing_required_mirror_rejected",
            rejected(
                lambda: catalog.validate_mcp_param_headers("read_metrics", valid_args, [])
            ),
            True,
        )
    )
    cases.append(
        (
            "header_body_mismatch_rejected",
            rejected(
                lambda: catalog.validate_mcp_param_headers(
                    "read_metrics",
                    valid_args,
                    [(b"mcp-param-region", b"eu-west1")],
                )
            ),
            True,
        )
    )
    cases.append(
        (
            "schema_extra_argument_rejected",
            rejected(
                lambda: catalog.validate_arguments(
                    "read_metrics",
                    {"region": "us-west1", "extra": True},
                )
            ),
            True,
        )
    )
    cases.append(
        (
            "unpinned_tool_rejected",
            rejected(lambda: catalog.validate_arguments("read_unpinned", {})),
            True,
        )
    )
    cases.append(
        (
            "nested_header_binding_valid",
            not rejected(
                lambda: catalog.validate_mcp_param_headers(
                    "get_user",
                    {"id": "u1", "context": {"tenant": "acme"}},
                    [(b"mcp-param-tenant", b"acme")],
                )
            ),
            False,
        )
    )
    unicode_value = "東京"
    encoded = base64.b64encode(unicode_value.encode()).decode()
    cases.append(
        (
            "base64_unicode_header_valid",
            not rejected(
                lambda: catalog.validate_mcp_param_headers(
                    "search",
                    {"q": "x", "region": unicode_value},
                    [(b"mcp-param-region", f"=?base64?{encoded}?=".encode())],
                )
            ),
            False,
        )
    )
    cases.append(
        (
            "malformed_base64_rejected",
            rejected(
                lambda: catalog.validate_mcp_param_headers(
                    "search",
                    {"q": "x", "region": "value"},
                    [(b"mcp-param-region", b"=?base64?%%%?=")],
                )
            ),
            True,
        )
    )
    cases.append(
        (
            "wrong_catalog_pin_rejected",
            rejected(lambda: TrustedToolCatalog.load(CATALOG_PATH, expected_sha256="0" * 64)),
            True,
        )
    )

    tmp_external, path_external, digest_external = temporary_catalog(
        {
            "type": "object",
            "properties": {"x": {"$ref": "https://example.com/external.json"}},
        }
    )
    try:
        cases.append(
            (
                "external_ref_rejected",
                rejected(
                    lambda: TrustedToolCatalog.load(
                        path_external,
                        expected_sha256=digest_external,
                    )
                ),
                True,
            )
        )
    finally:
        tmp_external.cleanup()

    tmp_number, path_number, digest_number = temporary_catalog(
        {
            "type": "object",
            "properties": {"amount": {"type": "number", "x-mcp-header": "Amount"}},
        }
    )
    try:
        cases.append(
            (
                "number_header_binding_rejected",
                rejected(
                    lambda: TrustedToolCatalog.load(path_number, expected_sha256=digest_number)
                ),
                True,
            )
        )
    finally:
        tmp_number.cleanup()

    tmp_comp, path_comp, digest_comp = temporary_catalog(
        {
            "type": "object",
            "properties": {
                "region": {"allOf": [{"type": "string", "x-mcp-header": "Region"}]}
            },
        }
    )
    try:
        cases.append(
            (
                "non_static_header_binding_rejected",
                rejected(lambda: TrustedToolCatalog.load(path_comp, expected_sha256=digest_comp)),
                True,
            )
        )
    finally:
        tmp_comp.cleanup()

    passed = sum(int(ok) for _, ok, _ in cases)
    unsafe_false_accepts = sum(int(not ok and security_case) for _, ok, security_case in cases)
    false_blocks = sum(int(not ok and not security_case) for _, ok, security_case in cases)
    report = {
        "cases": len(cases),
        "passed": passed,
        "exact_security_decision_accuracy": passed / len(cases),
        "unsafe_false_accepts": unsafe_false_accepts,
        "false_blocks": false_blocks,
        "details": [{"id": case_id, "ok": ok} for case_id, ok, _ in cases],
    }
    print(json.dumps(report, indent=2))
    return 0 if passed == len(cases) and unsafe_false_accepts == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

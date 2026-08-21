import base64
import hashlib
import json
from pathlib import Path

import pytest

from app.policy import canonical_payload
from app.tool_catalog import ToolCatalogError, TrustedToolCatalog, decode_mcp_header_value

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "config" / "trusted_tools.example.json"
CATALOG_PIN = (ROOT / "config" / "trusted_tools.example.sha256").read_text().strip()


def write_catalog(tmp_path: Path, tool_schema: dict) -> tuple[Path, str]:
    document = {
        "catalog_version": "test-v1",
        "protocol_version": "2026-07-28",
        "tools": [{"name": "test_tool", "inputSchema": tool_schema}],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    digest = hashlib.sha256(canonical_payload(document)).hexdigest()
    return path, digest


def test_example_catalog_matches_committed_pin():
    catalog = TrustedToolCatalog.load(CATALOG_PATH, expected_sha256=CATALOG_PIN)
    assert catalog.catalog_version == "2026-08-21.v1"
    assert catalog.digest == CATALOG_PIN


def test_wrong_catalog_pin_is_rejected():
    with pytest.raises(ToolCatalogError) as exc_info:
        TrustedToolCatalog.load(CATALOG_PATH, expected_sha256="0" * 64)
    assert exc_info.value.code == "trusted_catalog_pin_mismatch"


def test_external_schema_ref_is_rejected(tmp_path: Path):
    path, digest = write_catalog(
        tmp_path,
        {"type": "object", "properties": {"x": {"$ref": "https://example.com/schema.json"}}},
    )
    with pytest.raises(ToolCatalogError) as exc_info:
        TrustedToolCatalog.load(path, expected_sha256=digest)
    assert exc_info.value.code == "trusted_schema_external_ref_forbidden"


def test_x_mcp_header_number_type_is_rejected(tmp_path: Path):
    path, digest = write_catalog(
        tmp_path,
        {
            "type": "object",
            "properties": {"amount": {"type": "number", "x-mcp-header": "Amount"}},
        },
    )
    with pytest.raises(ToolCatalogError) as exc_info:
        TrustedToolCatalog.load(path, expected_sha256=digest)
    assert exc_info.value.code == "x_mcp_header_type_invalid"


def test_x_mcp_header_inside_composition_is_rejected(tmp_path: Path):
    path, digest = write_catalog(
        tmp_path,
        {
            "type": "object",
            "properties": {
                "region": {
                    "allOf": [{"type": "string", "x-mcp-header": "Region"}],
                }
            },
        },
    )
    with pytest.raises(ToolCatalogError) as exc_info:
        TrustedToolCatalog.load(path, expected_sha256=digest)
    assert exc_info.value.code == "x_mcp_header_not_statically_reachable"


def test_x_mcp_header_names_are_case_insensitively_unique(tmp_path: Path):
    path, digest = write_catalog(
        tmp_path,
        {
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "other": {"type": "string", "x-mcp-header": "region"},
            },
        },
    )
    with pytest.raises(ToolCatalogError) as exc_info:
        TrustedToolCatalog.load(path, expected_sha256=digest)
    assert exc_info.value.code == "x_mcp_header_name_duplicate"


def test_arguments_must_match_pinned_schema():
    catalog = TrustedToolCatalog.load(CATALOG_PATH, expected_sha256=CATALOG_PIN)
    with pytest.raises(ToolCatalogError) as exc_info:
        catalog.validate_arguments("read_metrics", {"region": "us-west1", "extra": True})
    assert exc_info.value.code == "tool_arguments_schema_invalid"


def test_policy_pattern_does_not_make_unpinned_tool_trusted():
    catalog = TrustedToolCatalog.load(CATALOG_PATH, expected_sha256=CATALOG_PIN)
    with pytest.raises(ToolCatalogError) as exc_info:
        catalog.validate_arguments("read_unpinned", {})
    assert exc_info.value.code == "tool_not_in_trusted_catalog"


def test_required_mcp_param_header_must_match_body():
    catalog = TrustedToolCatalog.load(CATALOG_PATH, expected_sha256=CATALOG_PIN)
    arguments = {"region": "us-west1", "window_minutes": 15}
    catalog.validate_arguments("read_metrics", arguments)
    forwarded = catalog.validate_mcp_param_headers(
        "read_metrics",
        arguments,
        [(b"mcp-param-region", b"us-west1")],
    )
    assert forwarded == [("mcp-param-region", "us-west1")]


def test_missing_mcp_param_header_is_rejected():
    catalog = TrustedToolCatalog.load(CATALOG_PATH, expected_sha256=CATALOG_PIN)
    arguments = {"region": "us-west1"}
    with pytest.raises(ToolCatalogError) as exc_info:
        catalog.validate_mcp_param_headers("read_metrics", arguments, [])
    assert exc_info.value.code == "mcp_param_missing"


def test_nested_mcp_param_header_is_extracted_by_property_path():
    catalog = TrustedToolCatalog.load(CATALOG_PATH, expected_sha256=CATALOG_PIN)
    arguments = {"id": "u1", "context": {"tenant": "acme"}}
    catalog.validate_mcp_param_headers(
        "get_user",
        arguments,
        [(b"mcp-param-tenant", b"acme")],
    )


def test_base64_sentinel_decodes_utf8_and_literal_sentinel_requires_encoding():
    encoded_unicode = "=?base64?" + base64.b64encode("東京".encode()).decode() + "?="
    assert decode_mcp_header_value(encoded_unicode) == "東京"

    literal = "=?base64?literal?="
    encoded_literal = "=?base64?" + base64.b64encode(literal.encode()).decode() + "?="
    assert decode_mcp_header_value(encoded_literal) == literal


def test_integer_header_comparison_is_numeric(tmp_path: Path):
    path, digest = write_catalog(
        tmp_path,
        {
            "type": "object",
            "properties": {
                "count": {"type": "integer", "x-mcp-header": "Count"},
            },
            "required": ["count"],
            "additionalProperties": False,
        },
    )
    catalog = TrustedToolCatalog.load(path, expected_sha256=digest)
    catalog.validate_arguments("test_tool", {"count": 42})
    catalog.validate_mcp_param_headers(
        "test_tool",
        {"count": 42},
        [(b"mcp-param-count", b"42.0")],
    )

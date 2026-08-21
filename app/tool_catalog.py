from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from app.policy import canonical_payload

MAX_SAFE_INTEGER = (2**53) - 1
MAX_CATALOG_TOOLS = 256
MAX_SCHEMA_DEPTH = 32
MAX_SCHEMA_NODES = 5000
MAX_MCP_PARAM_HEADERS = 64
MAX_MCP_PARAM_VALUE_BYTES = 8192
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class ToolCatalogError(ValueError):
    def __init__(self, code: str, *, path: str | None = None, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.path = path
        self.detail = detail

    def data(self) -> dict[str, str]:
        result = {"catalog_error": self.code}
        if self.path:
            result["path"] = self.path
        if self.detail:
            result["detail"] = self.detail
        return result


@dataclass(frozen=True)
class HeaderBinding:
    path: tuple[str, ...]
    name: str
    value_type: str


@dataclass(frozen=True)
class ToolContract:
    name: str
    input_schema: dict[str, Any]
    header_bindings: tuple[HeaderBinding, ...]
    validator: Draft202012Validator


def _json_without_duplicate_keys(raw: str) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ToolCatalogError("trusted_catalog_duplicate_key", path=key)
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=hook)
    except ToolCatalogError:
        raise
    except json.JSONDecodeError as exc:
        raise ToolCatalogError("trusted_catalog_invalid_json") from exc
    if not isinstance(parsed, dict):
        raise ToolCatalogError("trusted_catalog_root_must_be_object")
    return parsed


def _validate_schema_safety(schema: dict[str, Any]) -> None:
    node_count = 0

    def walk(value: Any, depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_SCHEMA_NODES:
            raise ToolCatalogError("trusted_schema_too_large")
        if depth > MAX_SCHEMA_DEPTH:
            raise ToolCatalogError("trusted_schema_too_deep")
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"$ref", "$dynamicRef"} and (
                    not isinstance(child, str) or not child.startswith("#")
                ):
                    raise ToolCatalogError("trusted_schema_external_ref_forbidden")
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)

    walk(schema, 0)

    if schema.get("type") != "object":
        raise ToolCatalogError("trusted_schema_root_must_be_object")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ToolCatalogError("trusted_schema_invalid") from exc


def _collect_header_bindings(schema: dict[str, Any]) -> tuple[HeaderBinding, ...]:
    bindings: list[HeaderBinding] = []
    seen_names: set[str] = set()

    def visit(value: Any, static_prefix: tuple[str, ...] | None, is_property: bool) -> None:
        if isinstance(value, list):
            for child in value:
                visit(child, None, False)
            return
        if not isinstance(value, dict):
            return

        if "x-mcp-header" in value:
            if not is_property or static_prefix is None:
                raise ToolCatalogError("x_mcp_header_not_statically_reachable")
            header_name = value["x-mcp-header"]
            if not isinstance(header_name, str) or not header_name or not _HEADER_TOKEN.fullmatch(
                header_name
            ):
                raise ToolCatalogError("x_mcp_header_name_invalid", path=".".join(static_prefix))
            value_type = value.get("type")
            if value_type not in {"string", "integer", "boolean"}:
                raise ToolCatalogError("x_mcp_header_type_invalid", path=".".join(static_prefix))
            normalized = header_name.lower()
            if normalized in seen_names:
                raise ToolCatalogError("x_mcp_header_name_duplicate", detail=header_name)
            seen_names.add(normalized)
            bindings.append(
                HeaderBinding(path=static_prefix, name=header_name, value_type=value_type)
            )

        properties = value.get("properties")
        if isinstance(properties, dict) and static_prefix is not None:
            for property_name, child in properties.items():
                visit(child, (*static_prefix, str(property_name)), True)

        for key, child in value.items():
            if key in {"properties", "x-mcp-header"}:
                continue
            if isinstance(child, (dict, list)):
                visit(child, None, False)

    visit(schema, (), False)
    return tuple(bindings)


def decode_mcp_header_value(value: str) -> str:
    if value.startswith("=?base64?") and value.endswith("?="):
        encoded = value[len("=?base64?") : -2]
        try:
            decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
            return decoded.decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error) as exc:
            raise ToolCatalogError("mcp_header_base64_invalid") from exc

    if value[:1] in {" ", "\t"} or value[-1:] in {" ", "\t"}:
        raise ToolCatalogError("mcp_header_plain_whitespace_invalid")
    if any(ord(char) != 9 and not 0x20 <= ord(char) <= 0x7E for char in value):
        raise ToolCatalogError("mcp_header_plain_value_invalid")
    return value


def _extract_path(arguments: dict[str, Any], path: tuple[str, ...]) -> tuple[bool, Any]:
    current: Any = arguments
    for segment in path:
        if not isinstance(current, dict) or segment not in current:
            return False, None
        current = current[segment]
    return True, current


def _header_matches(binding: HeaderBinding, decoded: str, value: Any) -> bool:
    if binding.value_type == "string":
        return isinstance(value, str) and decoded == value
    if binding.value_type == "boolean":
        return isinstance(value, bool) and decoded == ("true" if value else "false")
    if binding.value_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int) or abs(value) > MAX_SAFE_INTEGER:
            return False
        try:
            parsed = Decimal(decoded)
        except InvalidOperation:
            return False
        return parsed.is_finite() and parsed == Decimal(value)
    return False


class TrustedToolCatalog:
    def __init__(
        self,
        *,
        catalog_version: str,
        protocol_version: str,
        digest: str,
        contracts: dict[str, ToolContract],
    ):
        self.catalog_version = catalog_version
        self.protocol_version = protocol_version
        self.digest = digest
        self._contracts = contracts

    @classmethod
    def load(cls, path: str | Path, *, expected_sha256: str) -> TrustedToolCatalog:
        if not expected_sha256 or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise ToolCatalogError("trusted_catalog_pin_required")
        raw = Path(path).read_text(encoding="utf-8")
        document = _json_without_duplicate_keys(raw)
        digest = hashlib.sha256(canonical_payload(document)).hexdigest()
        if not hmac.compare_digest(digest, expected_sha256.lower()):
            raise ToolCatalogError("trusted_catalog_pin_mismatch")

        catalog_version = document.get("catalog_version")
        protocol_version = document.get("protocol_version")
        tools = document.get("tools")
        if not isinstance(catalog_version, str) or not catalog_version:
            raise ToolCatalogError("trusted_catalog_version_invalid")
        if not isinstance(protocol_version, str) or not protocol_version:
            raise ToolCatalogError("trusted_catalog_protocol_invalid")
        if not isinstance(tools, list) or not tools or len(tools) > MAX_CATALOG_TOOLS:
            raise ToolCatalogError("trusted_catalog_tools_invalid")

        contracts: dict[str, ToolContract] = {}
        for tool in tools:
            if not isinstance(tool, dict):
                raise ToolCatalogError("trusted_tool_definition_invalid")
            name = tool.get("name")
            schema = tool.get("inputSchema")
            if not isinstance(name, str) or not name or len(name) > 256:
                raise ToolCatalogError("trusted_tool_name_invalid")
            if name in contracts:
                raise ToolCatalogError("trusted_tool_name_duplicate", detail=name)
            if not isinstance(schema, dict):
                raise ToolCatalogError("trusted_tool_schema_missing", detail=name)
            _validate_schema_safety(schema)
            bindings = _collect_header_bindings(schema)
            contracts[name] = ToolContract(
                name=name,
                input_schema=schema,
                header_bindings=bindings,
                validator=Draft202012Validator(schema),
            )

        return cls(
            catalog_version=catalog_version,
            protocol_version=protocol_version,
            digest=digest,
            contracts=contracts,
        )

    def contract(self, tool_name: str) -> ToolContract:
        contract = self._contracts.get(tool_name)
        if contract is None:
            raise ToolCatalogError("tool_not_in_trusted_catalog", detail=tool_name)
        return contract

    def validate_arguments(self, tool_name: str, arguments: dict[str, Any]) -> ToolContract:
        contract = self.contract(tool_name)
        try:
            errors = sorted(
                contract.validator.iter_errors(arguments),
                key=lambda error: tuple(str(part) for part in error.absolute_path),
            )
        except Exception as exc:
            raise ToolCatalogError("trusted_schema_runtime_error", detail=tool_name) from exc
        if errors:
            error = errors[0]
            path = ".".join(str(part) for part in error.absolute_path) or "$"
            raise ToolCatalogError(
                "tool_arguments_schema_invalid",
                path=path,
                detail=str(error.validator),
            )
        return contract

    def validate_mcp_param_headers(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        raw_headers: Iterable[tuple[bytes, bytes]],
    ) -> list[tuple[str, str]]:
        contract = self.contract(tool_name)
        custom_headers: list[tuple[str, str]] = []
        by_name: dict[str, list[str]] = {}

        for raw_name, raw_value in raw_headers:
            name = raw_name.decode("latin-1")
            if not name.lower().startswith("mcp-param-"):
                continue
            if (
                len(custom_headers) >= MAX_MCP_PARAM_HEADERS
                or len(raw_value) > MAX_MCP_PARAM_VALUE_BYTES
            ):
                raise ToolCatalogError("mcp_param_headers_too_large")
            value = raw_value.decode("latin-1")
            custom_headers.append((name, value))
            by_name.setdefault(name.lower(), []).append(value)

        for binding in contract.header_bindings:
            normalized_name = f"mcp-param-{binding.name}".lower()
            supplied = by_name.get(normalized_name, [])
            present, body_value = _extract_path(arguments, binding.path)
            if not present or body_value is None:
                if supplied:
                    raise ToolCatalogError(
                        "mcp_param_unexpected",
                        path=".".join(binding.path),
                        detail=binding.name,
                    )
                continue
            if len(supplied) != 1:
                code = "mcp_param_missing" if not supplied else "mcp_param_duplicate"
                raise ToolCatalogError(code, path=".".join(binding.path), detail=binding.name)
            try:
                decoded = decode_mcp_header_value(supplied[0])
            except ToolCatalogError as exc:
                raise ToolCatalogError(
                    "mcp_param_malformed",
                    path=".".join(binding.path),
                    detail=binding.name,
                ) from exc
            if not _header_matches(binding, decoded, body_value):
                raise ToolCatalogError(
                    "mcp_param_body_mismatch",
                    path=".".join(binding.path),
                    detail=binding.name,
                )

        return custom_headers

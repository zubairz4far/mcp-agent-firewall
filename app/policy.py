from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.models import Decision, EvaluationInput, EvaluationResult, RiskLevel


@dataclass(frozen=True)
class PolicyConfig:
    version: str
    protocol_version: str
    default_decision: Decision
    allowed_methods: tuple[str, ...]
    allow_tools: tuple[str, ...]
    approval_tools: tuple[str, ...]
    deny_tools: tuple[str, ...]
    denied_argument_keys: tuple[str, ...]
    denied_path_patterns: tuple[str, ...]
    max_string_length: int
    amount_limit: float
    injection_fields: tuple[str, ...]
    injection_patterns: tuple[str, ...]

    @classmethod
    def load(cls, path: str | Path) -> PolicyConfig:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        args = data.get("argument_constraints", {})
        injection = data.get("injection_signals", {})
        tools = data.get("tools", {})
        return cls(
            version=str(data.get("version", "1")),
            protocol_version=str(data.get("protocol_version", "2026-07-28")),
            default_decision=Decision(data.get("default_decision", "deny")),
            allowed_methods=tuple(data.get("allowed_methods", [])),
            allow_tools=tuple(tools.get("allow", [])),
            approval_tools=tuple(tools.get("require_approval", [])),
            deny_tools=tuple(tools.get("deny", [])),
            denied_argument_keys=tuple(k.lower() for k in args.get("denied_keys", [])),
            denied_path_patterns=tuple(args.get("denied_path_patterns", [])),
            max_string_length=int(args.get("max_string_length", 5000)),
            amount_limit=float(args.get("max_numeric", {}).get("amount", 1000)),
            injection_fields=tuple(k.lower() for k in injection.get("untrusted_fields", [])),
            injection_patterns=tuple(injection.get("patterns", [])),
        )


class PolicyEngine:
    def __init__(self, policy: PolicyConfig):
        self.policy = policy

    def evaluate(self, request: EvaluationInput) -> EvaluationResult:
        reasons: list[str] = []
        signals: list[str] = []
        risk = RiskLevel.LOW

        body_method = request.body.method
        params = request.body.params
        body_name = params.get("name") if isinstance(params, dict) else None
        tool_name = request.mcp_name or (body_name if isinstance(body_name, str) else None)

        if request.protocol_version != self.policy.protocol_version:
            return self._deny(
                request,
                tool_name,
                "unsupported_protocol_version",
                RiskLevel.HIGH,
            )

        if request.mcp_method != body_method:
            return self._deny(
                request,
                tool_name,
                "mcp_method_header_body_mismatch",
                RiskLevel.CRITICAL,
            )

        if body_method == "tools/call":
            if not isinstance(body_name, str) or not body_name:
                return self._deny(request, tool_name, "missing_tool_name", RiskLevel.HIGH)
            if request.mcp_name != body_name:
                return self._deny(
                    request,
                    tool_name,
                    "mcp_name_header_body_mismatch",
                    RiskLevel.CRITICAL,
                )

        if body_method not in self.policy.allowed_methods:
            return self._deny(request, tool_name, "method_not_allowed", RiskLevel.HIGH)

        if body_method != "tools/call":
            return EvaluationResult(
                decision=Decision.ALLOW,
                risk=RiskLevel.LOW,
                reasons=["non_tool_method_allowed"],
                signals=[],
                tool_name=tool_name,
                method=body_method,
                requires_human_approval=False,
                policy_version=self.policy.version,
            )

        assert tool_name is not None
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return self._deny(request, tool_name, "tool_arguments_must_be_object", RiskLevel.HIGH)

        if self._matches(tool_name, self.policy.deny_tools):
            return self._deny(request, tool_name, "tool_explicitly_denied", RiskLevel.CRITICAL)

        arg_findings = self._inspect_arguments(arguments)
        signals.extend(arg_findings["signals"])
        if arg_findings["deny_reasons"]:
            return EvaluationResult(
                decision=Decision.DENY,
                risk=RiskLevel.CRITICAL,
                reasons=arg_findings["deny_reasons"],
                signals=signals,
                tool_name=tool_name,
                method=body_method,
                requires_human_approval=False,
                policy_version=self.policy.version,
            )

        approval_tool = self._matches(tool_name, self.policy.approval_tools)
        allow_tool = self._matches(tool_name, self.policy.allow_tools)
        if approval_tool:
            reasons.append("consequential_tool_requires_human_approval")
            risk = RiskLevel.HIGH
        elif not allow_tool:
            if self.policy.default_decision == Decision.DENY:
                return self._deny(request, tool_name, "tool_not_allowlisted", RiskLevel.HIGH)
            reasons.append("default_policy_applied")

        if arg_findings["approval_reasons"]:
            reasons.extend(arg_findings["approval_reasons"])
            risk = RiskLevel.HIGH

        if approval_tool or arg_findings["approval_reasons"]:
            return EvaluationResult(
                decision=Decision.APPROVAL_REQUIRED,
                risk=risk,
                reasons=reasons,
                signals=signals,
                tool_name=tool_name,
                method=body_method,
                requires_human_approval=True,
                policy_version=self.policy.version,
            )

        return EvaluationResult(
            decision=Decision.ALLOW,
            risk=RiskLevel.MEDIUM if signals else RiskLevel.LOW,
            reasons=["tool_allowlisted"],
            signals=signals,
            tool_name=tool_name,
            method=body_method,
            requires_human_approval=False,
            policy_version=self.policy.version,
        )

    def _inspect_arguments(self, arguments: dict[str, Any]) -> dict[str, list[str]]:
        deny_reasons: list[str] = []
        approval_reasons: list[str] = []
        signals: list[str] = []

        def walk(value: Any, path: tuple[str, ...] = ()) -> None:
            key = path[-1].lower() if path else ""
            if key in self.policy.denied_argument_keys:
                deny_reasons.append(f"sensitive_argument_key:{'.'.join(path)}")

            if isinstance(value, dict):
                for child_key, child in value.items():
                    walk(child, (*path, str(child_key)))
                return
            if isinstance(value, list):
                for idx, child in enumerate(value):
                    walk(child, (*path, str(idx)))
                return
            if isinstance(value, str):
                if len(value) > self.policy.max_string_length:
                    deny_reasons.append(f"oversized_string:{'.'.join(path)}")
                normalized = value.strip().lower()
                if any(
                    fnmatch.fnmatchcase(normalized, pattern.lower())
                    for pattern in self.policy.denied_path_patterns
                ):
                    deny_reasons.append(f"protected_path:{'.'.join(path)}")
                if key in self.policy.injection_fields and self._looks_like_injection(value):
                    signals.append(f"prompt_injection_signal:{'.'.join(path)}")
            if (
                key == "amount"
                and isinstance(value, (int, float))
                and not isinstance(value, bool)
                and float(value) > self.policy.amount_limit
            ):
                approval_reasons.append("amount_exceeds_auto_approval_limit")

        walk(arguments)
        return {
            "deny_reasons": sorted(set(deny_reasons)),
            "approval_reasons": sorted(set(approval_reasons)),
            "signals": sorted(set(signals)),
        }

    def _looks_like_injection(self, value: str) -> bool:
        return any(
            re.search(pattern, value, flags=re.IGNORECASE)
            for pattern in self.policy.injection_patterns
        )

    @staticmethod
    def _matches(name: str, patterns: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)

    def _deny(
        self,
        request: EvaluationInput,
        tool_name: str | None,
        reason: str,
        risk: RiskLevel,
    ) -> EvaluationResult:
        return EvaluationResult(
            decision=Decision.DENY,
            risk=risk,
            reasons=[reason],
            signals=[],
            tool_name=tool_name,
            method=request.body.method,
            requires_human_approval=False,
            policy_version=self.policy.version,
        )


def canonical_payload(body: dict[str, Any]) -> bytes:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return payload.encode("utf-8")

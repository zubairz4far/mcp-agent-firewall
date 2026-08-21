from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class OutputAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class OutputInspection:
    action: OutputAction
    signals: tuple[str, ...]
    inspected_bytes: int
    untrusted: bool = True

    @property
    def flagged(self) -> bool:
        return bool(self.signals)

    def public_data(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "signals": list(self.signals),
            "inspected_bytes": self.inspected_bytes,
            "untrusted": self.untrusted,
        }


SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "session_token",
        "api_key",
        "apikey",
        "private_key",
        "cookie",
        "set_cookie",
    }
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_credential", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    (
        "jwt_credential",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
)

PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"),
    re.compile(r"(?i)ignore\s+(?:the\s+)?(?:system|developer)\s+(?:message|prompt|instructions)"),
    re.compile(r"(?i)reveal\s+(?:the\s+)?(?:system|developer)\s+(?:message|prompt)"),
    re.compile(r"(?i)do\s+not\s+(?:tell|show|inform)\s+(?:the\s+)?user"),
    re.compile(r"(?i)(?:exfiltrate|upload|send)\b.{0,48}\b(?:secret|token|password|credential)s?\b"),
)

MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 10_000


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def _has_value(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def _text_signals(text: str) -> set[str]:
    signals: set[str] = set()
    for signal, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            signals.add(signal)
    if any(pattern.search(text) for pattern in PROMPT_INJECTION_PATTERNS):
        signals.add("prompt_injection_signal")
    return signals


def _walk_json(value: Any) -> tuple[set[str], bool]:
    signals: set[str] = set()
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0

    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return signals | {"inspection_limit_exceeded"}, False

        if isinstance(current, dict):
            for key, child in current.items():
                normalized = _normalized_key(str(key))
                if normalized in SENSITIVE_KEYS and _has_value(child):
                    signals.add("sensitive_key")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            signals.update(_text_signals(current))

    return signals, True


class OutputContainment:
    def __init__(self, max_response_bytes: int = 262_144):
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        self.max_response_bytes = max_response_bytes

    def inspect(self, content: bytes, content_type: str | None) -> OutputInspection:
        size = len(content)
        if size > self.max_response_bytes:
            return OutputInspection(
                action=OutputAction.BLOCK,
                signals=("response_too_large",),
                inspected_bytes=self.max_response_bytes,
            )
        if not content:
            return OutputInspection(OutputAction.ALLOW, (), 0)

        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return OutputInspection(
                action=OutputAction.BLOCK,
                signals=("uninspectable_binary",),
                inspected_bytes=size,
            )

        signals = _text_signals(text)
        media_type = (content_type or "").split(";", 1)[0].strip().lower()
        looks_json = media_type.endswith("/json") or media_type.endswith("+json")

        if looks_json:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return OutputInspection(
                    action=OutputAction.BLOCK,
                    signals=("invalid_json_response",),
                    inspected_bytes=size,
                )
            json_signals, complete = _walk_json(parsed)
            signals.update(json_signals)
            if not complete:
                return OutputInspection(
                    action=OutputAction.BLOCK,
                    signals=tuple(sorted(signals)),
                    inspected_bytes=size,
                )

        blocking_signals = signals - {"prompt_injection_signal"}
        action = OutputAction.BLOCK if blocking_signals else OutputAction.ALLOW
        return OutputInspection(
            action=action,
            signals=tuple(sorted(signals)),
            inspected_bytes=size,
        )

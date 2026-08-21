from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
import uuid
from typing import Literal

from pydantic import BaseModel, Field

from app.models import EvaluationInput
from app.policy import canonical_payload


class ApprovalError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ApprovalClaims(BaseModel):
    version: Literal[1] = 1
    jti: str = Field(min_length=16, max_length=128)
    request_sha256: str = Field(min_length=64, max_length=64)
    protocol_version: str
    method: str
    tool_name: str
    policy_version: str
    approver: str = Field(min_length=1, max_length=120)
    issued_at: int
    expires_at: int


class ApprovalIssueRequest(BaseModel):
    request: EvaluationInput
    approver: str = Field(min_length=1, max_length=120)
    ttl_seconds: int | None = Field(default=None, ge=1, le=3600)


class ApprovalIssueResponse(BaseModel):
    receipt: str
    jti: str
    request_sha256: str
    method: str
    tool_name: str
    policy_version: str
    approver: str
    issued_at: int
    expires_at: int


def approval_request_hash(request: EvaluationInput) -> str:
    payload = request.model_dump(mode="json", exclude_none=False)
    return hashlib.sha256(canonical_payload(payload)).hexdigest()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ApprovalError("approval_receipt_malformed") from exc


class ApprovalReceiptService:
    PREFIX = "afr1"

    def __init__(
        self,
        signing_key: str,
        *,
        default_ttl_seconds: int = 300,
        max_ttl_seconds: int = 900,
        clock_skew_seconds: int = 30,
    ):
        self._key = signing_key.encode("utf-8")
        if self._key and len(self._key) < 32:
            raise ValueError("APPROVAL_SIGNING_KEY must be at least 32 bytes")
        if default_ttl_seconds < 1 or max_ttl_seconds < default_ttl_seconds:
            raise ValueError("invalid approval TTL configuration")
        if max_ttl_seconds > 3600:
            raise ValueError("approval max TTL cannot exceed 3600 seconds")
        self.default_ttl_seconds = default_ttl_seconds
        self.max_ttl_seconds = max_ttl_seconds
        self.clock_skew_seconds = max(0, clock_skew_seconds)

    @property
    def configured(self) -> bool:
        return bool(self._key)

    def issue(
        self,
        request: EvaluationInput,
        *,
        policy_version: str,
        approver: str,
        ttl_seconds: int | None = None,
        now: int | None = None,
    ) -> tuple[str, ApprovalClaims]:
        if not self.configured:
            raise ApprovalError("approval_signing_not_configured")

        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if ttl < 1 or ttl > self.max_ttl_seconds:
            raise ApprovalError("approval_ttl_out_of_range")

        issued_at = int(time.time()) if now is None else int(now)
        tool_name = request.mcp_name
        if not tool_name:
            raise ApprovalError("approval_tool_name_missing")

        claims = ApprovalClaims(
            jti=uuid.uuid4().hex,
            request_sha256=approval_request_hash(request),
            protocol_version=request.protocol_version,
            method=request.mcp_method,
            tool_name=tool_name,
            policy_version=policy_version,
            approver=approver,
            issued_at=issued_at,
            expires_at=issued_at + ttl,
        )
        payload = json.dumps(
            claims.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        encoded_payload = _b64url_encode(payload)
        signature = hmac.new(
            self._key,
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        receipt = f"{self.PREFIX}.{encoded_payload}.{_b64url_encode(signature)}"
        return receipt, claims

    def verify(
        self,
        receipt: str,
        request: EvaluationInput,
        *,
        policy_version: str,
        now: int | None = None,
    ) -> ApprovalClaims:
        if not self.configured:
            raise ApprovalError("approval_signing_not_configured")

        parts = receipt.split(".")
        if len(parts) != 3 or parts[0] != self.PREFIX:
            raise ApprovalError("approval_receipt_malformed")

        encoded_payload = parts[1]
        provided_signature = _b64url_decode(parts[2])
        expected_signature = hmac.new(
            self._key,
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(provided_signature, expected_signature):
            raise ApprovalError("approval_signature_invalid")

        try:
            claims = ApprovalClaims.model_validate_json(_b64url_decode(encoded_payload))
        except Exception as exc:
            raise ApprovalError("approval_claims_invalid") from exc

        current_time = int(time.time()) if now is None else int(now)
        if claims.issued_at > current_time + self.clock_skew_seconds:
            raise ApprovalError("approval_issued_in_future")
        if claims.expires_at <= current_time:
            raise ApprovalError("approval_expired")
        if claims.expires_at <= claims.issued_at:
            raise ApprovalError("approval_claims_invalid")
        if claims.expires_at - claims.issued_at > self.max_ttl_seconds:
            raise ApprovalError("approval_ttl_exceeds_policy")

        expected_hash = approval_request_hash(request)
        if not hmac.compare_digest(claims.request_sha256, expected_hash):
            raise ApprovalError("approval_request_mismatch")
        if claims.protocol_version != request.protocol_version:
            raise ApprovalError("approval_protocol_mismatch")
        if claims.method != request.mcp_method:
            raise ApprovalError("approval_method_mismatch")
        if claims.tool_name != request.mcp_name:
            raise ApprovalError("approval_tool_mismatch")
        if claims.policy_version != policy_version:
            raise ApprovalError("approval_policy_version_mismatch")

        return claims


def response_from_issued(receipt: str, claims: ApprovalClaims) -> ApprovalIssueResponse:
    return ApprovalIssueResponse(
        receipt=receipt,
        jti=claims.jti,
        request_sha256=claims.request_sha256,
        method=claims.method,
        tool_name=claims.tool_name,
        policy_version=claims.policy_version,
        approver=claims.approver,
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
    )

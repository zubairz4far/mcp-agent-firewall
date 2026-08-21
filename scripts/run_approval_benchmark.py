from __future__ import annotations

import json
import tempfile
from pathlib import Path

from app.approval import ApprovalError, ApprovalReceiptService
from app.audit import AuditStore
from app.models import EvaluationInput, McpEnvelope


def request(path: str = "/tmp/example.txt", *, request_id: int = 1) -> EvaluationInput:
    return EvaluationInput(
        protocol_version="2026-07-28",
        mcp_method="tools/call",
        mcp_name="delete_file",
        body=McpEnvelope(
            jsonrpc="2.0",
            id=request_id,
            method="tools/call",
            params={"name": "delete_file", "arguments": {"path": path}},
        ),
    )


def rejected(callback) -> bool:
    try:
        callback()
    except ApprovalError:
        return True
    return False


def main() -> int:
    signing_key = "benchmark-signing-key-32-bytes-min!!"
    service = ApprovalReceiptService(
        signing_key,
        default_ttl_seconds=60,
        max_ttl_seconds=300,
    )
    original = request()
    receipt, claims = service.issue(
        original,
        policy_version="1",
        approver="benchmark-operator",
        now=1000,
    )

    prefix, payload, signature = receipt.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    tampered = f"{prefix}.{payload}.{replacement}{signature[1:]}"
    wrong_key = ApprovalReceiptService(
        "different-signing-key-32-bytes-min!!",
        default_ttl_seconds=60,
        max_ttl_seconds=300,
    )

    cases = [
        (
            "valid_exact_request",
            not rejected(lambda: service.verify(receipt, original, policy_version="1", now=1010)),
        ),
        (
            "tampered_signature_rejected",
            rejected(lambda: service.verify(tampered, original, policy_version="1", now=1010)),
        ),
        (
            "modified_argument_rejected",
            rejected(
                lambda: service.verify(
                    receipt,
                    request("/tmp/changed.txt"),
                    policy_version="1",
                    now=1010,
                )
            ),
        ),
        (
            "modified_request_id_rejected",
            rejected(
                lambda: service.verify(
                    receipt,
                    request(request_id=2),
                    policy_version="1",
                    now=1010,
                )
            ),
        ),
        (
            "expired_receipt_rejected",
            rejected(lambda: service.verify(receipt, original, policy_version="1", now=1060)),
        ),
        (
            "policy_drift_rejected",
            rejected(lambda: service.verify(receipt, original, policy_version="2", now=1010)),
        ),
        (
            "wrong_signing_key_rejected",
            rejected(lambda: wrong_key.verify(receipt, original, policy_version="1", now=1010)),
        ),
        (
            "malformed_receipt_rejected",
            rejected(lambda: service.verify("not-a-receipt", original, policy_version="1", now=1010)),
        ),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        store = AuditStore(str(Path(tmp) / "audit.db"))
        store.register_approval(claims)
        first_consume = store.consume_approval(claims, now=1010)
        replay_consume = store.consume_approval(claims, now=1010)

        _, unregistered_claims = service.issue(
            original,
            policy_version="1",
            approver="benchmark-operator",
            now=1000,
        )
        unregistered_consume = store.consume_approval(unregistered_claims, now=1010)

    cases.extend(
        [
            ("registered_receipt_consumed", first_consume is True),
            ("replay_rejected", replay_consume is False),
            ("unregistered_receipt_rejected", unregistered_consume is False),
        ]
    )

    passed = sum(int(ok) for _, ok in cases)
    report = {
        "cases": len(cases),
        "passed": passed,
        "exact_security_decision_accuracy": passed / len(cases),
        "unsafe_false_accepts": len(cases) - passed,
        "details": [{"id": case_id, "ok": ok} for case_id, ok in cases],
    }
    print(json.dumps(report, indent=2))
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())

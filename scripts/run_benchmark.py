from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.models import Decision, EvaluationInput
from app.policy import PolicyConfig, PolicyEngine


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-on-unsafe", action="store_true")
    args = parser.parse_args()

    engine = PolicyEngine(PolicyConfig.load(ROOT / "config" / "policy.example.yaml"))
    cases = [
        json.loads(line)
        for line in (ROOT / "evals" / "policy_safety_v1.jsonl").read_text().splitlines()
        if line.strip()
    ]

    correct = 0
    unsafe_false_accepts = 0
    false_blocks = 0
    rows = []
    for case in cases:
        request = EvaluationInput.model_validate(case["request"])
        result = engine.evaluate(request)
        expected = Decision(case["expected"])
        ok = result.decision == expected
        correct += int(ok)
        if expected in {Decision.DENY, Decision.APPROVAL_REQUIRED} and result.decision == Decision.ALLOW:
            unsafe_false_accepts += 1
        if expected == Decision.ALLOW and result.decision != Decision.ALLOW:
            false_blocks += 1
        rows.append(
            {
                "id": case["id"],
                "expected": expected.value,
                "predicted": result.decision.value,
                "ok": ok,
            }
        )

    report = {
        "cases": len(cases),
        "exact_decision_accuracy": correct / len(cases),
        "unsafe_false_accepts": unsafe_false_accepts,
        "false_blocks": false_blocks,
        "details": rows,
    }
    print(json.dumps(report, indent=2))
    if args.fail_on_unsafe and unsafe_false_accepts:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

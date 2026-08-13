"""命令行演示：允许、审批通过、拒绝、篡改四条路径。"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from langgraph.types import Command

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from approval.workflow import PROJECT_ROOT, build_workflow


def _interrupt_value(result: dict[str, Any]) -> Any:
    values = result.get("__interrupt__", ())
    if not values:
        return None
    return getattr(values[0], "value", values[0])


def main() -> int:
    parser = argparse.ArgumentParser(description="LangGraph + OPA 审批工作流演示")
    parser.add_argument(
        "--scenario",
        choices=["allow", "approve", "reject", "tamper"],
        default="approve",
    )
    parser.add_argument(
        "--checkpoint",
        default=str(PROJECT_ROOT / "approval" / "checkpoints" / "demo.sqlite"),
    )
    args = parser.parse_args()

    sample_name = "allow_low_risk.json" if args.scenario == "allow" else "require_approval.json"
    request = json.loads((PROJECT_ROOT / "samples" / sample_name).read_text(encoding="utf-8"))
    thread_id = f"demo-{args.scenario}-{uuid.uuid4().hex[:8]}"
    config = {"configurable": {"thread_id": thread_id}}
    graph, connection = build_workflow(args.checkpoint)
    try:
        first = graph.invoke({"request": request}, config=config)
        summary: dict[str, Any] = {
            "scenario": args.scenario,
            "thread_id": thread_id,
            "initial_effect": first["policy_decision"]["effect"],
            "paused": bool(first.get("__interrupt__")),
            "interrupt": _interrupt_value(first),
        }
        if first.get("__interrupt__"):
            review: dict[str, Any] = {
                "decision": "approve" if args.scenario in {"approve", "tamper"} else "reject",
                "approver_id": "manager-001",
                "approver_roles": ["business_approver"],
                "reason": "演示审批",
            }
            if args.scenario == "tamper":
                review["tamper_parameters"] = {"amount": 500000}
            final = graph.invoke(Command(resume=review), config=config)
            summary.update(
                {
                    "final_status": final["status"],
                    "final_effect": final["policy_decision"]["effect"],
                    "reason_codes": [
                        str(code) for code in final["policy_decision"].get("reason_codes", [])
                    ],
                    "execution_receipts": final.get("execution_receipts", []),
                }
            )
        else:
            summary.update(
                {
                    "final_status": first["status"],
                    "final_effect": first["policy_decision"]["effect"],
                    "execution_receipts": first.get("execution_receipts", []),
                }
            )
        print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())

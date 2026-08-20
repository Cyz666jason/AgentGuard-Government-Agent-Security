"""命令行演示：允许、审批通过、拒绝、篡改四条路径。"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any

from langgraph.types import Command

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from approval.workflow import PROJECT_ROOT, build_workflow
from enforcement.http_stack import OpaRestClient
from service.opa_runtime import (
    CLI_PERFORMANCE_NOTE,
    REST_PERFORMANCE_NOTE,
    ResidentOpaProcess,
)


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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
    parser.add_argument(
        "--opa-mode",
        choices=["rest", "cli"],
        default="rest",
        help=(
            "rest=常驻 OPA REST（默认，生产形态）；"
            "cli=每次决策启动一次 OPA CLI，仅用于离线单文件复现，不是生产性能结果"
        ),
    )
    parser.add_argument(
        "--opa-base-url",
        default="",
        help="复用已在运行的常驻 OPA；留空则由本演示自行拉起一个临时常驻 OPA",
    )
    args = parser.parse_args()

    sample_name = "allow_low_risk.json" if args.scenario == "allow" else "require_approval.json"
    request = json.loads((PROJECT_ROOT / "samples" / sample_name).read_text(encoding="utf-8"))
    thread_id = f"demo-{args.scenario}-{uuid.uuid4().hex[:8]}"
    config = {"configurable": {"thread_id": thread_id}}
    demo_token = secrets.token_urlsafe(24)

    def demo_authenticator(review: dict[str, Any]) -> dict[str, Any]:
        if not secrets.compare_digest(str(review.get("demo_auth_token", "")), demo_token):
            raise PermissionError("演示审批身份验证失败")
        return {
            "id": "manager-001",
            "roles": ["business_approver"],
            "identity_source": "local_demo_authenticator",
        }

    resident_opa: ResidentOpaProcess | None = None
    opa_client = None
    performance_note = CLI_PERFORMANCE_NOTE
    if args.opa_mode == "rest":
        base_url = args.opa_base_url
        if not base_url:
            resident_opa = ResidentOpaProcess(
                PROJECT_ROOT, address=f"127.0.0.1:{_free_port()}"
            ).start()
            base_url = resident_opa.base_url
        opa_client = OpaRestClient(base_url)
        performance_note = REST_PERFORMANCE_NOTE

    graph, connection = build_workflow(
        args.checkpoint,
        approver_authenticator=demo_authenticator,
        opa_client=opa_client,
    )
    try:
        first = graph.invoke({"request": request}, config=config)
        summary: dict[str, Any] = {
            "scenario": args.scenario,
            "thread_id": thread_id,
            "opa_mode": args.opa_mode,
            "performance_representative": args.opa_mode == "rest",
            "performance_note": performance_note,
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
                "demo_auth_token": demo_token,
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
        if resident_opa is not None:
            resident_opa.stop()


if __name__ == "__main__":
    raise SystemExit(main())

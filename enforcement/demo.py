"""阻断网关与安全内核的命令行演示。"""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
import uuid
from pathlib import Path

from langgraph.types import Command

from approval.workflow import PROJECT_ROOT, build_workflow
from enforcement import build_gateway
from security_kernel import WasmSecurityKernel


class FailingOpa:
    def decide(self, request):
        raise RuntimeError("demo OPA outage")


def sample(name: str) -> dict:
    return json.loads((PROJECT_ROOT / "samples" / name).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentGuard 强制阻断与安全内核演示")
    parser.add_argument(
        "--scenario",
        choices=[
            "allow",
            "pending",
            "deny",
            "approved",
            "replay",
            "tamper",
            "opa_down",
            "full_chain",
            "kernel_loop",
            "kernel_wasi",
        ],
        default="full_chain",
    )
    parser.add_argument("--state-dir", default="")
    args = parser.parse_args()

    state_context = None
    if args.state_dir:
        state_dir = Path(args.state_dir)
    else:
        state_context = tempfile.TemporaryDirectory()
        state_dir = Path(state_context.name)
    try:
        if args.scenario.startswith("kernel_"):
            module = "infinite_loop.wat" if args.scenario == "kernel_loop" else "wasi_fs_attempt.wat"
            result = WasmSecurityKernel(fuel=20_000).execute(
                PROJECT_ROOT / "security_kernel" / "modules" / module
            )
        else:
            opa_client = FailingOpa() if args.scenario == "opa_down" else None
            gateway = build_gateway(state_dir, secret=b"D" * 32, opa_client=opa_client)
            if args.scenario == "allow":
                result = gateway.invoke(sample("allow_low_risk.json"))
            elif args.scenario == "pending":
                result = gateway.invoke(sample("require_approval.json"))
            elif args.scenario == "deny":
                result = gateway.invoke(sample("deny_dangerous_command.json"))
            elif args.scenario == "approved":
                result = gateway.invoke(sample("allow_with_approval.json"))
            elif args.scenario == "opa_down":
                result = gateway.invoke(sample("allow_low_risk.json"))
            elif args.scenario == "replay":
                request = sample("allow_low_risk.json")
                authorization = gateway.authorize(request)
                first = gateway.dispatch(request, authorization["ticket"])
                second = gateway.dispatch(request, authorization["ticket"])
                result = {"first": first, "replay": second}
            elif args.scenario == "tamper":
                request = sample("allow_low_risk.json")
                authorization = gateway.authorize(request)
                changed = copy.deepcopy(request)
                changed["action"]["parameters"]["limit"] = 999
                result = gateway.dispatch(changed, authorization["ticket"])
            else:
                checkpoint = state_dir / "full_chain.sqlite"

                def isolated_executor(request, decision):
                    return gateway.invoke(request)

                graph, connection = build_workflow(checkpoint, executor=isolated_executor)
                config = {"configurable": {"thread_id": f"demo-{uuid.uuid4().hex}"}}
                try:
                    first = graph.invoke(
                        {"request": sample("require_approval.json")}, config=config
                    )
                    final = graph.invoke(
                        Command(
                            resume={
                                "decision": "approve",
                                "approver_id": "manager-demo",
                                "approver_roles": ["business_approver"],
                            }
                        ),
                        config=config,
                    )
                    result = {
                        "initial_effect": first["policy_decision"]["effect"],
                        "paused": "__interrupt__" in first,
                        "final_status": final["status"],
                        "execution_receipts": final.get("execution_receipts", []),
                    }
                finally:
                    connection.close()
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return 0
    finally:
        if state_context is not None:
            state_context.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

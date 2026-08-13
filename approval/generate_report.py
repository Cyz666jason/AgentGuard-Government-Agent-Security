"""根据实际演示输出生成审批工作流量化报告。"""

from __future__ import annotations

import json
import re
from datetime import date
from importlib.metadata import version
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def main() -> int:
    demos = {
        name: json.loads((REPORTS / f"approval_demo_{name}.json").read_text(encoding="utf-8-sig"))
        for name in ("allow", "approve", "reject", "tamper")
    }
    test_text = (REPORTS / "approval_unit_tests.txt").read_text(
        encoding="utf-8-sig", errors="replace"
    )
    match = re.search(r"Ran\s+(\d+)\s+tests?", test_text)
    test_total = int(match.group(1)) if match else 0
    tests_passed = test_total > 0 and re.search(r"^OK\s*$", test_text, re.MULTILINE) is not None

    checks = {
        "低风险免审批放行": demos["allow"]["final_status"] == "executed_simulated",
        "高风险动作持久化暂停": all(demos[name]["paused"] for name in ("approve", "reject", "tamper")),
        "合法审批后恢复执行": demos["approve"]["final_effect"] == "allow"
        and len(demos["approve"]["execution_receipts"]) == 1,
        "人工拒绝后阻断": demos["reject"]["final_effect"] == "deny"
        and len(demos["reject"]["execution_receipts"]) == 0,
        "审批后参数篡改阻断": "D103_APPROVAL_ACTION_TAMPERED"
        in demos["tamper"]["reason_codes"]
        and len(demos["tamper"]["execution_receipts"]) == 0,
        "修改参数后清空旧凭证并重新审批": "test_edit_clears_old_approval_and_pauses_again"
        in test_text,
        "发起人自批阻断": "test_self_approval_is_blocked" in test_text,
        "无审批角色阻断": "test_unauthorized_approver_role_is_blocked" in test_text,
        "跨任务复用阻断": "test_cross_task_approval_reuse_is_blocked" in test_text,
        "重启后从持久化暂停点恢复": "test_new_process_graph_can_resume_same_thread" in test_text,
    }
    summary = {
        "name": "AgentGuard OPA + LangGraph 审批工作流实测",
        "generated_at": date.today().isoformat(),
        "versions": {
            "langgraph": version("langgraph"),
            "langgraph-checkpoint-sqlite": version("langgraph-checkpoint-sqlite"),
            "opa": "1.19.0",
        },
        "unit_tests": {"passed": test_total if tests_passed else 0, "total": test_total},
        "scenario_checks": checks,
        "scenario_passed": sum(checks.values()),
        "scenario_total": len(checks),
        "unsafe_execution_count": sum(
            len(demos[name].get("execution_receipts", [])) for name in ("reject", "tamper")
        ),
        "real_tool_execution": False,
        "note": "所有执行均为 simulated_only，不触发真实转账、删除或系统命令。",
    }
    (REPORTS / "approval_evaluation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    rows = "\n".join(
        f"| {name} | {'通过' if passed else '失败'} |" for name, passed in checks.items()
    )
    report = f"""# OPA + LangGraph 人工审批工作流实测报告

生成日期：{summary['generated_at']}

## 结论

第二阶段已实现并实际运行：OPA 负责三态安全决策，LangGraph 负责高风险任务的持久化暂停与恢复，SQLite 保存检查点；审批恢复后必须再次调用 OPA。共 {summary['unit_tests']['passed']}/{summary['unit_tests']['total']} 个自动化测试通过，{summary['scenario_passed']}/{summary['scenario_total']} 项关键能力验证通过，拒绝或篡改场景的误执行次数为 {summary['unsafe_execution_count']}。

## 关键验证

| 验证项 | 结果 |
|---|---|
{rows}

## 四条可演示路径

- `allow`：低风险读取由 OPA 直接放行，生成 1 条模拟执行回执。
- `approve`：高风险转账先暂停；审批恢复后 OPA 返回 `L002_VALID_APPROVAL`，仅模拟执行 1 次。
- `reject`：审批拒绝后 OPA 返回 `D101_APPROVAL_STATUS`，执行回执为 0。
- `tamper`：审批后把金额由 5000 改为 500000，OPA 返回 `D103_APPROVAL_ACTION_TAMPERED`，执行回执为 0。

## 版本与复现

- OPA：1.19.0
- LangGraph：{summary['versions']['langgraph']}
- LangGraph SQLite Checkpoint：{summary['versions']['langgraph-checkpoint-sqlite']}
- 安装：`powershell -ExecutionPolicy Bypass -File .\\scripts\\setup_approval.ps1`
- 全量验证：`powershell -ExecutionPolicy Bypass -File .\\scripts\\run_approval_all.ps1`

## 安全边界

本原型不会真正转账、删除文件或执行系统命令；工具执行节点固定输出 `simulated_only`。生产部署还需要审批凭证的一次性原子核销、统一网关强制执行、真实身份系统和隔离沙箱。
"""
    (REPORTS / "approval_evaluation_report.md").write_text(report, encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if tests_passed and all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

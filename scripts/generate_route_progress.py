"""Generate a machine-readable and human-readable open-source route dashboard.

The dashboard only summarizes evidence already produced by the reproducible test
pipeline.  It deliberately keeps test definitions, unit tests and demonstrations
as separate denominators so that they cannot be presented as one inflated
"accuracy" number.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = PROJECT_ROOT / "reports"
DATASET_DIR = PROJECT_ROOT / "datasets"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def count_jsonl(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig") as handle:
        return sum(1 for line in handle if line.strip())


def result_row(name: str, result: dict[str, Any], evidence: str) -> dict[str, Any]:
    passed = int(result["passed"])
    total = int(result["total"])
    return {
        "name": name,
        "passed": passed,
        "total": total,
        "pass_rate": round(passed / total, 6) if total else 0.0,
        "status": "passed" if passed == total and total > 0 else "failed",
        "evidence": evidence,
    }


def main() -> int:
    full = load_json(REPORT_DIR / "full_security_evaluation_summary.json")
    evaluation = load_json(REPORT_DIR / "evaluation_summary.json")
    coverage = load_json(REPORT_DIR / "coverage.json")
    machine = load_json(REPORT_DIR / "test_machine_environment.json")

    dataset_specs = [
        (
            "策略决策",
            DATASET_DIR / "agent_guard_cases.jsonl",
            DATASET_DIR / "metadata.json",
        ),
        (
            "审批流程",
            DATASET_DIR / "approval_workflow_cases.jsonl",
            DATASET_DIR / "approval_workflow_metadata.json",
        ),
        (
            "强制执行与安全内核",
            DATASET_DIR / "enforcement_kernel_cases.jsonl",
            DATASET_DIR / "enforcement_kernel_metadata.json",
        ),
    ]
    datasets: list[dict[str, Any]] = []
    for layer, jsonl_path, metadata_path in dataset_specs:
        metadata = load_json(metadata_path)
        actual = count_jsonl(jsonl_path)
        declared = int(metadata["total_cases"])
        datasets.append(
            {
                "layer": layer,
                "file": jsonl_path.relative_to(PROJECT_ROOT).as_posix(),
                "actual_cases": actual,
                "declared_cases": declared,
                "count_consistent": actual == declared,
                "contains_personal_data": bool(
                    metadata.get("contains_personal_data", False)
                ),
            }
        )

    metrics = [
        result_row(
            "OPA/Rego单元测试",
            full["opa_unit_tests"],
            "reports/full_opa_tests.txt",
        ),
        result_row(
            "OPA-Envoy前置策略测试",
            full["opa_envoy_policy_tests"],
            "reports/opa_envoy_policy_tests.txt",
        ),
        result_row(
            "三态策略数据集",
            full["opa_dataset"],
            "reports/evaluation_summary.json",
        ),
        result_row(
            "身份/审批/网关/内核Python测试",
            full["python_security_tests"],
            "reports/full_python_tests.txt",
        ),
        result_row(
            "常驻OPA REST网络链路",
            full["network_enforcement_e2e"],
            "reports/network_enforcement_e2e.json",
        ),
        result_row(
            "Keycloak/OIDC真实链路",
            full["keycloak_oidc_e2e"],
            "reports/keycloak_oidc_e2e.json",
        ),
        result_row(
            "完整链路演示检查",
            {
                "passed": full["demonstration_passed"],
                "total": full["demonstration_total"],
            },
            "reports/full_security_evaluation_summary.json",
        ),
        result_row(
            "OpenBao外部密钥与共享票据核销",
            full["openbao_kms_ha_e2e"],
            "reports/openbao_kms_ha_e2e.json",
        ),
        result_row(
            "QEMU独立Linux来宾内核隔离",
            full["qemu_native_isolation_e2e"],
            "reports/qemu_native_isolation_e2e.json",
        ),
    ]

    containers = machine["container_environment"]
    route = [
        {
            "stage": "1 赛题解读",
            "status": "completed",
            "evidence": "docs/开源路线自动推进总览_20260813.md#2-赛题解读题目怎样转化为工程任务",
            "next": "后续实现继续映射到感知—决策—调用—执行和赛题评分项",
        },
        {
            "stage": "2 开源技术路线与选型",
            "status": "completed",
            "evidence": "Keycloak + OPA + LangGraph + 强制网关 + Wasmtime",
            "next": "生产分支补OPA-Envoy、ToolHive、KMS/HA与原生隔离",
        },
        {
            "stage": "3 复现效果与问题",
            "status": "completed_with_gaps",
            "evidence": "reports/full_security_evaluation_summary.json；reports/复现问题台账_20260813.md",
            "next": "补产品级容器E2E、并发、故障注入和真实业务适配器",
        },
        {
            "stage": "4 相关评估与数据支撑",
            "status": "partial",
            "evidence": "三层83条合成定义；各类测试分母独立统计",
            "next": "取得授权后加入脱敏日志、盲测集、红队和生产回放",
        },
        {
            "stage": "5 整体大图与清晰语言",
            "status": "completed",
            "evidence": "docs/整体开源技术路线图_20260813.mmd",
            "next": "所有后续材料复用同一架构语言和边界表述",
        },
    ]

    all_checks_passed = all(item["status"] == "passed" for item in metrics)
    all_dataset_counts_consistent = all(item["count_consistent"] for item in datasets)
    unsafe_execution_count = int(full["unsafe_execution_count"])

    dashboard = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "project": "AgentGuard 政企智能体权限、审批、阻断与安全内核",
        "contest_focus": "面向工具调用和任务执行的安全约束与审批控制",
        "overall": {
            "automated_regression_passed": all_checks_passed,
            "dataset_counts_consistent": all_dataset_counts_consistent,
            "unsafe_execution_count": unsafe_execution_count,
            "current_machine_scope_passed": (
                all_checks_passed
                and all_dataset_counts_consistent
                and unsafe_execution_count == 0
            ),
            "production_ready": False,
            "production_ready_reason": "仍缺OPA-Envoy/ToolHive产品容器E2E、多节点KMS/HA故障切换、真实业务凭据、获批真实数据和远程GitHub认证。",
        },
        "route": route,
        "test_metrics": metrics,
        "policy_effect_metrics": {
            "effect_accuracy": evaluation["effect_accuracy"],
            "reason_code_accuracy": evaluation["reason_code_accuracy"],
            "dangerous_action_block_rate": evaluation[
                "dangerous_action_block_rate"
            ],
            "legitimate_action_pass_rate": evaluation[
                "legitimate_action_pass_rate"
            ],
            "approval_routing_accuracy": evaluation[
                "approval_routing_accuracy"
            ],
            "invalid_approval_block_rate": evaluation[
                "invalid_approval_block_rate"
            ],
            "unsafe_allow_count": evaluation["unsafe_allow_count"],
            "cli_end_to_end_latency_ms": evaluation[
                "cli_end_to_end_latency_ms"
            ],
            "rego_total_coverage": round(float(coverage["coverage"]), 4),
        },
        "data_support": {
            "datasets": datasets,
            "total_layered_case_definitions": sum(
                item["actual_cases"] for item in datasets
            ),
            "data_type": "synthetic",
            "warning": "83是三层测试定义数量，不是可以相加后称为83/83的单一准确率分母。",
        },
        "environment": {
            "tested_at": machine["tested_at"],
            "os": machine["os"],
            "logical_processors": machine["logical_processors"],
            "memory_gb": machine["memory_gb"],
            "python": machine["python"],
            "components": machine["components"],
            "native_http_policy_enforcement_e2e_tested": containers[
                "native_http_policy_enforcement_e2e_tested"
            ],
            "opa_envoy_product_e2e_tested": containers[
                "opa_envoy_end_to_end_tested"
            ],
            "toolhive_container_tested": containers[
                "toolhive_container_tested"
            ],
            "environment_blocker": containers["reason"],
        },
        "known_gaps": full["known_gaps"],
        "resolved_regression": {
            "id": "P-20260813-01",
            "summary": "修复JWT篡改用例可能只改变Base64url未使用填充位的问题；现改为翻转真实签名字节。",
            "evidence": [
                "identity/run_keycloak_e2e.py",
                "identity/tests/test_oidc.py",
                "reports/keycloak_oidc_e2e.json",
            ],
            "status": "resolved",
        },
        "official_sources": {
            "OPA": "https://www.openpolicyagent.org/docs",
            "Keycloak": "https://www.keycloak.org/securing-apps/oidc-layers",
            "LangGraph": "https://langchain-ai.github.io/langgraph/concepts/breakpoints/",
            "Wasmtime": "https://docs.wasmtime.dev/api/wasmtime/struct.Store.html",
            "ToolHive": "https://github.com/stacklok/toolhive",
            "OpenBao": "https://openbao.org/docs/",
            "QEMU": "https://www.qemu.org/docs/master/system/introduction.html",
        },
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORT_DIR / "open_source_route_progress.json"
    markdown_path = REPORT_DIR / "open_source_route_progress.md"
    json_path.write_text(
        json.dumps(dashboard, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    status_text = "通过" if dashboard["overall"]["current_machine_scope_passed"] else "未通过"
    md_lines = [
        "# AgentGuard 开源路线自动进度看板",
        "",
        f"> 自动生成时间：{dashboard['generated_at']}",
        f"> 当前测试机范围：**{status_text}**；生产就绪：**否**。",
        "",
        "## 五阶段路线",
        "",
        "| 阶段 | 状态 | 证据 | 下一动作 |",
        "|---|---|---|---|",
    ]
    for item in route:
        md_lines.append(
            f"| {item['stage']} | {item['status']} | {item['evidence']} | {item['next']} |"
        )

    md_lines.extend(
        [
            "",
            "## 最新自动回归",
            "",
            "| 检查项 | 结果 | 证据 |",
            "|---|---:|---|",
        ]
    )
    for item in metrics:
        md_lines.append(
            f"| {item['name']} | {item['passed']}/{item['total']} | `{item['evidence']}` |"
        )

    latency = evaluation["cli_end_to_end_latency_ms"]
    md_lines.extend(
        [
            "",
            "## 数据与性能",
            "",
            f"- 三层数据定义：{dashboard['data_support']['total_layered_case_definitions']}条（策略55、审批9、执行/内核19），均为合成数据。",
            f"- 策略数据危险动作误放行：{evaluation['unsafe_allow_count']}；完整链路危险动作误执行：{unsafe_execution_count}。",
            f"- OPA CLI逐例端到端：均值{latency['mean']} ms，P95 {latency['p95']} ms；该值包含进程启动，不代表常驻服务纯策略延迟。",
            f"- 全部Rego文件总覆盖率：{float(coverage['coverage']):.2f}%。",
            "",
            "## 未完成边界",
            "",
        ]
    )
    for gap in full["known_gaps"]:
        md_lines.append(
            f"- **{gap['item']}**：{gap['reason']} 下一步：{gap['next']}"
        )
    md_lines.extend(
        [
            "",
            "## 统计口径",
            "",
            "各测试层的分母保持独立；不把单元测试、数据定义和演示检查相加为一个准确率。当前结论仅覆盖本机、当前代码版本和已定义场景，不能表述为已经生产就绪或系统绝对安全。",
            "",
        ]
    )
    markdown_path.write_text("\n".join(md_lines), encoding="utf-8")

    print(
        json.dumps(
            {
                "status": "passed" if status_text == "通过" else "failed",
                "json_report": json_path.relative_to(PROJECT_ROOT).as_posix(),
                "markdown_report": markdown_path.relative_to(PROJECT_ROOT).as_posix(),
                "test_groups": len(metrics),
                "dataset_definitions": dashboard["data_support"][
                    "total_layered_case_definitions"
                ],
                "unsafe_execution_count": unsafe_execution_count,
            },
            ensure_ascii=False,
        )
    )
    return 0 if dashboard["overall"]["current_machine_scope_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Generate a machine-readable and human-readable open-source route dashboard.

The dashboard only summarizes evidence already produced by the reproducible test
pipeline.  It deliberately keeps test definitions, unit tests and demonstrations
as separate denominators so that they cannot be presented as one inflated
"accuracy" number.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = PROJECT_ROOT / "reports"
CORE_REPORT_DIR = REPORT_DIR / "core"
NETWORK_REPORT_DIR = REPORT_DIR / "e2e" / "network"
IDENTITY_REPORT_DIR = REPORT_DIR / "e2e" / "identity"
OPENBAO_REPORT_DIR = REPORT_DIR / "e2e" / "openbao"
ISOLATION_REPORT_DIR = REPORT_DIR / "e2e" / "isolation"
OPENCLAW_REPORT_DIR = REPORT_DIR / "e2e" / "openclaw"
PUBLIC_BENCHMARK_REPORT_DIR = REPORT_DIR / "evaluation" / "public-benchmarks"
PREFLIGHT_REPORT_DIR = REPORT_DIR / "preflight"
STATUS_REPORT_DIR = REPORT_DIR / "status"
DATASET_DIR = PROJECT_ROOT / "datasets"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evidence.precedence import (  # noqa: E402
    TIER_CI_ANCESTOR,
    TIER_CI_HEAD,
    TIER_CI_UNRELATED,
    EvidenceResolver,
)

CI_TIERS = {TIER_CI_HEAD, TIER_CI_ANCESTOR, TIER_CI_UNRELATED}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def load_optional_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = load_json(path)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


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


def openclaw_check_row(
    name: str,
    report: dict[str, Any] | None,
    evidence: str,
    *,
    passed: int,
    total: int,
) -> dict[str, Any]:
    """Normalize OpenClaw evidence without treating a missing report as a pass.

    OpenClaw model evidence is intentionally kept in its own denominators.  The
    model dataset (5 fixed synthetic cases), CLI turn checks and Control UI turn
    checks must not be added to the Python/OPA or demonstration totals.
    """

    checks = report.get("checks") if isinstance(report, dict) else None
    checks_ok = isinstance(checks, dict) and bool(checks) and all(
        value is True for value in checks.values()
    )
    report_ok = (
        isinstance(report, dict)
        and report.get("status") == "passed_with_declared_scope"
        and checks_ok
        and total > 0
        and passed == total
    )
    return {
        "name": name,
        "passed": passed if report_ok else 0,
        "total": total,
        "pass_rate": round(passed / total, 6) if report_ok and total else 0.0,
        "status": "passed" if report_ok else "not_run_or_missing",
        "evidence": evidence,
        "checked_at": report.get("generated_at") if isinstance(report, dict) else None,
        "scope": "test_only_synthetic_fixture" if isinstance(report, dict) else None,
    }


def load_openclaw_evidence() -> dict[str, Any]:
    """Load the three independent OpenClaw model evidence reports."""

    dataset = load_optional_json(
        OPENCLAW_REPORT_DIR / "openclaw_agentguard_model_dataset.json"
    )
    model_turn = load_optional_json(
        OPENCLAW_REPORT_DIR / "openclaw_agentguard_model_turn.json"
    )
    control_ui = load_optional_json(
        OPENCLAW_REPORT_DIR / "openclaw_agentguard_control_ui_turn.json"
    )

    dataset_summary = dataset.get("summary", {}) if isinstance(dataset, dict) else {}
    dataset_total = int(dataset_summary.get("total_cases", 0) or 0)
    dataset_passed = int(dataset_summary.get("passed_cases", 0) or 0)

    def check_counts(report: dict[str, Any] | None) -> tuple[int, int]:
        checks = report.get("checks", {}) if isinstance(report, dict) else {}
        if not isinstance(checks, dict) or not checks:
            return 0, 0
        total = len(checks)
        return sum(1 for value in checks.values() if value is True), total

    model_passed, model_total = check_counts(model_turn)
    ui_passed, ui_total = check_counts(control_ui)
    rows = [
        openclaw_check_row(
            "OpenClaw模型固定合成测试集",
            dataset,
            "reports/e2e/openclaw/openclaw_agentguard_model_dataset.json",
            passed=dataset_passed,
            total=dataset_total,
        ),
        openclaw_check_row(
            "OpenClaw CLI真实模型回合",
            model_turn,
            "reports/e2e/openclaw/openclaw_agentguard_model_turn.json",
            passed=model_passed,
            total=model_total,
        ),
        openclaw_check_row(
            "OpenClaw Control UI真实模型回合",
            control_ui,
            "reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json",
            passed=ui_passed,
            total=ui_total,
        ),
    ]
    generated_at = max(
        (
            str(report.get("generated_at"))
            for report in (dataset, model_turn, control_ui)
            if isinstance(report, dict) and report.get("generated_at")
        ),
        default=None,
    )
    return {
        "reports": {
            "dataset": dataset,
            "model_turn": model_turn,
            "control_ui": control_ui,
        },
        "rows": rows,
        "checked_at": generated_at,
        "all_passed": bool(rows) and all(row["status"] == "passed" for row in rows),
        "dataset_total": dataset_total,
        "dataset_passed": dataset_passed,
    }


def main() -> int:
    full = load_json(CORE_REPORT_DIR / "full_security_evaluation_summary.json")
    evaluation = load_json(CORE_REPORT_DIR / "evaluation_summary.json")
    coverage = load_json(CORE_REPORT_DIR / "coverage.json")
    machine = load_json(PREFLIGHT_REPORT_DIR / "test_machine_environment.json")
    openbao_raft = load_json(OPENBAO_REPORT_DIR / "openbao_raft_ha_e2e.json")
    public_smoke = load_optional_json(
        PUBLIC_BENCHMARK_REPORT_DIR / "public_benchmark_fixture_smoke.json"
    ) or {}
    stage4_preflight = load_optional_json(
        PREFLIGHT_REPORT_DIR / "stage4_preflight.json"
    ) or {}
    openclaw = load_openclaw_evidence()

    public_benchmarks = public_smoke.get("benchmarks", {})
    public_fixture_contract_passed = (
        public_smoke.get("kind") == "adapter_contract_smoke_test"
        and public_smoke.get("uses_synthetic_fixtures") is True
        and public_smoke.get("uses_upstream_raw_data") is False
        and public_smoke.get("aggregate_metrics") is None
        and set(public_benchmarks) == {"agentdojo", "injecagent", "agentharm"}
        and all(
            isinstance(item, dict)
            and item.get("result") == "passed"
            and int(item.get("denominator", 0)) > 0
            for item in public_benchmarks.values()
        )
    )
    allowed_stage4_statuses = {
        "blocked_external_environment",
        "awaiting_authorized_input",
        "configuration_prepared_not_verified",
    }
    stage4_status = stage4_preflight.get("status", "missing_evidence")
    stage4_preflight_valid = (
        stage4_status in allowed_stage4_statuses
        and stage4_preflight.get("preflight_valid") is True
        and stage4_preflight.get("production_ready") is False
        and stage4_preflight.get("product_validation_completed") is False
        and stage4_preflight.get("preflight_mode") == "read_only"
    )

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
            "reports/core/full_opa_tests.txt",
        ),
        result_row(
            "OPA-Envoy前置策略测试",
            full["opa_envoy_policy_tests"],
            "reports/e2e/network/opa_envoy_policy_tests.txt",
        ),
        result_row(
            "三态策略数据集",
            full["opa_dataset"],
            "reports/core/evaluation_summary.json",
        ),
        result_row(
            "身份/审批/网关/内核Python测试",
            full["python_security_tests"],
            "reports/core/full_python_tests.txt",
        ),
        result_row(
            "常驻OPA REST网络链路",
            full["network_enforcement_e2e"],
            "reports/e2e/network/network_enforcement_e2e.json",
        ),
        result_row(
            "Keycloak/OIDC真实链路",
            full["keycloak_oidc_e2e"],
            "reports/e2e/identity/keycloak_oidc_e2e.json",
        ),
        result_row(
            "完整链路演示检查",
            {
                "passed": full["demonstration_passed"],
                "total": full["demonstration_total"],
            },
            "reports/core/full_security_evaluation_summary.json",
        ),
        result_row(
            "OpenBao外部密钥与共享票据核销",
            full["openbao_kms_ha_e2e"],
            "reports/e2e/openbao/openbao_kms_ha_e2e.json",
        ),
        result_row(
            "OpenBao三节点Raft故障切换",
            openbao_raft,
            "reports/e2e/openbao/openbao_raft_ha_e2e.json",
        ),
        result_row(
            "QEMU独立Linux来宾内核隔离",
            full["qemu_native_isolation_e2e"],
            "reports/e2e/isolation/qemu_native_isolation_e2e.json",
        ),
        *openclaw["rows"],
    ]

    resolver = EvidenceResolver(PROJECT_ROOT)
    envoy_claim = resolver.resolve("opa_envoy_container_e2e")
    toolhive_claim = resolver.resolve("toolhive_container_e2e")
    publication_claim = resolver.resolve("github_public_release")

    containers = machine["container_environment"]
    route = [
        {
            "stage": "1 赛题解读",
            "status": "completed",
            "evidence": "docs/overview/开源路线自动推进总览_20260813.md#2-赛题解读题目怎样转化为工程任务",
            "next": "后续实现继续映射到感知—决策—调用—执行和赛题评分项",
        },
        {
            "stage": "2 开源技术路线与选型",
            "status": "completed",
            "evidence": "Keycloak + OPA + LangGraph + 强制网关 + Wasmtime + OPA-Envoy/ToolHive 容器链路",
            "next": "生产分支补跨故障域KMS/HA、Kubernetes NetworkPolicy/mTLS与Kata/Firecracker",
        },
        {
            "stage": "3 复现效果与问题",
            "status": (
                "completed_with_gaps"
                if public_fixture_contract_passed
                else "partial_missing_public_adapter_evidence"
            ),
            "evidence": (
                "reports/core/full_security_evaluation_summary.json；"
                "reports/e2e/network/github_actions_container_product_e2e.json；"
                "reports/status/复现问题台账_20260813.md；"
                "reports/evaluation/public-benchmarks/public_benchmark_fixture_smoke.json（仅适配器契约）"
            ),
            "next": "导入许可允许的真实公开样本并生成真实策略预测；外部产品实测继续按阶段4门禁执行",
        },
        {
            "stage": "4 相关评估与数据支撑",
            "status": (
                "partial_external_inputs_required"
                if stage4_preflight_valid
                else "partial_missing_preflight_evidence"
            ),
            "evidence": (
                "三层83条合成定义；三套公开基准适配器使用6条自编fixture验证；"
                f"阶段4只读预检={stage4_status}"
            ),
            "next": "取得许可数据和组织授权后，分别完成真实公开基准、盲测、红队、产品E2E与生产回放",
        },
        {
            "stage": "5 整体大图与清晰语言",
            "status": "completed",
            "evidence": "docs/architecture/整体开源技术路线图_20260813.mmd",
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
            "production_ready_reason": (
                "OPA-Envoy/ToolHive 容器 E2E 已在 GitHub Linux Runner 实测通过，"
                "公开仓库已发布；生产就绪仍缺 Kata/Firecracker KVM 隔离、"
                "OpenBao 跨故障域与 TLS/自动解封/快照恢复、Kubernetes NetworkPolicy 与 mTLS、"
                "Keycloak HTTPS/高可用/目录联邦/真实 MFA、单位授权的真实业务凭据与获批生产数据。"
            ),
        },
        "evidence_precedence": {
            "rule": (
                "与当前提交历史匹配的CI实测证据 > 当前机器新鲜实测证据 > "
                "历史环境检查与历史失败记录"
            ),
            "report": "reports/status/evidence_precedence.json",
            "head_commit": resolver.head_commit,
            "claims": {
                "opa_envoy_container_e2e": envoy_claim.as_dict(),
                "toolhive_container_e2e": toolhive_claim.as_dict(),
                "github_public_release": publication_claim.as_dict(),
            },
        },
        "route": route,
        "test_metrics": metrics,
        "openclaw_model_e2e": {
            "status": "passed_with_declared_scope" if openclaw["all_passed"] else "not_run_or_missing",
            "checked_at": openclaw["checked_at"],
            "dataset": {
                "passed": openclaw["dataset_passed"],
                "total": openclaw["dataset_total"],
                "evidence": "reports/e2e/openclaw/openclaw_agentguard_model_dataset.json",
                "data_type": "fixed_synthetic_fixture",
                "public_benchmark": False,
            },
            "cli_model_turn_evidence": "reports/e2e/openclaw/openclaw_agentguard_model_turn.json",
            "control_ui_model_turn_evidence": "reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json",
            "only_allowed_tool": "agentguard-notices__list_notices",
            "unexpected_tool_call_count": (
                int((openclaw["reports"]["dataset"] or {}).get("summary", {}).get("unexpected_tool_call_count", 0))
                if isinstance(openclaw["reports"]["dataset"], dict)
                else 0
            ),
            "side_effect_result_count": (
                int((openclaw["reports"]["dataset"] or {}).get("summary", {}).get("side_effect_result_count", 0))
                if isinstance(openclaw["reports"]["dataset"], dict)
                else 0
            ),
            "scope_boundary": "5个固定合成fixture，仅覆盖当前隔离回环配置；不是公开基准或生产安全结论。",
        },
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
            "openclaw_model_fixture": {
                "total_cases": openclaw["dataset_total"],
                "passed_cases": openclaw["dataset_passed"],
                "evidence": "reports/e2e/openclaw/openclaw_agentguard_model_dataset.json",
                "data_type": "fixed_synthetic_fixture",
                "is_public_benchmark": False,
                "boundary": "固定5例只验证当前模型、工具过滤和隔离回环；不得泛化为公开基准或生产安全结论。",
            },
            "public_benchmark_support": {
                "adapter_contract_passed": public_fixture_contract_passed,
                "uses_synthetic_fixtures": public_smoke.get(
                    "uses_synthetic_fixtures", False
                ),
                "uses_upstream_raw_data": public_smoke.get(
                    "uses_upstream_raw_data", False
                ),
                "fixture_denominators": {
                    name: int(item.get("denominator", 0))
                    for name, item in sorted(public_benchmarks.items())
                    if isinstance(item, dict)
                },
                "aggregate_metrics": public_smoke.get("aggregate_metrics"),
                "real_upstream_evaluation_completed": False,
                "evidence": "reports/evaluation/public-benchmarks/public_benchmark_fixture_smoke.json",
                "boundary": "fixture只验证转换、校验和评测合同，不是公开基准真实成绩。",
            },
        },
        "stage4_preflight": {
            "evidence_valid": stage4_preflight_valid,
            "preflight_valid": stage4_preflight.get("preflight_valid", False),
            "status": stage4_status,
            "production_ready": stage4_preflight.get("production_ready", False),
            "product_validation_completed": stage4_preflight.get(
                "product_validation_completed", False
            ),
            "summary": stage4_preflight.get("summary", {}),
            "evidence": "reports/preflight/stage4_preflight.json",
            "boundary": "只读预检与配置准备不等于KVM、跨域HA、集群、身份或生产数据实测。",
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
            # 容器类结论一律取自证据裁决，不再直接读本机环境快照，
            # 否则本机没有 Docker 的历史事实会覆盖 Linux Runner 的成功结果。
            "opa_envoy_product_e2e_tested": envoy_claim.verdict is True,
            "opa_envoy_product_e2e_environment": (
                "github_actions_linux_runner"
                if envoy_claim.tier in CI_TIERS
                else "local_test_machine"
            ),
            "toolhive_container_tested": toolhive_claim.verdict is True,
            "toolhive_container_environment": (
                "github_actions_linux_runner"
                if toolhive_claim.tier in CI_TIERS
                else "local_test_machine"
            ),
            "local_machine_container_runtime_available": bool(
                containers.get("docker_cli_available", False)
            ),
            "environment_blocker": (
                "本测试机未安装 Docker，WSL 命令存在但没有 Linux 发行版；"
                "容器类 E2E 因此在 GitHub Linux Runner 上执行并取得实测证据。"
            ),
            "openclaw_model_e2e_checked_at": openclaw["checked_at"],
        },
        "publication": {
            "github_public_release": publication_claim.verdict is True,
            "status": (
                "published_public" if publication_claim.verdict is True else "not_published"
            ),
            "evidence": publication_claim.source,
        },
        "known_gaps": full["known_gaps"],
        "resolved_regression": {
            "id": "P-20260813-01",
            "summary": "修复JWT篡改用例可能只改变Base64url未使用填充位的问题；现改为翻转真实签名字节。",
            "evidence": [
                "identity/run_keycloak_e2e.py",
                "identity/tests/test_oidc.py",
                "reports/e2e/identity/keycloak_oidc_e2e.json",
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
            "AgentDojo": "https://github.com/ethz-spylab/agentdojo",
            "InjecAgent": "https://github.com/uiuc-kang-lab/InjecAgent",
            "AgentHarm": "https://huggingface.co/datasets/ai-safety-institute/AgentHarm",
        },
    }

    STATUS_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = STATUS_REPORT_DIR / "open_source_route_progress.json"
    markdown_path = STATUS_REPORT_DIR / "open_source_route_progress.md"
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
            "- 公开基准适配：AgentDojo、InjecAgent、AgentHarm 三套转换/校验/独立分母管线已通过各2条自编fixture；未导入上游原始数据，不是公开基准成绩。",
            f"- 阶段4只读预检：`{dashboard['stage4_preflight']['status']}`；产品验证完成：否，生产就绪：否。",
            f"- 策略数据危险动作误放行：{evaluation['unsafe_allow_count']}；完整链路危险动作误执行：{unsafe_execution_count}。",
            f"- OPA CLI逐例端到端：均值{latency['mean']} ms，P95 {latency['p95']} ms；该值包含进程启动，不代表常驻服务纯策略延迟。",
            f"- 全部Rego文件总覆盖率：{float(coverage['coverage']):.2f}%。",
            "",
            "## OpenClaw 模型回环证据",
            "",
            f"- 核验时间：`{openclaw['checked_at'] or '未记录'}`；总体状态：`{'passed_with_declared_scope' if openclaw['all_passed'] else 'not_run_or_missing'}`。",
            f"- 固定合成模型测试集：{openclaw['dataset_passed']}/{openclaw['dataset_total']}；CLI 与 Control UI 真实模型回合分别独立记录在 `reports/e2e/openclaw/openclaw_agentguard_model_turn.json` 和 `reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json`。",
            "- 当前配置只允许 `agentguard-notices__list_notices`；5 个用例是项目自有固定 synthetic fixture，不是 AgentDojo、InjecAgent、AgentHarm 等公开基准成绩。",
            "- 回环静态开发身份、隔离合成 SQLite 与 loopback 服务仅用于测试；生产仍需 requester-scoped OIDC、TLS/mTLS、网络隔离和授权业务凭据。",
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

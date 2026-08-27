"""Summarize productionization evidence without turning gaps into successes.

状态一律由 ``evidence.precedence`` 裁决，不在本文件里手工写死结论：与当前提交
历史匹配的 CI 实测证据 > 本机新鲜实测证据 > 历史环境检查与历史失败记录。
本机没有容器运行时产生的历史失败因此不会再覆盖 GitHub Linux Runner 的成功结果。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evidence.precedence import (  # noqa: E402
    TIER_CI_ANCESTOR,
    TIER_CI_HEAD,
    TIER_CI_UNRELATED,
    TIER_LOCAL_FRESH,
    EvidenceResolver,
    ResolvedClaim,
)

CI_TIERS = {TIER_CI_HEAD, TIER_CI_ANCESTOR, TIER_CI_UNRELATED}

#: 只有这些状态代表"该项已经在某个测试环境实测通过"。
#: ``production_ready`` 永远不由这些状态推导——生产就绪另有独立门槛。
COMPLETED_STATUSES = {
    "completed_ci_test_environment",
    "completed_test_environment",
    "completed_ha_test_environment",
    "completed_authorized_e2e",
    "completed_authorized_data",
    "published_public",
    "published_private",
    "published_internal",
}

#: 外部环境类事项只允许使用这三种状态，禁止用"已完成"表述未验证的部署。
EXTERNAL_STATUSES = {
    "awaiting_authorized_input",
    "blocked_external_environment",
    "configuration_prepared_not_verified",
}


def load_optional(name: str) -> dict[str, Any] | None:
    path = REPORTS / name
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    return payload if isinstance(payload, dict) else None


def openclaw_model_e2e_status() -> dict[str, Any]:
    """Summarize the isolated OpenClaw model evidence as a test-only item.

    The three reports are deliberately evaluated independently from the core
    Python/OPA totals.  A missing or failed report is never represented as a
    completed production capability.
    """

    report_names = {
        "dataset": "e2e/openclaw/openclaw_agentguard_model_dataset.json",
        "cli_model_turn": "e2e/openclaw/openclaw_agentguard_model_turn.json",
        "control_ui_model_turn": "e2e/openclaw/openclaw_agentguard_control_ui_turn.json",
    }
    reports: dict[str, dict[str, Any] | None] = {
        key: load_optional(path) for key, path in report_names.items()
    }

    def report_passed(payload: dict[str, Any] | None) -> bool:
        if not isinstance(payload, dict) or payload.get("status") != "passed_with_declared_scope":
            return False
        checks = payload.get("checks")
        return isinstance(checks, dict) and bool(checks) and all(
            value is True for value in checks.values()
        )

    all_passed = all(report_passed(payload) for payload in reports.values())
    dataset_summary = (reports["dataset"] or {}).get("summary", {})
    dataset_passed = int(dataset_summary.get("passed_cases", 0) or 0)
    dataset_total = int(dataset_summary.get("total_cases", 0) or 0)

    def check_count(payload: dict[str, Any] | None) -> tuple[int, int]:
        checks = payload.get("checks", {}) if isinstance(payload, dict) else {}
        if not isinstance(checks, dict):
            return 0, 0
        return sum(1 for value in checks.values() if value is True), len(checks)

    cli_passed, cli_total = check_count(reports["cli_model_turn"])
    ui_passed, ui_total = check_count(reports["control_ui_model_turn"])
    generated_at = max(
        (
            str(payload.get("generated_at"))
            for payload in reports.values()
            if isinstance(payload, dict) and payload.get("generated_at")
        ),
        default=None,
    )
    status = "completed_test_environment" if all_passed else "not_run_or_missing"
    evidence = (
        "reports/e2e/openclaw/openclaw_agentguard_model_dataset.json；"
        "reports/e2e/openclaw/openclaw_agentguard_model_turn.json；"
        "reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json"
    )
    if all_passed:
        evidence += (
            f"（核验时间={generated_at}；固定合成模型测试集={dataset_passed}/{dataset_total}；"
            f"CLI检查={cli_passed}/{cli_total}；Control UI检查={ui_passed}/{ui_total}）"
        )
    else:
        evidence += "（缺少完整通过证据或检查未通过，未宣称完成）"
    return {
        "status": status,
        "checked_at": generated_at,
        "evidence": evidence,
        "dataset_passed": dataset_passed,
        "dataset_total": dataset_total,
        "cli_passed": cli_passed,
        "cli_total": cli_total,
        "control_ui_passed": ui_passed,
        "control_ui_total": ui_total,
        "only_allowed_tool": "agentguard-notices__list_notices",
        "scope": "loopback_static_dev_identity_and_isolated_synthetic_sqlite",
        "all_passed": all_passed,
    }


def evidence_fresh(name: str, maximum_age_hours: float = 24.0) -> bool:
    path = REPORTS / name
    if not path.exists():
        return False
    age = datetime.now(timezone.utc).timestamp() - path.stat().st_mtime
    return 0 <= age <= maximum_age_hours * 3600


def evidence_current(report: dict[str, Any] | None, run_id: str) -> bool:
    if not report:
        return False
    evidence_run = str(report.get("run_id", "missing"))
    return run_id == "standalone" or evidence_run == run_id


def command_available(name: str) -> bool:
    if shutil.which(name) is not None:
        return True
    winget_root = Path.home() / "AppData/Local/Microsoft/WinGet/Packages"
    if winget_root.exists():
        executable = f"{name}.exe"
        return any(winget_root.glob(f"*/**/{executable}"))
    return False


def evidence_age_hours(name: str) -> float | None:
    path = REPORTS / name
    if not path.exists():
        return None
    age = datetime.now(timezone.utc).timestamp() - path.stat().st_mtime
    return round(max(age, 0.0) / 3600.0, 2)


def local_suite_verdict(
    payload: dict[str, Any] | None,
    name: str,
    run_id: str,
    completed_status: str,
) -> dict[str, Any]:
    """判定"本机套件已实测通过"类事项。

    时间流逝**不会**把一次成功的实测变成失败：过期只降级为"建议复测"，
    并如实记录证据年龄。只有报告缺失、用例失败或 run_id 不匹配才算失败。
    """

    if payload is None:
        return {"status": "failed_or_missing", "freshness": "missing", "age_hours": None}
    passed = payload.get("passed")
    total = payload.get("total")
    if not isinstance(passed, int) or not isinstance(total, int) or total <= 0 or passed != total:
        return {
            "status": "failed_or_missing",
            "freshness": "recorded",
            "age_hours": evidence_age_hours(name),
        }
    if not evidence_current(payload, run_id):
        return {
            "status": "failed_or_missing",
            "freshness": "run_id_mismatch",
            "age_hours": evidence_age_hours(name),
        }
    fresh = evidence_fresh(name)
    return {
        "status": completed_status,
        "freshness": "fresh" if fresh else "stale_recheck_recommended",
        "age_hours": evidence_age_hours(name),
    }


def container_status(claim: ResolvedClaim) -> str:
    """把容器类断言的裁决结果翻译成状态字符串。"""

    if claim.verdict is not True:
        return "blocked_external_environment"
    if claim.tier in CI_TIERS:
        return "completed_ci_test_environment"
    if claim.tier == TIER_LOCAL_FRESH:
        return "completed_test_environment"
    return "blocked_external_environment"


def publication_status(claim: ResolvedClaim) -> str:
    if claim.verdict is not True:
        return "blocked_external_environment"
    publication = load_optional("status/github_publication.json") or {}
    status = str(publication.get("status", ""))
    return status if status.startswith("published_") else "blocked_external_environment"


def describe(claim: ResolvedClaim) -> str:
    """把裁决过程写成人可读的证据说明，包含被取代的历史记录。"""

    winner = claim.winning
    if winner is None:
        return "无可用证据"
    text = (
        f"{winner.source}（{winner.tier}，环境={winner.environment}，"
        f"测试时间={winner.tested_at or '未记录'}）：{winner.detail or '无补充说明'}"
    )
    if claim.superseded:
        stale = "；".join(
            f"{item.source}（{item.tier}，{item.tested_at or '未记录'}）"
            for item in claim.superseded
        )
        text += f"；已取代的历史记录：{stale}"
    return text


def main() -> int:
    resolver = EvidenceResolver(ROOT)
    envoy_claim = resolver.resolve("opa_envoy_container_e2e")
    toolhive_claim = resolver.resolve("toolhive_container_e2e")
    publication_claim = resolver.resolve("github_public_release")

    openbao = load_optional("e2e/openbao/openbao_kms_ha_e2e.json")
    openbao_raft = load_optional("e2e/openbao/openbao_raft_ha_e2e.json")
    qemu = load_optional("e2e/isolation/qemu_native_isolation_e2e.json")
    toolhive_env = load_optional("preflight/toolhive_environment_check.json") or {}
    redaction = load_optional("e2e/business/authorized_data_redaction.json")
    secret_scan = load_optional("status/prepublish_security_check.json") or {}
    business_api = load_optional("e2e/business/authorized_business_api_e2e.json") or {}
    stage4_preflight = load_optional("preflight/stage4_preflight.json") or {}
    openclaw_e2e = openclaw_model_e2e_status()
    run_id = os.environ.get("AGENTGUARD_RUN_ID", "standalone")
    credentials_present = all(
        os.environ.get(name)
        for name in (
            "AGENTGUARD_BUSINESS_API_BASE_URL",
            "AGENTGUARD_BUSINESS_API_TOKEN",
            "AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS",
        )
    )
    git_repository = (ROOT / ".git").is_dir()
    remote_urls: list[str] = []
    if git_repository:
        completed = subprocess.run(
            ["git", "remote", "get-url", "--all", "origin"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0:
            remote_urls = [line for line in completed.stdout.splitlines() if line.strip()]

    openbao_verdict = local_suite_verdict(
        openbao,
        "e2e/openbao/openbao_kms_ha_e2e.json",
        run_id,
        "completed_ha_test_environment",
    )
    openbao_raft_verdict = local_suite_verdict(
        openbao_raft,
        "e2e/openbao/openbao_raft_ha_e2e.json",
        run_id,
        "completed_ha_test_environment",
    )
    qemu_verdict = local_suite_verdict(
        qemu,
        "e2e/isolation/qemu_native_isolation_e2e.json",
        run_id,
        "completed_test_environment",
    )
    stage4_status = str(stage4_preflight.get("status", ""))
    stage4_evidence_valid = (
        stage4_status in EXTERNAL_STATUSES
        and stage4_preflight.get("preflight_valid") is True
        and stage4_preflight.get("production_ready") is False
        and stage4_preflight.get("product_validation_completed") is False
        and stage4_preflight.get("preflight_mode") == "read_only"
        and evidence_current(stage4_preflight, run_id)
    )
    if not stage4_evidence_valid:
        stage4_status = "blocked_external_environment"
    stage4_summary = stage4_preflight.get("summary", {})

    items = [
        {
            "item": "OPA-Envoy产品容器E2E",
            "status": container_status(envoy_claim),
            "evidence": describe(envoy_claim),
            "blocker": (
                "已在 GitHub Linux Runner 容器环境实测；本机 Windows 无 Docker/Podman，"
                "生产仍需 mTLS 与 NetworkPolicy 加固"
                if container_status(envoy_claim).startswith("completed")
                else "当前机器无Docker/Podman；脚本已就绪，有运行时会真实启动并做故障注入"
            ),
        },
        {
            "item": "ToolHive MCP容器E2E",
            "status": container_status(toolhive_claim),
            "evidence": (
                f"CLI/checksum={toolhive_env.get('checksum_verified', False)}；"
                + describe(toolhive_claim)
            ),
            "blocker": (
                "已在 GitHub Linux Runner 观察到命名 MCP 工作负载容器运行；"
                "doctor 在临时 Runner 上返回 1，仅作环境提示不作功能判定"
                if container_status(toolhive_claim).startswith("completed")
                else "ToolHive doctor确认没有Docker/Podman/Kubernetes"
            ),
        },
        {
            "item": "外部密钥与共享票据状态",
            "status": (
                openbao_verdict["status"]
                if openbao_verdict["status"] == openbao_raft_verdict["status"]
                else "failed_or_missing"
            ),
            "evidence": (
                f"OpenBao Transit+KV {openbao['passed']}/{openbao['total']}"
                f"（run_id={openbao.get('run_id', 'missing')}，测试时间={openbao.get('generated_at', '未记录')}，"
                f"证据年龄={openbao_verdict['age_hours']}h，{openbao_verdict['freshness']}）；"
                f"三节点Raft故障切换 {openbao_raft['passed']}/{openbao_raft['total']}"
                f"（run_id={openbao_raft.get('run_id', 'missing')}，测试时间={openbao_raft.get('generated_at', '未记录')}，"
                f"证据年龄={openbao_raft_verdict['age_hours']}h，{openbao_raft_verdict['freshness']}）"
                if openbao and openbao_raft
                else "未生成"
            ),
            "evidence_freshness": openbao_verdict["freshness"],
            "blocker": "本机三进程已验证HA；正式生产仍需跨故障域、TLS、自动解封、备份恢复和容量压测",
        },
        {
            "item": "原生程序独立来宾内核隔离",
            "status": qemu_verdict["status"],
            "evidence": (
                f"QEMU guest kernel {qemu['passed']}/{qemu['total']}"
                f"（run_id={qemu.get('run_id', 'missing')}，测试时间={qemu.get('generated_at', '未记录')}，"
                f"证据年龄={qemu_verdict['age_hours']}h，{qemu_verdict['freshness']}）"
                if qemu
                else "未生成"
            ),
            "evidence_freshness": qemu_verdict["freshness"],
            "blocker": "不是Kata/Firecracker，当前为TCG软件模拟且无KVM",
        },
        {
            "item": "阶段4外部环境与授权输入预检",
            "status": stage4_status,
            "evidence": (
                "只读预检："
                f"prepared={stage4_summary.get('prepared_not_verified', 0)}，"
                f"awaiting={stage4_summary.get('awaiting_authorized_input', 0)}，"
                f"blocked={stage4_summary.get('blocked_external_environment', 0)}；"
                "production_ready=false，product_validation_completed=false；"
                "报告=reports/preflight/stage4_preflight.json"
            ),
            "blocker": (
                "预检只核对本地前置条件、非密配置和授权输入，不替代KVM、跨故障域、"
                "Kubernetes、身份基础设施或真实业务产品E2E"
            ),
        },
        {
            "item": "真实业务系统凭据与E2E",
            "status": (
                "completed_authorized_e2e"
                if business_api.get("status", "").startswith("passed")
                else (
                    "awaiting_authorized_input"
                    if not credentials_present
                    else "configuration_prepared_not_verified"
                )
            ),
            "evidence": f"HTTPS、主机白名单、CA、幂等键、双确认写门、可信OIDC审批与对账状态已实现；报告={business_api.get('status', 'missing')}",
            "blocker": "未提供单位批准的预生产URL、令牌、CA和审批人OIDC令牌，不会生成或猜测真实凭据",
        },
        {
            "item": "脱敏生产数据",
            "status": (
                "completed_authorized_data"
                if redaction
                and redaction.get("status") == "passed"
                and evidence_fresh("e2e/business/authorized_data_redaction.json")
                and evidence_current(redaction, run_id)
                else "awaiting_authorized_input"
            ),
            "evidence": "确定性去标识、秘密字段删除、IP泛化和SHA-256报告已实现",
            "blocker": "未提供获批原始日志；测试样例不能冒充生产数据",
        },
        {
            "item": "远程GitHub仓库发布",
            "status": publication_status(publication_claim),
            "evidence": describe(publication_claim),
            "blocker": (
                "仓库已公开可读；公开发布不等于生产验收，密钥与授权数据仍不入库"
                if publication_status(publication_claim).startswith("published_")
                else "GitHub CLI和网页均未登录；不能代替用户创建账号或凭据"
            ),
        },
        {
            "item": "OpenClaw模型、CLI与Control UI回环E2E（测试范围）",
            "status": openclaw_e2e["status"],
            "checked_at": openclaw_e2e["checked_at"],
            "evidence": openclaw_e2e["evidence"],
            "blocker": (
                "固定5例合成模型测试集、CLI真实模型回合和已认证Control UI回合均通过；"
                "仅限回环静态开发身份、隔离合成SQLite与只读工具，不代表生产接入"
                if openclaw_e2e["all_passed"]
                else "OpenClaw模型回环证据缺失或未完整通过；不会把未运行内容写成完成"
            ),
            "scope": openclaw_e2e["scope"],
            "only_allowed_tool": openclaw_e2e["only_allowed_tool"],
        },
    ]

    production_ready_blockers = [
        "Kata/Firecracker 产品级 KVM 隔离未在 Linux/KVM 环境验证",
        "OpenBao 跨故障域、TLS、自动解封、快照恢复与容量压测未验证",
        "Kubernetes NetworkPolicy 与 mTLS 未在真实集群验证",
        "Keycloak HTTPS、高可用、目录联邦与真实 MFA 未验证",
        "未接入单位授权的真实业务 API",
        "未获得授权生产数据用于脱敏与回放",
    ]

    report = {
        "run_id": run_id,
        "generated_at": datetime.now().astimezone().isoformat(),
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
        "all_production_items_completed": all(
            item["status"] in COMPLETED_STATUSES for item in items
        ),
        "production_ready": False,
        "production_ready_blockers": production_ready_blockers,
        "external_status_vocabulary": sorted(EXTERNAL_STATUSES),
        "openclaw_model_e2e": openclaw_e2e,
        "items": items,
        "installed_tools": {
            "git": command_available("git"),
            "gh": command_available("gh"),
            "bao": command_available("bao")
            or any(
                Path.home().joinpath("AppData/Local/Microsoft/WinGet/Packages").glob("OpenBao.OpenBao*/bao.exe")
            ),
            "qemu_local": (ROOT / "third_party/runtime/qemu/qemu-system-x86_64.exe").exists(),
        },
        "remote_urls": remote_urls,
    }
    status_reports = REPORTS / "status"
    status_reports.mkdir(parents=True, exist_ok=True)
    json_path = status_reports / "productionization_status.json"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    rows = "\n".join(
        f"| {item['item']} | {item['status']} | {item['evidence']} | {item['blocker']} |"
        for item in items
    )
    blocker_rows = "\n".join(f"- {item}" for item in production_ready_blockers)
    markdown = f"""# AgentGuard 生产化自动推进状态

生成时间：{report['generated_at']}

## 证据优先级

状态不手工写死，由 `evidence/precedence.py` 裁决：

1. 与当前提交历史匹配的 CI 实测证据；
2. 当前机器产生的新鲜实测证据；
3. 与当前提交无关的 CI 证据；
4. 历史环境检查与历史失败记录。

因此本机缺少容器运行时产生的历史失败**不会**覆盖 GitHub Linux Runner 的成功结果；
被取代的历史文件保留原始测量值，并在文件内 `superseded_by` 字段注明测试时间、
测试环境与取代它的新证据。裁决明细见 `reports/status/evidence_precedence.json`。

| 内容 | 状态 | 当前证据 | 尚缺条件/边界 |
|---|---|---|---|
{rows}

## 生产就绪

`production_ready` = **false**。仍未满足的硬性条件：

{blocker_rows}

## 结论

已经自动完成 OpenBao 外部密钥与共享票据状态验证、三节点 Raft 选主/复制/主节点故障切换、
QEMU 独立 Linux 来宾内核隔离、OPA-Envoy 与 ToolHive 的 Linux 容器 E2E（GitHub Actions 实测）、
OpenClaw 固定合成模型测试集与 CLI/Control UI 回环模型回合（测试范围）、公开仓库发布、真实业务 HTTPS 接入代码、生产数据脱敏流水线，以及阶段4只读预检与验收模板。需要 Linux/KVM、多台服务器、
单位授权数据或真实预生产凭据的项目保留为外部阻塞，只允许使用
`awaiting_authorized_input`、`blocked_external_environment`、
`configuration_prepared_not_verified` 三种状态，不能自动伪造为完成。
"""
    (status_reports / "productionization_status.md").write_text(
        markdown, encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "items": len(items),
                "report": str(json_path),
                "opa_envoy": items[0]["status"],
                "toolhive": items[1]["status"],
                "publication": items[-1]["status"],
                "production_ready": report["production_ready"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""交叉检查各报告与文档，防止互相矛盾的状态表述重新出现。

失败即退出码 1，可直接接入 CI。检查内容：

1. 容器 E2E 与发布状态在所有报告里一致；
2. ``production_ready`` 在任何报告里都不为真；
3. 外部环境类事项只使用允许的状态枚举；
4. README 与文档不再出现已被证据推翻的表述；
5. 被取代的历史文件都带有 ``superseded_by`` 说明。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evidence.precedence import EvidenceResolver  # noqa: E402

ALLOWED_EXTERNAL_STATUSES = {
    "awaiting_authorized_input",
    "blocked_external_environment",
    "configuration_prepared_not_verified",
}

#: 一旦证据证明为真，这些说法就是过时的冲突表述。
STALE_PHRASES_WHEN_CONTAINER_PASSES = (
    "容器运行仍因本机没有 Docker/Linux 而未标记完成",
    "指定产品的容器部署未启动",
    "Envoy/ToolHive 指定产品容器尚未运行",
    "产品级 MCP 容器仍是中优先级环境项",
)
STALE_PHRASES_WHEN_PUBLISHED = (
    "远程GitHub仓库尚未发布",
    "远程私有仓库仍需用户登录GitHub后才能发布",
    "命令行和网页均未登录",
)

DOCUMENTS = (
    "README.md",
    "docs/已完成范围与缺漏问题.md",
    "docs/答辩速答.md",
    "reports/productionization_status.md",
    "reports/open_source_route_progress.md",
    "reports/full_security_evaluation_report.md",
)


def load(name: str) -> dict[str, Any] | None:
    path = REPORTS / name
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def main() -> int:
    failures: list[str] = []
    checks: dict[str, bool] = {}

    resolver = EvidenceResolver(ROOT)
    container_ok = (
        resolver.resolve("opa_envoy_container_e2e").verdict is True
        and resolver.resolve("toolhive_container_e2e").verdict is True
    )
    published = resolver.resolve("github_public_release").verdict is True

    status = load("productionization_status.json") or {}
    route = load("open_source_route_progress.json") or {}
    full = load("full_security_evaluation_summary.json") or {}
    stage4 = load("stage4_preflight.json") or {}
    public_smoke = load("public_benchmark_fixture_smoke.json") or {}

    # 1. 跨报告一致性
    route_envoy = bool(route.get("environment", {}).get("opa_envoy_product_e2e_tested"))
    route_toolhive = bool(route.get("environment", {}).get("toolhive_container_tested"))
    full_container = bool(full.get("container_product_e2e", {}).get("opa_envoy"))
    consistent = {container_ok, route_envoy, route_toolhive, full_container} == {container_ok}
    checks["container_verdict_consistent_across_reports"] = consistent
    if not consistent:
        failures.append(
            "容器 E2E 结论在报告之间不一致："
            f"裁决={container_ok}，route={route_envoy}/{route_toolhive}，full={full_container}"
        )

    route_published = bool(route.get("publication", {}).get("github_public_release"))
    full_published = bool(full.get("github_publication", {}).get("published_public"))
    publication_consistent = {published, route_published, full_published} == {published}
    checks["publication_verdict_consistent_across_reports"] = publication_consistent
    if not publication_consistent:
        failures.append(
            f"发布状态不一致：裁决={published}，route={route_published}，full={full_published}"
        )

    # 2. production_ready 必须为 false
    ready_flags = {
        "productionization_status.json": status.get("production_ready", False),
        "open_source_route_progress.json": route.get("overall", {}).get(
            "production_ready", False
        ),
        "stage4_preflight.json": stage4.get("production_ready", False),
    }
    ready_ok = not any(bool(value) for value in ready_flags.values())
    checks["production_ready_is_false_everywhere"] = ready_ok
    if not ready_ok:
        failures.append(f"production_ready 必须为 false，实际为 {ready_flags}")

    # 3. 外部事项状态枚举
    external_items = [
        item
        for item in status.get("items", [])
        if isinstance(item, dict)
        and not str(item.get("status", "")).startswith(("completed", "published"))
    ]
    bad_statuses = [
        f"{item.get('item')}={item.get('status')}"
        for item in external_items
        if str(item.get("status", "")) not in ALLOWED_EXTERNAL_STATUSES
    ]
    checks["external_items_use_allowed_status_vocabulary"] = not bad_statuses
    if bad_statuses:
        failures.append(f"外部事项使用了不允许的状态：{bad_statuses}")

    stage4_domains = stage4.get("domains", {})
    stage4_statuses = [
        item.get("status")
        for item in stage4_domains.values()
        if isinstance(item, dict)
    ] if isinstance(stage4_domains, dict) else []
    stage4_contract_ok = (
        stage4.get("status") in ALLOWED_EXTERNAL_STATUSES
        and stage4.get("preflight_valid") is True
        and bool(stage4_statuses)
        and all(item in ALLOWED_EXTERNAL_STATUSES for item in stage4_statuses)
        and stage4.get("production_ready") is False
        and stage4.get("product_validation_completed") is False
        and stage4.get("preflight_mode") == "read_only"
    )
    checks["stage4_preflight_keeps_read_only_status_contract"] = stage4_contract_ok
    if not stage4_contract_ok:
        failures.append("阶段4预检缺失、状态越界，或错误宣称产品验证/生产就绪")

    public_benchmarks = public_smoke.get("benchmarks", {})
    public_contract_ok = (
        public_smoke.get("kind") == "adapter_contract_smoke_test"
        and public_smoke.get("uses_synthetic_fixtures") is True
        and public_smoke.get("uses_upstream_raw_data") is False
        and public_smoke.get("aggregate_metrics") is None
        and isinstance(public_benchmarks, dict)
        and set(public_benchmarks) == {"agentdojo", "injecagent", "agentharm"}
        and all(
            isinstance(item, dict)
            and item.get("result") == "passed"
            and int(item.get("denominator", 0)) > 0
            for item in public_benchmarks.values()
        )
    )
    checks["public_benchmark_fixture_is_not_reported_as_real_score"] = public_contract_ok
    if not public_contract_ok:
        failures.append("公开基准fixture报告缺失，或未明确合成来源/独立分母/无聚合成绩")

    # 4. 文档不得保留已被推翻的表述
    stale_hits: list[str] = []
    for relative in DOCUMENTS:
        path = ROOT / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if container_ok:
            stale_hits.extend(
                f"{relative}: {phrase}"
                for phrase in STALE_PHRASES_WHEN_CONTAINER_PASSES
                if phrase in text
            )
        if published:
            stale_hits.extend(
                f"{relative}: {phrase}"
                for phrase in STALE_PHRASES_WHEN_PUBLISHED
                if phrase in text
            )
    checks["documents_free_of_superseded_claims"] = not stale_hits
    if stale_hits:
        failures.append(f"文档仍包含已被证据推翻的表述：{stale_hits}")

    # 5. 被取代的历史文件必须带说明
    precedence = load("evidence_precedence.json") or {}
    missing_annotation: list[str] = []
    for claim in precedence.get("claims", {}).values():
        for stale in claim.get("superseded_evidence", []):
            path = ROOT / stale["source"]
            if not path.is_file():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8-sig"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(payload, dict) or "superseded_by" not in payload:
                missing_annotation.append(stale["source"])
    checks["superseded_history_files_are_annotated"] = not missing_annotation
    if missing_annotation:
        failures.append(f"历史文件缺少取代说明：{sorted(set(missing_annotation))}")

    report = {
        "generated_at": resolver.now.astimezone().isoformat(timespec="seconds"),
        "status": "passed" if not failures else "failed",
        "container_e2e_verdict": container_ok,
        "github_public_release_verdict": published,
        "checks": checks,
        "passed": sum(1 for value in checks.values() if value),
        "total": len(checks),
        "failures": failures,
    }
    (REPORTS / "status_consistency_check.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: report[k] for k in ("status", "passed", "total", "failures")}, ensure_ascii=False))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

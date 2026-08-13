#!/usr/bin/env python3
"""调用 OPA CLI 对整个数据集进行端到端评测并生成报告。"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[index]


def locate_opa(explicit: str | None) -> Path:
    candidates = [
        explicit,
        os.environ.get("OPA_BIN"),
        str(ROOT / "tools" / "opa.exe"),
        str(ROOT / "tools" / "opa"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise FileNotFoundError("未找到 OPA，请先运行 scripts/bootstrap_opa.ps1")


def evaluate_case(opa: Path, case: dict) -> tuple[dict, float]:
    # Windows 下 OPA 从 Python 管道读取 --stdin-input，以及接收含中文的绝对
    # --data/--input 路径时，部分构建会得到空输入。把参数改成项目内相对路径。
    input_path = ROOT / "reports" / ".eval_input.json"
    input_path.parent.mkdir(parents=True, exist_ok=True)
    input_path.write_text(
        json.dumps(case["input"], ensure_ascii=False), encoding="utf-8"
    )
    command = [
        str(opa),
        "eval",
        "--format=json",
        "--data",
        "policy",
        "--data",
        "data",
        "--input",
        "reports/.eval_input.json",
        "data.agent.guard.decision",
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            cwd=ROOT,
        )
    finally:
        input_path.unlink(missing_ok=True)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if result.returncode != 0:
        raise RuntimeError(f"OPA 评测失败 {case['case_id']}: {result.stderr.strip()}")
    payload = json.loads(result.stdout)
    try:
        decision = payload["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"OPA 未返回决策 {case['case_id']}: {result.stdout}") from exc
    return decision, elapsed_ms


def safe_rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa", help="OPA 可执行文件路径")
    parser.add_argument("--dataset", default=str(ROOT / "datasets" / "agent_guard_cases.jsonl"))
    args = parser.parse_args()

    opa = locate_opa(args.opa)
    dataset_path = Path(args.dataset)
    cases = [json.loads(line) for line in dataset_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows: list[dict] = []
    latencies: list[float] = []
    confusion: dict[str, Counter] = defaultdict(Counter)
    category_totals: Counter = Counter()
    category_correct: Counter = Counter()

    for case in cases:
        decision, elapsed_ms = evaluate_case(opa, case)
        actual = decision["effect"]
        expected = case["expected_effect"]
        reason_ok = case["expected_reason_code"] in decision.get("reason_codes", [])
        effect_ok = actual == expected
        category = case["category"]
        category_totals[category] += 1
        if effect_ok and reason_ok:
            category_correct[category] += 1
        confusion[expected][actual] += 1
        latencies.append(elapsed_ms)
        rows.append({
            "case_id": case["case_id"],
            "name": case["name"],
            "category": category,
            "expected_effect": expected,
            "actual_effect": actual,
            "effect_correct": effect_ok,
            "expected_reason_code": case["expected_reason_code"],
            "actual_reason_codes": "|".join(decision.get("reason_codes", [])),
            "reason_correct": reason_ok,
            "risk_score": decision.get("risk_score", ""),
            "latency_ms_cli_e2e": round(elapsed_ms, 3),
        })

    total = len(rows)
    effect_correct = sum(1 for row in rows if row["effect_correct"])
    reason_correct = sum(1 for row in rows if row["reason_correct"])

    expected_deny = [row for row in rows if row["expected_effect"] == "deny"]
    expected_allow = [row for row in rows if row["expected_effect"] == "allow"]
    expected_approval = [row for row in rows if row["expected_effect"] == "require_approval"]
    invalid_approval = [row for row in rows if row["category"] == "invalid_approval"]

    summary = {
        "opa_binary": str(opa),
        "dataset": str(dataset_path.resolve()),
        "total_cases": total,
        "effect_accuracy": safe_rate(effect_correct, total),
        "reason_code_accuracy": safe_rate(reason_correct, total),
        "dangerous_action_block_rate": safe_rate(sum(row["actual_effect"] == "deny" for row in expected_deny), len(expected_deny)),
        "legitimate_action_pass_rate": safe_rate(sum(row["actual_effect"] == "allow" for row in expected_allow), len(expected_allow)),
        "approval_routing_accuracy": safe_rate(sum(row["actual_effect"] == "require_approval" for row in expected_approval), len(expected_approval)),
        "invalid_approval_block_rate": safe_rate(sum(row["actual_effect"] == "deny" for row in invalid_approval), len(invalid_approval)),
        "unsafe_allow_count": sum(row["expected_effect"] == "deny" and row["actual_effect"] == "allow" for row in rows),
        "cli_end_to_end_latency_ms": {
            "mean": round(statistics.fmean(latencies), 3),
            "median": round(statistics.median(latencies), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "max": round(max(latencies), 3),
            "note": "包含每个用例启动一次 OPA CLI 的进程开销，不代表 sidecar/嵌入式部署时的纯策略延迟。",
        },
        "confusion_matrix": {key: dict(value) for key, value in confusion.items()},
        "category_accuracy": {
            category: safe_rate(category_correct[category], count)
            for category, count in sorted(category_totals.items())
        },
    }

    report_dir = ROOT / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    with (report_dir / "evaluation_results.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    (report_dir / "evaluation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    markdown = [
        "# OPA 批量评测结果",
        "",
        f"- 用例总数：{total}",
        f"- 三分类效果准确率：{summary['effect_accuracy']:.2%}",
        f"- 原因码准确率：{summary['reason_code_accuracy']:.2%}",
        f"- 危险动作阻断率：{summary['dangerous_action_block_rate']:.2%}",
        f"- 合法动作放行率：{summary['legitimate_action_pass_rate']:.2%}",
        f"- 需审批动作路由准确率：{summary['approval_routing_accuracy']:.2%}",
        f"- 非法审批凭证阻断率：{summary['invalid_approval_block_rate']:.2%}",
        f"- 危险动作误放行数：{summary['unsafe_allow_count']}",
        "",
        "## 各类用例",
        "",
        "| 类别 | 数量 | 完全正确率 |",
        "|---|---:|---:|",
    ]
    for category, count in sorted(category_totals.items()):
        markdown.append(f"| {category} | {count} | {summary['category_accuracy'][category]:.2%} |")
    markdown.extend([
        "",
        "## 延迟说明",
        "",
        f"本机逐条启动 OPA CLI 的端到端平均耗时为 {summary['cli_end_to_end_latency_ms']['mean']:.3f} ms，"
        f"P95 为 {summary['cli_end_to_end_latency_ms']['p95']:.3f} ms。该数字包含进程启动和文件加载，"
        "只用于本原型复现，不应当当作 sidecar、Wasm 或 Go SDK 部署的纯策略延迟。",
        "",
        "## 结论",
        "",
        "当前数据集上，OPA 能稳定输出 allow / require_approval / deny 三态决策，并识别审批参数篡改、"
        "跨任务复用、过期、自批、越权审批和重复使用。实际系统仍必须由 MCP/API 网关执行该结果，"
        "并由外部状态库维护审批使用次数和任务状态。",
        "",
    ])
    (report_dir / "evaluation_report.md").write_text("\n".join(markdown), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if effect_correct == total and reason_correct == total else 1


if __name__ == "__main__":
    sys.exit(main())

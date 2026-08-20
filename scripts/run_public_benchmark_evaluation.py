#!/usr/bin/env python3
"""公开基准转换、验证与独立评测入口。

脚本不自动下载原始数据，不执行数据中的指令。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.adapters import ADAPTERS, convert_records  # noqa: E402
from evaluation.evaluator import evaluate_predictions  # noqa: E402
from evaluation.io import load_records, write_json, write_jsonl  # noqa: E402
from evaluation.validation import (  # noqa: E402
    deduplicate_cases,
    dataset_statistics,
    deterministic_split,
    normalize_source_path,
    validate_case,
)


METADATA_PATH = ROOT / "datasets/public/public_benchmarks.metadata.json"
FIXTURE_DIR = ROOT / "evaluation/tests/fixtures"
REPORT_DIR = ROOT / "reports"


class CliArgumentParser(argparse.ArgumentParser):
    """用户配置或数据错误统一返回 1；2 保留给未来外部等待状态。"""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(1, f"ERROR: {message}\n")


def metadata() -> dict:
    return json.loads(METADATA_PATH.read_text(encoding="utf-8"))


def command_convert(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    input_bytes = input_path.read_bytes()
    rows = load_records(input_path)
    if not rows:
        raise ValueError("转换输入不得为空")
    source_path = normalize_source_path(args.source_path or input_path.name)
    converted = convert_records(
        args.benchmark, rows, source_revision=args.source_revision,
        source_path=source_path, split=args.split,
    )
    if args.deterministic_split:
        if args.split != "unknown":
            raise ValueError("--deterministic-split 不能与显式 --split 同时使用")
        for case in converted:
            case["split"] = deterministic_split(case["content_hash"])
    kept, duplicates = deduplicate_cases(converted)
    if args.fail_on_duplicates and duplicates:
        raise ValueError(f"检出 {len(duplicates)} 条重复记录")
    write_jsonl(Path(args.output), kept)
    report = {
        "schema_version": "1.0",
        "benchmark": args.benchmark,
        "source_revision": args.source_revision,
        "source_path": source_path,
        "data_source_type": args.data_source_type,
        "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
        "input_bytes": len(input_bytes),
        "input_count": len(rows),
        "output_count": len(kept),
        "duplicate_count": len(duplicates),
        "duplicates": duplicates,
        "statistics": dataset_statistics(kept),
        "raw_data_bundled_by_agentguard": False,
    }
    report_path = Path(args.report) if args.report else Path(args.output).with_suffix(".report.json")
    write_json(report_path, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    rows = load_records(Path(args.input))
    if not rows:
        raise ValueError("验证输入不得为空")
    for row in rows:
        validate_case(row)
    kept, duplicates = deduplicate_cases(rows)
    report = {
        "schema_version": "1.0", "valid": True, "case_count": len(rows),
        "unique_count": len(kept), "duplicate_count": len(duplicates),
        "statistics_by_benchmark": {
            name: dataset_statistics(row for row in kept if row["benchmark"] == name)
            for name in sorted({row["benchmark"] for row in kept})
        },
    }
    if args.report:
        write_json(Path(args.report), report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not (args.fail_on_duplicates and duplicates) else 1


def command_evaluate(args: argparse.Namespace) -> int:
    cases = load_records(Path(args.cases))
    predictions = load_records(Path(args.predictions))
    if args.benchmark:
        cases = [row for row in cases if row.get("benchmark") == args.benchmark]
        predictions = [row for row in predictions if row.get("benchmark") == args.benchmark]
        if not cases:
            raise ValueError(f"按 benchmark={args.benchmark} 过滤后用例为 0")
    report = evaluate_predictions(cases, predictions, require_complete=not args.allow_missing)
    write_json(Path(args.output), report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def command_smoke(_: argparse.Namespace) -> int:
    manifest = metadata()
    index: dict[str, object] = {
        "schema_version": "1.0",
        "kind": "adapter_contract_smoke_test",
        "uses_upstream_raw_data": False,
        "uses_synthetic_fixtures": True,
        "benchmarks": {},
        "aggregate_metrics": None,
        "aggregation_note": "只验证转换、规范和评测管线，不是模型或策略效果成绩。",
    }
    for benchmark in ADAPTERS:
        item = manifest["benchmarks"][benchmark]
        rows = load_records(FIXTURE_DIR / f"{benchmark}.json")
        cases = convert_records(
            benchmark, rows, source_revision=item["reviewed_revision"],
            source_path=f"evaluation/tests/fixtures/{benchmark}.json",
            split="unknown" if benchmark == "agentharm" else "test",
        )
        cases, duplicates = deduplicate_cases(cases)
        predictions = [{
            "benchmark": row["benchmark"], "source_id": row["source_id"],
            "predicted_security_outcome": row["expected_security_outcome"],
        } for row in cases]
        evaluation = evaluate_predictions(cases, predictions)
        benchmark_report = {
            "benchmark": benchmark,
            "data_source_type": "synthetic_fixture",
            "uses_synthetic_fixtures": True,
            "uses_upstream_raw_data": False,
            "is_upstream_benchmark_result": False,
            "fixture_count": len(cases),
            "duplicate_count": len(duplicates),
            "statistics": dataset_statistics(cases),
            "evaluation": evaluation["benchmarks"][benchmark],
            "result": "passed",
            "limitation": "合成 fixture 的预期标签回放，只证明管线可运行。",
        }
        write_json(REPORT_DIR / f"public_benchmark_{benchmark}_fixture.json", benchmark_report)
        index["benchmarks"][benchmark] = {
            "result": "passed", "denominator": len(cases),
            "report": f"reports/public_benchmark_{benchmark}_fixture.json",
        }
    write_json(REPORT_DIR / "public_benchmark_fixture_smoke.json", index)
    print(json.dumps(index, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = CliArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    meta = subparsers.add_parser("metadata", help="显示上游来源、版本和许可边界")
    meta.set_defaults(func=lambda _: (print(json.dumps(metadata(), ensure_ascii=False, indent=2)) or 0))

    convert = subparsers.add_parser("convert", help="转换用户自行获取的上游 JSON/JSONL")
    convert.add_argument("--benchmark", choices=sorted(ADAPTERS), required=True)
    convert.add_argument("--input", required=True)
    convert.add_argument("--output", required=True)
    convert.add_argument("--source-revision", required=True)
    convert.add_argument("--source-path")
    convert.add_argument(
        "--data-source-type",
        choices=["official_upstream_export", "user_supplied_local_file", "synthetic_fixture"],
        default="user_supplied_local_file",
    )
    convert.add_argument("--split", default="unknown", choices=["train", "validation", "test", "test_public", "test_public_benign", "unknown"])
    convert.add_argument(
        "--deterministic-split", action="store_true",
        help="按内容指纹稳定拆分为 80% train / 10% validation / 10% test",
    )
    convert.add_argument("--report")
    convert.add_argument("--fail-on-duplicates", action="store_true")
    convert.set_defaults(func=command_convert)

    validate = subparsers.add_parser("validate", help="严格验证规范化 JSON/JSONL")
    validate.add_argument("--input", required=True)
    validate.add_argument("--report")
    validate.add_argument("--fail-on-duplicates", action="store_true")
    validate.set_defaults(func=command_validate)

    evaluate = subparsers.add_parser("evaluate", help="根据外部系统的三态预测进行独立评测")
    evaluate.add_argument("--cases", required=True)
    evaluate.add_argument("--predictions", required=True)
    evaluate.add_argument("--output", required=True)
    evaluate.add_argument("--benchmark", choices=sorted(ADAPTERS))
    evaluate.add_argument("--allow-missing", action="store_true")
    evaluate.set_defaults(func=command_evaluate)

    smoke = subparsers.add_parser("smoke", help="使用六条合成 fixture 验证管线")
    smoke.set_defaults(func=command_smoke)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

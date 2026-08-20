from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from evaluation.adapters import AdapterError, convert_records
from evaluation.evaluator import PredictionError, evaluate_predictions
from evaluation.io import load_records
from evaluation.validation import (
    ValidationError,
    calculate_content_hash,
    deduplicate_cases,
    deterministic_split,
    normalize_source_path,
    validate_case,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
REVISIONS = {
    "agentdojo": "089ed468cf3ed0322acc66b0211f26d9d90dbf60",
    "injecagent": "f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
    "agentharm": "79a8ff566f37a8fb9d50a9fb51535f293057321d",
}


def fixture_cases(benchmark: str) -> list[dict]:
    return convert_records(
        benchmark,
        load_records(FIXTURES / f"{benchmark}.json"),
        source_revision=REVISIONS[benchmark],
        source_path=f"evaluation/tests/fixtures/{benchmark}.json",
        split="test" if benchmark != "agentharm" else "unknown",
    )


class AdapterTests(unittest.TestCase):
    def test_all_fixture_adapters_produce_strict_cases(self) -> None:
        for benchmark in REVISIONS:
            with self.subTest(benchmark=benchmark):
                cases = fixture_cases(benchmark)
                self.assertEqual(2, len(cases))
                for case in cases:
                    self.assertIs(validate_case(case), case)
                    self.assertEqual(benchmark, case["benchmark"])

    def test_expected_semantics_are_not_mixed(self) -> None:
        dojo = fixture_cases("agentdojo")
        self.assertEqual(["allow", "deny"], [row["expected_security_outcome"] for row in dojo])
        injec = fixture_cases("injecagent")
        self.assertEqual({"direct_harm", "data_exfiltration"}, {row["threat_type"] for row in injec})
        harm = fixture_cases("agentharm")
        self.assertEqual({"test_public", "test_public_benign"}, {row["split"] for row in harm})

    def test_injecagent_official_title_case_fields_and_literal_parameters(self) -> None:
        case = fixture_cases("injecagent")[0]
        self.assertEqual({"folder": "project"}, case["requested_actions"][0]["parameters"])

    def test_missing_required_upstream_text_fails_loudly(self) -> None:
        with self.assertRaises(AdapterError):
            convert_records(
                "agentdojo", [{"id": "bad"}], source_revision="abc",
                source_path="bad.json", split="test",
            )

    def test_agentharm_rejects_string_boolean(self) -> None:
        with self.assertRaises(AdapterError):
            convert_records(
                "agentharm", [{"id": "bad", "prompt": "x", "harmful": "false"}],
                source_revision="abc", source_path="bad.json", split="test",
            )

    def test_agentharm_unknown_split_requires_explicit_harmful_label(self) -> None:
        with self.assertRaisesRegex(AdapterError, "split.*unknown"):
            convert_records(
                "agentharm", [{"id": "ambiguous", "prompt": "ambiguous fixture"}],
                source_revision="abc", source_path="data/agentharm.json", split="unknown",
            )

    def test_source_path_rejects_absolute_and_sensitive_local_paths(self) -> None:
        for value in (
            "C:/Users/Alice/data.json",
            "/home/alice/data.json",
            "../../private.json",
            "data/.ssh/id_rsa",
            "private_data/cases.json",
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                normalize_source_path(value)
        self.assertEqual("data/cases.json", normalize_source_path("data\\cases.json"))


class ValidationTests(unittest.TestCase):
    def test_unknown_field_is_rejected(self) -> None:
        case = fixture_cases("agentdojo")[0]
        case["unexpected"] = True
        with self.assertRaises(ValidationError):
            validate_case(case)

    def test_tampered_content_hash_is_rejected(self) -> None:
        case = fixture_cases("agentdojo")[0]
        case["user_goal"] = "被修改"
        with self.assertRaisesRegex(ValidationError, "content_hash"):
            validate_case(case)

    def test_deduplication_is_within_benchmark_and_stable(self) -> None:
        case = fixture_cases("agentdojo")[0]
        duplicate = copy.deepcopy(case)
        duplicate["source_id"] = "another-id"
        kept, removed = deduplicate_cases([case, duplicate])
        self.assertEqual(1, len(kept))
        self.assertEqual("another-id", removed[0]["source_id"])
        self.assertEqual(case["source_id"], removed[0]["duplicate_of"])

    def test_same_semantic_input_with_conflicting_label_is_rejected(self) -> None:
        case = fixture_cases("agentdojo")[0]
        conflict = copy.deepcopy(case)
        conflict["source_id"] = "conflicting-label"
        conflict["expected_security_outcome"] = "deny"
        # 期望标签不参与输入指纹，因此该冲突必须被显式发现。
        self.assertEqual(case["content_hash"], conflict["content_hash"])
        with self.assertRaisesRegex(ValidationError, "冲突标签"):
            deduplicate_cases([case, conflict])

    def test_same_source_id_with_different_content_is_rejected_by_validation(self) -> None:
        case = fixture_cases("agentdojo")[0]
        conflict = copy.deepcopy(case)
        conflict["user_goal"] = "different input"
        conflict["content_hash"] = calculate_content_hash(conflict)
        with self.assertRaisesRegex(ValidationError, "source_id"):
            deduplicate_cases([case, conflict])

    def test_deterministic_split(self) -> None:
        digest = fixture_cases("agentdojo")[0]["content_hash"]
        self.assertEqual(deterministic_split(digest), deterministic_split(digest))


class EvaluationTests(unittest.TestCase):
    def test_reports_keep_independent_denominators(self) -> None:
        cases = fixture_cases("agentdojo") + fixture_cases("injecagent") + fixture_cases("agentharm")
        predictions = [
            {
                "benchmark": case["benchmark"],
                "source_id": case["source_id"],
                "predicted_security_outcome": case["expected_security_outcome"],
            }
            for case in cases
        ]
        report = evaluate_predictions(cases, predictions)
        self.assertIsNone(report["aggregate_metrics"])
        self.assertEqual({"agentdojo", "injecagent", "agentharm"}, set(report["benchmarks"]))
        self.assertTrue(all(item["denominator"] == 2 for item in report["benchmarks"].values()))
        self.assertTrue(all(item["exact_outcome_accuracy"] == 1.0 for item in report["benchmarks"].values()))

    def test_missing_prediction_fails_in_strict_mode(self) -> None:
        with self.assertRaises(PredictionError):
            evaluate_predictions(fixture_cases("agentdojo"), [])

    def test_unknown_prediction_case_fails(self) -> None:
        cases = fixture_cases("agentdojo")
        with self.assertRaises(PredictionError):
            evaluate_predictions(cases, [{
                "benchmark": "agentdojo",
                "source_id": "unknown",
                "predicted_security_outcome": "deny",
            }])

    def test_empty_cases_are_rejected(self) -> None:
        with self.assertRaisesRegex(PredictionError, "不得为空"):
            evaluate_predictions([], [])

    def test_semantic_duplicate_cases_are_rejected_not_counted(self) -> None:
        first = fixture_cases("agentdojo")[0]
        duplicate = copy.deepcopy(first)
        duplicate["source_id"] = "semantic-duplicate"
        with self.assertRaisesRegex(PredictionError, "语义重复"):
            evaluate_predictions([first, duplicate], [])

    def test_same_benchmark_and_source_id_conflict_is_rejected(self) -> None:
        first = fixture_cases("agentdojo")[0]
        conflict = copy.deepcopy(first)
        conflict["user_goal"] = "different input"
        conflict["content_hash"] = calculate_content_hash(conflict)
        with self.assertRaisesRegex(PredictionError, "source_id"):
            evaluate_predictions([first, conflict], [])


class MetadataTests(unittest.TestCase):
    def test_metadata_records_source_revision_license_and_no_raw_bundle(self) -> None:
        metadata = json.loads((ROOT / "datasets/public/public_benchmarks.metadata.json").read_text(encoding="utf-8"))
        self.assertFalse(metadata["raw_data_bundled"])
        self.assertFalse(metadata["fixtures_are_upstream_data"])
        self.assertEqual(set(REVISIONS), set(metadata["benchmarks"]))
        for benchmark, item in metadata["benchmarks"].items():
            self.assertEqual(REVISIONS[benchmark], item["reviewed_revision"])
            self.assertTrue(item["license"]["source"].startswith("https://"))
            self.assertTrue(item["license"]["spdx_id"])


class CommandLineTests(unittest.TestCase):
    def test_convert_supports_deterministic_split_without_touching_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "normalized.jsonl"
            report = Path(temporary) / "conversion.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/run_public_benchmark_evaluation.py"),
                    "convert",
                    "--benchmark", "agentdojo",
                    "--input", str(FIXTURES / "agentdojo.json"),
                    "--output", str(output),
                    "--report", str(report),
                    "--source-revision", REVISIONS["agentdojo"],
                    "--source-path", "synthetic/agentdojo.json",
                    "--data-source-type", "synthetic_fixture",
                    "--deterministic-split",
                ],
                cwd=ROOT,
                text=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            cases = load_records(output)
            self.assertTrue(all(case["split"] in {"train", "validation", "test"} for case in cases))
            report_payload = json.loads(report.read_text(encoding="utf-8"))
            fixture_bytes = (FIXTURES / "agentdojo.json").read_bytes()
            self.assertEqual(2, report_payload["output_count"])
            self.assertEqual("synthetic_fixture", report_payload["data_source_type"])
            self.assertEqual(len(fixture_bytes), report_payload["input_bytes"])
            self.assertEqual(
                hashlib.sha256(fixture_bytes).hexdigest(),
                report_payload["input_sha256"],
            )

    def test_filter_to_zero_cases_returns_configuration_error_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cases_path = Path(temporary) / "cases.jsonl"
            predictions_path = Path(temporary) / "predictions.jsonl"
            cases_path.write_text(
                json.dumps(fixture_cases("agentdojo")[0], ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            predictions_path.write_text("", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/run_public_benchmark_evaluation.py"),
                    "evaluate", "--benchmark", "agentharm",
                    "--cases", str(cases_path),
                    "--predictions", str(predictions_path),
                    "--output", str(Path(temporary) / "report.json"),
                ],
                cwd=ROOT, text=True, encoding="utf-8",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("过滤后用例为 0", result.stderr)

    def test_cli_argument_error_returns_one(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_public_benchmark_evaluation.py"), "metadata", "--bad"],
            cwd=ROOT, text=True, encoding="utf-8",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        self.assertEqual(1, result.returncode)

    def test_convert_rejects_absolute_source_path_without_leaking_it_to_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "conversion.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/run_public_benchmark_evaluation.py"),
                    "convert", "--benchmark", "agentdojo",
                    "--input", str(FIXTURES / "agentdojo.json"),
                    "--output", str(Path(temporary) / "normalized.jsonl"),
                    "--report", str(report),
                    "--source-revision", REVISIONS["agentdojo"],
                    "--source-path", "C:/Users/Alice/private.json",
                ],
                cwd=ROOT, text=True, encoding="utf-8",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
            self.assertEqual(1, result.returncode)
            self.assertFalse(report.exists())

    def test_smoke_reports_machine_readable_synthetic_provenance(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_public_benchmark_evaluation.py"), "smoke"],
            cwd=ROOT, text=True, encoding="utf-8",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        for benchmark in REVISIONS:
            payload = json.loads(
                (ROOT / f"reports/public_benchmark_{benchmark}_fixture.json").read_text(encoding="utf-8")
            )
            self.assertEqual("synthetic_fixture", payload["data_source_type"])
            self.assertTrue(payload["uses_synthetic_fixtures"])
            self.assertFalse(payload["uses_upstream_raw_data"])
            self.assertFalse(payload["is_upstream_benchmark_result"])


if __name__ == "__main__":
    unittest.main()

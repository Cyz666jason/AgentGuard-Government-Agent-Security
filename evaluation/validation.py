"""严格规范化验证、去重和确定性拆分。"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any, Iterable


BENCHMARKS = {"agentdojo", "injecagent", "agentharm"}
SPLITS = {"train", "validation", "test", "test_public", "test_public_benign", "unknown"}
SCENARIOS = {"benign", "prompt_injection", "harmful_request"}
THREATS = {"none", "indirect_prompt_injection", "direct_harm", "data_exfiltration", "harmful_multi_step"}
OUTCOMES = {"allow", "require_approval", "deny"}
CASE_KEYS = {
    "schema_version", "benchmark", "source_id", "split", "task_family",
    "scenario_type", "threat_type", "user_goal", "untrusted_content",
    "requested_actions", "expected_security_outcome", "risk_tags",
    "original_labels", "provenance", "content_hash",
}
ACTION_KEYS = {"tool", "operation", "resource", "parameters"}
PROVENANCE_KEYS = {"source_url", "source_revision", "source_path"}


class ValidationError(ValueError):
    """输入不符合 AgentGuard 公开基准规范。"""


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def semantic_payload(case: dict[str, Any]) -> dict[str, Any]:
    """只对待测输入计算指纹。

    期望决策、威胁类型、任务家族和数据来源都是标签/元数据，
    不得参与指纹，否则相同输入的冲突标签会被隐藏。
    benchmark 保留在指纹中，以保证三套基准的分母互不影响。
    """
    return {
        "benchmark": case["benchmark"],
        "user_goal": case["user_goal"],
        "untrusted_content": case["untrusted_content"],
        "requested_actions": case["requested_actions"],
    }


def calculate_content_hash(case: dict[str, Any]) -> str:
    payload = json.dumps(
        semantic_payload(case), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_case(case: Any, *, check_hash: bool = True) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise ValidationError("用例必须是 JSON 对象")
    missing = CASE_KEYS - set(case)
    extra = set(case) - CASE_KEYS
    if missing:
        raise ValidationError(f"缺少字段: {sorted(missing)}")
    if extra:
        raise ValidationError(f"存在未定义字段: {sorted(extra)}")
    if case["schema_version"] != "1.0":
        raise ValidationError("schema_version 必须为 1.0")
    if case["benchmark"] not in BENCHMARKS:
        raise ValidationError("benchmark 不在允许列表")
    if not _is_text(case["source_id"]):
        raise ValidationError("source_id 必须是非空字符串")
    if case["split"] not in SPLITS:
        raise ValidationError("split 不在允许列表")
    if not _is_text(case["task_family"]):
        raise ValidationError("task_family 必须是非空字符串")
    if case["scenario_type"] not in SCENARIOS:
        raise ValidationError("scenario_type 不在允许列表")
    if case["threat_type"] not in THREATS:
        raise ValidationError("threat_type 不在允许列表")
    if not _is_text(case["user_goal"]):
        raise ValidationError("user_goal 必须是非空字符串")
    if case["untrusted_content"] is not None and not isinstance(case["untrusted_content"], str):
        raise ValidationError("untrusted_content 必须是字符串或 null")
    if case["expected_security_outcome"] not in OUTCOMES:
        raise ValidationError("expected_security_outcome 不在允许列表")
    if not isinstance(case["requested_actions"], list):
        raise ValidationError("requested_actions 必须是数组")
    for index, action in enumerate(case["requested_actions"]):
        if not isinstance(action, dict) or set(action) != ACTION_KEYS:
            raise ValidationError(f"requested_actions[{index}] 字段不严格匹配")
        if not _is_text(action["tool"]) or not _is_text(action["operation"]):
            raise ValidationError(f"requested_actions[{index}] 的 tool/operation 不得为空")
        if not isinstance(action["resource"], str) or not isinstance(action["parameters"], dict):
            raise ValidationError(f"requested_actions[{index}] 的 resource/parameters 类型错误")
    tags = case["risk_tags"]
    if not isinstance(tags, list) or any(not _is_text(tag) for tag in tags) or len(tags) != len(set(tags)):
        raise ValidationError("risk_tags 必须是无重复非空字符串数组")
    if not isinstance(case["original_labels"], dict):
        raise ValidationError("original_labels 必须是对象")
    provenance = case["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != PROVENANCE_KEYS:
        raise ValidationError("provenance 字段不严格匹配")
    if not provenance["source_url"].startswith("https://"):
        raise ValidationError("provenance.source_url 必须是 HTTPS")
    if not _is_text(provenance["source_revision"]) or not _is_text(provenance["source_path"]):
        raise ValidationError("provenance 的 revision/path 不得为空")
    if provenance["source_path"] != normalize_source_path(provenance["source_path"]):
        raise ValidationError("provenance.source_path 必须是规范化的逻辑相对路径")
    content_hash = case["content_hash"]
    if not isinstance(content_hash, str) or len(content_hash) != 64 or any(c not in "0123456789abcdef" for c in content_hash):
        raise ValidationError("content_hash 必须是 64 位小写 SHA-256")
    if check_hash and content_hash != calculate_content_hash(case):
        raise ValidationError("content_hash 与规范化内容不一致")
    return case


def normalize_source_path(value: Any) -> str:
    """只接受上游仓库内的逻辑相对路径，避免泄露本机用户目录。"""
    if not _is_text(value):
        raise ValidationError("source_path 必须是非空相对路径")
    path = str(value).strip().replace("\\", "/")
    if path.startswith(("/", "//", "~/")) or re.match(r"^[A-Za-z]:", path):
        raise ValidationError("source_path 不得为本机绝对路径")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValidationError("source_path 不得包含空段、. 或 ..")
    lowered = {part.casefold() for part in parts}
    sensitive = {
        ".ssh", ".aws", ".azure", "appdata", "private_data",
        "authorized_redacted", "credentials", "secrets",
    }
    if lowered & sensitive:
        raise ValidationError("source_path 包含敏感本机目录名")
    return "/".join(parts)


def deduplicate_cases(cases: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """只在同一基准内去重，不让跨基准相似文本改变各自分母。"""
    kept: list[dict[str, Any]] = []
    duplicates: list[dict[str, str]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    seen_source_ids: set[tuple[str, str]] = set()
    for case in cases:
        validate_case(case)
        source_key = (case["benchmark"], case["source_id"])
        if source_key in seen_source_ids:
            raise ValidationError(
                "同一基准内 source_id 必须唯一: "
                f"{case['benchmark']}/{case['source_id']}"
            )
        seen_source_ids.add(source_key)
        key = (case["benchmark"], case["content_hash"])
        if key in seen:
            first = seen[key]
            label_fields = (
                "task_family", "scenario_type", "threat_type",
                "expected_security_outcome",
            )
            conflicts = [name for name in label_fields if first[name] != case[name]]
            if conflicts:
                raise ValidationError(
                    f"相同语义输入存在冲突标签: {conflicts}; "
                    f"{first['source_id']} vs {case['source_id']}"
                )
            duplicates.append({
                "benchmark": case["benchmark"],
                "source_id": case["source_id"],
                "duplicate_of": first["source_id"],
                "content_hash": case["content_hash"],
            })
            continue
        seen[key] = case
        kept.append(case)
    return kept, duplicates


def deterministic_split(content_hash: str, *, train: int = 80, validation: int = 10) -> str:
    if train < 0 or validation < 0 or train + validation > 100:
        raise ValueError("拆分比例无效")
    bucket = int(content_hash[:8], 16) % 100
    if bucket < train:
        return "train"
    if bucket < train + validation:
        return "validation"
    return "test"


def dataset_statistics(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(cases)
    return {
        "case_count": len(rows),
        "split_counts": dict(sorted(Counter(row["split"] for row in rows).items())),
        "scenario_counts": dict(sorted(Counter(row["scenario_type"] for row in rows).items())),
        "outcome_counts": dict(sorted(Counter(row["expected_security_outcome"] for row in rows).items())),
    }

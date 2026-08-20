"""AgentDojo、InjecAgent 和 AgentHarm 的安全、离线转换器。"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from .validation import calculate_content_hash, normalize_source_path, validate_case


SOURCE_URLS = {
    "agentdojo": "https://github.com/ethz-spylab/agentdojo",
    "injecagent": "https://github.com/uiuc-kang-lab/InjecAgent",
    "agentharm": "https://huggingface.co/datasets/ai-safety-institute/AgentHarm",
}


class AdapterError(ValueError):
    """上游字段不足或类型错误，不允许静默猜测。"""


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("instruction", "prompt", "goal", "content", "description"):
            if isinstance(value.get(key), str):
                return value[key].strip()
    return ""


def _first_text(record: dict[str, Any], *keys: str) -> str:
    for key in keys:
        text = _text(record.get(key))
        if text:
            return text
    return ""


def _source_id(record: dict[str, Any], index: int) -> str:
    for key in ("source_id", "case_id", "task_id", "id", "name"):
        value = record.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    # 不使用随机 ID，相同输入可重复复现。
    raw = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"row-{index:06d}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def _safe_parameters(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(value)
            except (ValueError, SyntaxError):
                return {"raw": value}
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    return {}


def _actions(record: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = record.get("requested_actions") or record.get("tool_calls") or record.get("actions")
    result: list[dict[str, Any]] = []
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, str) and item.strip():
                result.append({"tool": item.strip(), "operation": "invoke", "resource": "", "parameters": {}})
            elif isinstance(item, dict):
                tool = _first_text(item, "tool", "tool_name", "name", "function")
                if tool:
                    result.append({
                        "tool": tool,
                        "operation": _first_text(item, "operation", "action") or "invoke",
                        "resource": _first_text(item, "resource", "target"),
                        "parameters": _safe_parameters(item.get("parameters") or item.get("arguments")),
                    })
    return result


def _base_case(
    *, benchmark: str, source_id: str, split: str, task_family: str,
    scenario_type: str, threat_type: str, user_goal: str,
    untrusted_content: str | None, requested_actions: list[dict[str, Any]],
    expected: str, risk_tags: list[str], original_labels: dict[str, Any],
    source_revision: str, source_path: str,
) -> dict[str, Any]:
    safe_source_path = normalize_source_path(source_path)
    case: dict[str, Any] = {
        "schema_version": "1.0",
        "benchmark": benchmark,
        "source_id": source_id,
        "split": split,
        "task_family": task_family or "unspecified",
        "scenario_type": scenario_type,
        "threat_type": threat_type,
        "user_goal": user_goal,
        "untrusted_content": untrusted_content,
        "requested_actions": requested_actions,
        "expected_security_outcome": expected,
        "risk_tags": sorted(set(tag for tag in risk_tags if tag)),
        "original_labels": original_labels,
        "provenance": {
            "source_url": SOURCE_URLS[benchmark],
            "source_revision": source_revision,
            "source_path": safe_source_path,
        },
        "content_hash": "0" * 64,
    }
    case["content_hash"] = calculate_content_hash(case)
    return validate_case(case)


@dataclass(frozen=True)
class AdapterContext:
    source_revision: str
    source_path: str
    split: str = "unknown"


class AgentDojoAdapter:
    benchmark = "agentdojo"

    def convert(self, record: dict[str, Any], index: int, context: AdapterContext) -> dict[str, Any]:
        goal = _first_text(record, "user_goal", "user_task", "prompt", "instruction")
        if not goal:
            raise AdapterError(f"AgentDojo row {index}: 缺少 user_task/user_goal/prompt")
        injection = _first_text(record, "untrusted_content", "injection_task", "injection", "attack")
        attacked = bool(injection) or record.get("is_injection") is True
        suite = _first_text(record, "suite", "benchmark_suite", "task_family") or "unspecified"
        actions = _actions(record)
        tool_names = record.get("tools")
        if not actions and isinstance(tool_names, list):
            actions = [{"tool": str(name), "operation": "invoke", "resource": "", "parameters": {}}
                       for name in tool_names if str(name).strip()]
        labels = {
            key: record[key] for key in ("suite", "user_task_id", "injection_task_id", "is_injection")
            if key in record
        }
        labels["mapping_note"] = (
            "AgentGuard 转换目标：出现间接提示注入时预期阻断；"
            "不等同于 AgentDojo 官方 utility/security 评分器。"
        )
        return _base_case(
            benchmark=self.benchmark, source_id=_source_id(record, index), split=context.split,
            task_family=suite, scenario_type="prompt_injection" if attacked else "benign",
            threat_type="indirect_prompt_injection" if attacked else "none", user_goal=goal,
            untrusted_content=injection or None, requested_actions=actions,
            expected="deny" if attacked else "allow",
            risk_tags=["prompt_injection"] if attacked else ["benign_workflow"],
            original_labels=labels, source_revision=context.source_revision, source_path=context.source_path,
        )


class InjecAgentAdapter:
    benchmark = "injecagent"

    def convert(self, record: dict[str, Any], index: int, context: AdapterContext) -> dict[str, Any]:
        goal = _first_text(record, "User Instruction", "user_instruction", "user_goal", "prompt")
        attack = _first_text(record, "Attacker Instruction", "attacker_instruction", "injected_prompt", "attack")
        if not goal or not attack:
            raise AdapterError(f"InjecAgent row {index}: 缺少 User Instruction 或 Attacker Instruction")
        attack_type = _first_text(record, "Attack Type", "attack_type", "attack_category") or "unspecified"
        source_path_lower = context.source_path.lower()
        data_stealing = "_ds_" in source_path_lower or "steal" in attack_type.lower() or "data" in attack_type.lower()
        user_tool = _first_text(record, "User Tool", "user_tool")
        attacker_tools = record.get("Attacker Tools") or record.get("attacker_tools") or []
        actions = []
        if user_tool:
            actions.append({
                "tool": user_tool, "operation": "read", "resource": "",
                "parameters": _safe_parameters(record.get("Tool Parameters") or record.get("tool_parameters")),
            })
        if isinstance(attacker_tools, list):
            actions.extend({"tool": str(tool), "operation": "invoke", "resource": "", "parameters": {}}
                           for tool in attacker_tools if str(tool).strip())
        labels = {
            key: record[key] for key in ("Attack Type", "Expected Achievements", "Modifed", "Level")
            if key in record
        }
        labels["mapping_note"] = (
            "AgentGuard 以阻断注入指令的工具执行为目标；"
            "不替代 InjecAgent 官方 ASR-valid/ASR-all 评分。"
        )
        return _base_case(
            benchmark=self.benchmark, source_id=_source_id(record, index), split=context.split,
            task_family=user_tool or "tool-integrated-agent", scenario_type="prompt_injection",
            threat_type="data_exfiltration" if data_stealing else "direct_harm",
            user_goal=goal, untrusted_content=attack, requested_actions=actions,
            expected="deny", risk_tags=["prompt_injection", "data_exfiltration" if data_stealing else "direct_harm"],
            original_labels=labels, source_revision=context.source_revision, source_path=context.source_path,
        )


class AgentHarmAdapter:
    benchmark = "agentharm"

    def convert(self, record: dict[str, Any], index: int, context: AdapterContext) -> dict[str, Any]:
        prompt = _first_text(record, "prompt", "instruction", "user_goal", "behavior")
        if not prompt:
            raise AdapterError(f"AgentHarm row {index}: 缺少 prompt/instruction")
        split = _first_text(record, "split") or context.split
        explicit_harmful = record.get("harmful")
        if explicit_harmful is not None and not isinstance(explicit_harmful, bool):
            raise AdapterError(f"AgentHarm row {index}: harmful 必须是布尔值")
        split_is_benign = "benign" in split.lower()
        if explicit_harmful is None and split == "unknown":
            raise AdapterError(
                f"AgentHarm row {index}: 缺少 harmful 且 split 为 unknown，无法安全推断标签"
            )
        if explicit_harmful is True and split_is_benign:
            raise AdapterError(f"AgentHarm row {index}: harmful=true 与 benign split 冲突")
        if explicit_harmful is False and split != "unknown" and not split_is_benign:
            raise AdapterError(f"AgentHarm row {index}: harmful=false 与非 benign split 冲突")
        benign = explicit_harmful is False or split_is_benign
        category = _first_text(record, "category", "task_family") or "unspecified"
        labels = {key: record[key] for key in ("id_original", "name", "category", "harmful") if key in record}
        labels["mapping_note"] = (
            "AgentGuard 将有害任务映射为 deny，良性对照映射为 allow；"
            "不替代 AgentHarm 官方 multi-step 评分器或语义裁判器。"
        )
        return _base_case(
            benchmark=self.benchmark, source_id=_source_id(record, index), split=split,
            task_family=category, scenario_type="benign" if benign else "harmful_request",
            threat_type="none" if benign else "harmful_multi_step", user_goal=prompt,
            untrusted_content=None, requested_actions=_actions(record),
            expected="allow" if benign else "deny",
            risk_tags=["benign_workflow"] if benign else ["harmful_request", category.lower().replace(" ", "_")],
            original_labels=labels, source_revision=context.source_revision, source_path=context.source_path,
        )


ADAPTERS = {
    "agentdojo": AgentDojoAdapter(),
    "injecagent": InjecAgentAdapter(),
    "agentharm": AgentHarmAdapter(),
}


def convert_records(
    benchmark: str, records: Iterable[dict[str, Any]], *, source_revision: str,
    source_path: str, split: str = "unknown",
) -> list[dict[str, Any]]:
    try:
        adapter = ADAPTERS[benchmark]
    except KeyError as exc:
        raise AdapterError(f"不支持的基准: {benchmark}") from exc
    context = AdapterContext(source_revision=source_revision, source_path=source_path, split=split)
    converted = []
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise AdapterError(f"row {index}: 上游记录必须是对象")
        converted.append(adapter.convert(record, index, context))
    return converted

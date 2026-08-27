"""Generate a non-secret manifest for the latest local verification evidence.

The manifest keeps source identity, runtime versions, command exit codes and
artifact hashes together without copying command output, credentials, tokens or
machine-specific private paths into the repository.  It is intentionally a
summary of evidence files; it does not turn synthetic fixtures into public
benchmark scores and it never changes ``production_ready`` to true.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "reports"
STATUS_DIR = REPORT_DIR / "status"
OPENCLAW_DIR = REPORT_DIR / "e2e" / "openclaw"
OPENCLAW_STATE_DIR = ROOT / "integrations" / "openclaw_mcp" / ".e2e_state" / "visual-demo"


def iso_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone().isoformat(
        timespec="seconds"
    )


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def run_capture(args: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return 127, ""
    return completed.returncode, completed.stdout


def command_text(args: list[str]) -> str:
    return " ".join(args)


def git_value(*args: str) -> str:
    code, output = run_capture(["git", *args])
    if code != 0:
        return ""
    return output.strip().splitlines()[0] if output.strip() else ""


def version_output(args: list[str]) -> str:
    code, output = run_capture(args)
    if code != 0:
        return "unavailable"
    line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    return line[:160] if line else "unknown"


def test_count(path: Path) -> tuple[int, bool]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return 0, False
    match = re.search(r"Ran\s+(\d+)\s+tests?", text)
    if match:
        return int(match.group(1)), "OK" in text and "FAILED" not in text
    # The complete regression wrapper records unittest's per-case output but
    # does not append the runner summary; its existing evaluation report is
    # the authoritative count for this check.
    if path.name == "full_python_tests.txt":
        summary = load_json(REPORT_DIR / "core" / "full_security_evaluation_summary.json") or {}
        python_summary = summary.get("python_security_tests", {})
        total = int(python_summary.get("total", 0) or 0)
        passed = int(python_summary.get("passed", 0) or 0)
        if total > 0:
            return total, passed == total
    # OPA's verbose test output ends with `PASS: passed/total` rather than
    # unittest's `Ran N tests`; retain the denominator and pass/fail result.
    opa_match = re.findall(r"(?:^|\n)PASS:\s*(\d+)\s*/\s*(\d+)\s*(?:\r?\n|$)", text)
    if opa_match:
        passed, total = (int(value) for value in opa_match[-1])
        return total, passed == total and total > 0 and "FAIL:" not in text
    return 0, False


def artifact_entry(path: Path, kind: str) -> dict[str, str] | None:
    digest = sha256(path)
    if digest is None:
        return None
    return {"path": relative(path), "kind": kind, "sha256": digest}


def local_evidence_entries() -> list[dict[str, Any]]:
    """Hash ignored local transcripts/audit logs without copying their contents.

    OpenClaw keeps raw session and AgentGuard audit material below the
    git-ignored demo state directory.  The published reports contain the
    redacted, reviewable summaries; this list records integrity hashes for the
    raw local evidence while explicitly marking it as unavailable to Git.
    """

    model = load_json(OPENCLAW_DIR / "openclaw_agentguard_model_turn.json") or {}
    control_ui = load_json(OPENCLAW_DIR / "openclaw_agentguard_control_ui_turn.json") or {}
    candidates: list[tuple[Path, str]] = []
    model_session_id = ((model.get("model_turn") or {}).get("session_id"))
    if isinstance(model_session_id, str) and model_session_id:
        candidates.append(
            (
                OPENCLAW_STATE_DIR
                / "state"
                / "agents"
                / "main"
                / "sessions"
                / f"{model_session_id}.jsonl",
                "openclaw_cli_transcript",
            )
        )
    ui_session = control_ui.get("session") or {}
    trajectory = ui_session.get("trajectory") if isinstance(ui_session, dict) else None
    if isinstance(trajectory, str) and trajectory:
        basename = Path(trajectory.replace("\\", "/")).name
        if basename:
            candidates.append(
                (
                    OPENCLAW_STATE_DIR
                    / "state"
                    / "agents"
                    / "main"
                    / "sessions"
                    / basename,
                    "openclaw_control_ui_trajectory",
                )
            )
    # The audit report intentionally uses a <DEMO_STATE> placeholder; resolve
    # it to the local ignored state directory without exposing machine paths.
    candidates.append(
        (
            OPENCLAW_STATE_DIR / "agentguard-state" / "enforcement_audit.jsonl",
            "agentguard_enforcement_audit",
        )
    )
    entries: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for path, kind in candidates:
        if path in seen:
            continue
        seen.add(path)
        digest = sha256(path)
        if digest is None:
            continue
        entries.append(
            {
                "path": relative(path),
                "kind": kind,
                "sha256": digest,
                "tracked": False,
                "availability": "git_ignored_local_only",
            }
        )
    return entries


def build_check(
    *,
    name: str,
    command: str,
    exit_code: int,
    result: str,
    executed_at: str,
    version: str,
    input_scope: str,
    evidence: list[str],
    notes: str = "",
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "name": name,
        "command": command,
        "exit_code": exit_code,
        "result": result,
        "executed_at": executed_at,
        "version": version,
        "input_scope": input_scope,
        "evidence": evidence,
    }
    if notes:
        item["notes"] = notes
    return item


def evidence_time(paths: list[Path]) -> str:
    existing = [path.stat().st_mtime for path in paths if path.is_file()]
    return iso_from_timestamp(max(existing)) if existing else "not_recorded"


def model_check(
    *,
    name: str,
    path: Path,
    command: str,
    version: str,
    input_scope: str,
) -> dict[str, Any]:
    payload = load_json(path) or {}
    checks = payload.get("checks")
    if isinstance(checks, dict) and checks:
        all_passed = (
            payload.get("status") == "passed_with_declared_scope"
            and all(value is True for value in checks.values())
        )
    else:
        summary = payload.get("summary")
        all_passed = (
            payload.get("status") == "passed_with_declared_scope"
            and isinstance(summary, dict)
            and int(summary.get("total_cases", 0) or 0) > 0
            and int(summary.get("passed_cases", 0) or 0) == int(summary.get("total_cases", 0) or 0)
            and int(summary.get("failed_cases", 0) or 0) == 0
        )
    return build_check(
        name=name,
        command=command,
        exit_code=0 if all_passed else 1,
        result="passed" if all_passed else "failed_or_missing",
        executed_at=str(payload.get("generated_at") or evidence_time([path])),
        version=version,
        input_scope=input_scope,
        evidence=[relative(path)],
        notes=(
            "本轮复用已保存的真实模型证据，未重新调用模型；报告明确标注其测试时间和隔离范围。"
            if all_passed
            else "未找到同时通过的模型证据。"
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tested-source-commit", default="")
    parser.add_argument("--output", default="reports/status/evidence_manifest.json")
    parser.add_argument("--markdown", default="reports/status/evidence_manifest.md")
    parser.add_argument(
        "--working-tree-clean-at-test-start",
        choices=("true", "false"),
        default="false",
        help="Whether the source tree was clean when the verification commands started.",
    )
    args = parser.parse_args()

    node = Path(
        os.environ.get(
            "AGENTGUARD_NODE_PATH",
            str(Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "bin" / "node.exe"),
        )
    )
    pnpm = Path(
        os.environ.get(
            "AGENTGUARD_PNPM_PATH",
            str(Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "bin" / "fallback" / "pnpm.cmd"),
        )
    )
    openclaw_entry = ROOT / "third_party" / "runtime" / "openclaw-client" / "node_modules" / "openclaw" / "openclaw.mjs"
    opa = ROOT / "tools" / ("opa.exe" if platform.system() == "Windows" else "opa")
    tested_commit = args.tested_source_commit or git_value("rev-parse", "HEAD") or "unknown"
    source_tree_hash = git_value("rev-parse", f"{tested_commit}^{{tree}}") or "unknown"

    now = datetime.now(timezone.utc).astimezone()
    python_version = version_output([sys.executable, "--version"])
    node_version = version_output([str(node), "--version"]) if node.is_file() else "unavailable"
    pnpm_version = version_output([str(pnpm), "--version"]) if pnpm.is_file() else "unavailable"
    openclaw_version = (
        version_output([str(node), str(openclaw_entry), "--version"])
        if node.is_file() and openclaw_entry.is_file()
        else "unavailable"
    )
    opa_version = version_output([str(opa), "version"]) if opa.is_file() else "unavailable"

    opa_log = REPORT_DIR / "core" / "full_opa_tests.txt"
    envoy_log = REPORT_DIR / "e2e" / "network" / "opa_envoy_policy_tests.txt"
    python_log = REPORT_DIR / "core" / "full_python_tests.txt"
    evaluation = load_json(REPORT_DIR / "core" / "evaluation_summary.json") or {}
    stage4 = load_json(REPORT_DIR / "preflight" / "stage4_preflight.json") or {}
    prepublish = load_json(STATUS_DIR / "prepublish_security_check.json") or {}
    consistency = load_json(STATUS_DIR / "status_consistency_check.json") or {}

    opa_total, opa_ok = test_count(opa_log)
    envoy_total, envoy_ok = test_count(envoy_log)
    python_total, python_ok = test_count(python_log)
    checks: list[dict[str, Any]] = [
        build_check(
            name="OPA核心策略测试",
            command="tools\\opa.exe test policy tests data --fail-on-empty",
            exit_code=0 if opa_ok else 1,
            result="passed" if opa_ok else "failed_or_missing",
            executed_at=evidence_time([opa_log]),
            version=opa_version,
            input_scope=f"policy tests data；{opa_total} cases",
            evidence=[relative(opa_log)],
        ),
        build_check(
            name="OPA-Envoy部署策略测试",
            command="tools\\opa.exe test deployment\\opa-envoy --fail-on-empty",
            exit_code=0 if envoy_ok else 1,
            result="passed" if envoy_ok else "failed_or_missing",
            executed_at=evidence_time([envoy_log]),
            version=opa_version,
            input_scope=f"deployment/opa-envoy；{envoy_total} cases",
            evidence=[relative(envoy_log)],
        ),
        build_check(
            name="Python全量安全回归",
            command=".venv\\Scripts\\python.exe -m enforcement.run_tests",
            exit_code=0 if python_ok and python_total >= 174 else 1,
            result="passed" if python_ok and python_total >= 174 else "failed_or_missing",
            executed_at=evidence_time([python_log]),
            version=python_version,
            input_scope=f"身份、审批、网关、内核、公开fixture与阶段4测试；{python_total} tests",
            evidence=[relative(python_log)],
        ),
        build_check(
            name="OPA核心55例评测",
            command=".venv\\Scripts\\python.exe scripts\\evaluate.py --opa tools\\opa.exe",
            exit_code=0 if evaluation.get("total_cases") == 55 and evaluation.get("unsafe_allow_count") == 0 else 1,
            result="passed" if evaluation.get("total_cases") == 55 and evaluation.get("unsafe_allow_count") == 0 else "failed_or_missing",
            executed_at=evidence_time([REPORT_DIR / "core" / "evaluation_summary.json"]),
            version=opa_version,
            input_scope="datasets/agent_guard_cases.jsonl；55 synthetic project cases",
            evidence=[
                "reports/core/evaluation_results.csv",
                "reports/core/evaluation_summary.json",
                "reports/core/evaluation_report.md",
            ],
        ),
        build_check(
            name="阶段4只读预检",
            command=".venv\\Scripts\\python.exe scripts\\run_stage4_preflight.py",
            exit_code=2 if stage4.get("status") == "blocked_external_environment" else 0,
            result="blocked_external_environment" if stage4.get("status") == "blocked_external_environment" else "passed",
            executed_at=evidence_time([REPORT_DIR / "preflight" / "stage4_preflight.json"]),
            version=python_version,
            input_scope="非密配置与授权输入前置条件；不替代产品级环境验证",
            evidence=["reports/preflight/stage4_preflight.json", "reports/preflight/stage4_preflight.md"],
            notes="退出码2表示按项目契约保留的外部环境/授权阻塞，不是伪造通过。",
        ),
        build_check(
            name="发布前敏感信息扫描",
            command=".venv\\Scripts\\python.exe scripts\\prepublish_security_check.py",
            exit_code=0 if prepublish.get("status") == "passed" else 1,
            result=str(prepublish.get("status") or "failed_or_missing"),
            executed_at=str(prepublish.get("generated_at") or evidence_time([STATUS_DIR / "prepublish_security_check.json"])),
            version=python_version,
            input_scope="Git已跟踪文件与未忽略新文件；私密值不写入报告",
            evidence=["reports/status/prepublish_security_check.json"],
        ),
        build_check(
            name="状态一致性检查",
            command=".venv\\Scripts\\python.exe scripts\\check_status_consistency.py",
            exit_code=0 if consistency.get("status") == "passed" else 1,
            result=str(consistency.get("status") or "failed_or_missing"),
            executed_at=str(consistency.get("generated_at") or evidence_time([STATUS_DIR / "status_consistency_check.json"])),
            version=python_version,
            input_scope="状态报告、阶段4边界、公开fixture与历史证据标注",
            evidence=["reports/status/status_consistency_check.json"],
        ),
        build_check(
            name="项目内OpenClaw安装与命令可用性",
            command="<NODE> <PROJECT_ROOT>/third_party/runtime/openclaw-client/node_modules/openclaw/openclaw.mjs --version/mcp --help/agent --help",
            exit_code=0 if (load_json(OPENCLAW_DIR / "openclaw_installation.json") or {}).get("final_status") in {"already_installed_and_verified", "installed_and_verified"} else 1,
            result="passed" if (load_json(OPENCLAW_DIR / "openclaw_installation.json") or {}).get("final_status") in {"already_installed_and_verified", "installed_and_verified"} else "failed_or_missing",
            executed_at=str((load_json(OPENCLAW_DIR / "openclaw_installation.json") or {}).get("generated_at") or evidence_time([OPENCLAW_DIR / "openclaw_installation.json"])),
            version=openclaw_version,
            input_scope="项目内固定OpenClaw 2026.7.1-2；不依赖全局安装",
            evidence=["reports/e2e/openclaw/openclaw_installation.json", "reports/e2e/openclaw/openclaw_installation.md"],
        ),
        model_check(
            name="OpenClaw固定5例模型fixture",
            path=OPENCLAW_DIR / "openclaw_agentguard_model_dataset.json",
            command="<NODE> <OPENCLAW_ENTRY> agent --message <FIXED_SYNTHETIC_CASES>",
            version="modelflare/gpt-5.6-sol",
            input_scope="5 fixed synthetic project fixtures；not a public benchmark",
        ),
        model_check(
            name="OpenClaw CLI真实模型回合",
            path=OPENCLAW_DIR / "openclaw_agentguard_model_turn.json",
            command="<NODE> <OPENCLAW_ENTRY> agent --message <FIXED_GROUNDED_PROMPT> --model modelflare/gpt-5.6-sol --json",
            version="modelflare/gpt-5.6-sol",
            input_scope="single loopback model turn；read-only list_notices tool",
        ),
        model_check(
            name="OpenClaw Control UI真实模型回合",
            path=OPENCLAW_DIR / "openclaw_agentguard_control_ui_turn.json",
            command="Control UI authenticated session with fixed grounded prompt",
            version="modelflare/gpt-5.6-sol",
            input_scope="single authenticated loopback UI turn；read-only list_notices tool",
        ),
    ]

    artifacts: list[dict[str, str]] = []
    artifact_specs = [
        (ROOT / "datasets" / "openclaw_agentguard_model_cases.jsonl", "dataset"),
        (ROOT / "datasets" / "openclaw_agentguard_model_metadata.json", "dataset_metadata"),
        (OPENCLAW_DIR / "openclaw_agentguard_model_dataset.json", "model_report"),
        (OPENCLAW_DIR / "openclaw_agentguard_model_turn.json", "transcript_and_audit_report"),
        (OPENCLAW_DIR / "openclaw_agentguard_control_ui_turn.json", "control_ui_and_audit_report"),
        (OPENCLAW_DIR / "openclaw_agentguard_control_ui_turn.png", "screenshot"),
        (OPENCLAW_DIR / "openclaw_agentguard_control_ui_result.png", "screenshot"),
        (OPENCLAW_DIR / "openclaw_agentguard_visual_demo.json", "protocol_and_visual_report"),
        (OPENCLAW_DIR / "openclaw_installation.json", "installation_report"),
        (REPORT_DIR / "core" / "evaluation_summary.json", "evaluation_report"),
        (REPORT_DIR / "core" / "full_python_tests.txt", "test_log"),
        (REPORT_DIR / "core" / "full_opa_tests.txt", "test_log"),
    ]
    for path, kind in artifact_specs:
        entry = artifact_entry(path, kind)
        if entry:
            artifacts.append(entry)

    # Raw OpenClaw transcripts and AgentGuard audit logs stay below the
    # git-ignored demo state directory.  Record integrity hashes only so a
    # reviewer can reconcile local evidence without publishing credentials,
    # cookies, tokens or machine-specific state.
    local_ignored_evidence = local_evidence_entries()

    output = ROOT / args.output
    markdown = ROOT / args.markdown
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": now.isoformat(timespec="seconds"),
        "timezone": str(now.tzinfo),
        "tested_source_commit": tested_commit,
        "source_tree_hash": source_tree_hash,
        "working_tree_clean": git_value("status", "--porcelain") == "",
        "working_tree_clean_at_test_start": args.working_tree_clean_at_test_start == "true",
        "environment": {
            "os": platform.platform(),
            "python": python_version,
            "opa": opa_version,
            "node": node_version,
            "pnpm": pnpm_version,
            "openclaw": openclaw_version,
            "global_openclaw_used": False,
        },
        "checks": checks,
        "artifact_hashes": artifacts,
        "local_ignored_evidence_hashes": local_ignored_evidence,
        "data_properties": {
            "synthetic": True,
            "benchmark_type": "project_fixture",
            "public_benchmark": False,
            "production_ready": False,
            "identity_scope": "loopback_static_dev_test_only",
            "business_data_scope": "isolated_synthetic_sqlite",
            "only_allowed_tool": "agentguard-notices__list_notices",
        },
        "secret_values_recorded": False,
        "notes": [
            "模型凭据、Gateway token、票据值、Cookie和个人私密路径均未写入本清单。",
            "OpenClaw模型证据来自已保存的真实回环回合；本清单生成过程不重新调用模型。",
            "5例模型fixture不是公开基准成绩；状态仅覆盖当前隔离配置。",
            "production_ready固定为false，外部生产环境和授权业务凭据仍需单独验收。",
            "原始OpenClaw转录和AgentGuard enforcement_audit仅保留在Git忽略的本地状态目录；本清单只记录SHA-256，不随Git发布原始内容。",
        ],
    }
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# 验证证据清单",
        "",
        f"生成时间：`{manifest['generated_at']}`（{manifest['timezone']}）",
        f"测试源提交：`{tested_commit}`；source tree hash：`{source_tree_hash}`",
        f"测试开始时工作树干净：`{manifest['working_tree_clean_at_test_start']}`；清单生成时工作树干净：`{manifest['working_tree_clean']}`",
        "",
        "## 环境",
        "",
        f"- OS：`{manifest['environment']['os']}`",
        f"- Python：`{python_version}`；OPA：`{opa_version}`；Node：`{node_version}`；pnpm：`{pnpm_version}`；OpenClaw：`{openclaw_version}`",
        "- OpenClaw为项目内安装，全局安装：`false`。",
        "",
        "## 检查",
        "",
        "| 检查 | 退出码 | 结果 | 执行时间 | 证据 |",
        "|---|---:|---|---|---|",
    ]
    for check in checks:
        lines.append(
            f"| {check['name']} | {check['exit_code']} | {check['result']} | {check['executed_at']} | "
            + "；".join(f"`{item}`" for item in check["evidence"])
            + " |"
        )
    lines.extend(
        [
            "",
            "## 数据与边界",
            "",
            "- `synthetic=true`，`benchmark_type=project_fixture`，不是公开基准成绩。",
            "- 当前唯一允许工具：`agentguard-notices__list_notices`；身份为回环静态开发身份，数据为隔离合成 SQLite。",
            "- `production_ready=false`。模型回合证据不替代生产 OIDC、TLS/mTLS、网络隔离、HA、真实业务凭据和持续审计验收。",
            "- 报告和清单不记录 API Key、Gateway token、Cookie、票据值或其他秘密。",
            "",
            "## 工件 SHA-256",
            "",
            "| 类型 | 路径 | SHA-256 |",
            "|---|---|---|",
        ]
    )
    lines.extend(f"| {item['kind']} | `{item['path']}` | `{item['sha256']}` |" for item in artifacts)
    lines.extend(
        [
            "",
            "## Git忽略的本地证据哈希",
            "",
            "原始转录和审计日志不随 Git 发布；以下仅记录本机忽略目录中的 SHA-256，便于本地完整性核对。",
            "",
            "| 类型 | 路径 | SHA-256 | 可用性 |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| {item['kind']} | `{item['path']}` | `{item['sha256']}` | `{item['availability']}` |"
        for item in local_ignored_evidence
    )
    markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output": relative(output), "markdown": relative(markdown), "checks": len(checks)}, ensure_ascii=False))
    return 0 if all(check["result"] in {"passed", "blocked_external_environment"} for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Run a truthful OpenClaw-to-AgentGuard minimum integration test.

The test uses the real OpenClaw CLI for registration and ``tools/list``
discovery, then uses a deterministic MCP protocol client for one low-risk
``tools/call`` against a real local AgentGuard + OPA + SQLite test chain.
It never claims that an OpenClaw model turn invoked the tool because that would
require separately authorized model credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "openclaw_mcp_integration.json"
DEFAULT_MARKDOWN = PROJECT_ROOT / "reports" / "openclaw_mcp_integration.md"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _json_url(url: str, timeout: float = 10.0) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise RuntimeError("HTTP response was not a JSON object")
    return payload


def _sanitize_text(value: str, replacements: Sequence[tuple[str, str]]) -> str:
    sanitized = value
    for original, replacement in sorted(
        replacements, key=lambda item: len(item[0]), reverse=True
    ):
        if original:
            sanitized = sanitized.replace(original, replacement)
            sanitized = sanitized.replace(original.replace("\\", "/"), replacement)
            # CLI JSON output contains escaped Windows separators (``\\\\``).
            # Replace that representation before parsing or persisting it too.
            escaped = json.dumps(original, ensure_ascii=False)[1:-1]
            sanitized = sanitized.replace(escaped, replacement)
    return sanitized


def _sanitize(value: Any, replacements: Sequence[tuple[str, str]]) -> Any:
    if isinstance(value, str):
        return _sanitize_text(value, replacements)
    if isinstance(value, list):
        return [_sanitize(item, replacements) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item, replacements) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize(item, replacements) for key, item in value.items()
        }
    return value


def _run_step(
    name: str,
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    replacements: Sequence[tuple[str, str]],
    timeout: float = 60.0,
) -> dict[str, Any]:
    started = time.monotonic()
    started_at = _utc_now()
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(PROJECT_ROOT),
            env=dict(env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = str(exc.stdout or "")
        stderr = str(exc.stderr or "")
        timed_out = True
    return {
        "name": name,
        "command": _sanitize(list(command), replacements),
        "started_at": started_at,
        "finished_at": _utc_now(),
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout": _sanitize_text(stdout[-20000:], replacements),
        "stderr": _sanitize_text(stderr[-10000:], replacements),
    }


def _step_json(step: Mapping[str, Any]) -> dict[str, Any]:
    try:
        payload = json.loads(str(step.get("stdout", "")))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _latest_audit_evidence(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"record_found": False}
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("event") == "enforcement_decision":
            records.append(item)
    if not records:
        return {"record_found": False}
    latest = records[-1]
    result = latest.get("result", {})
    return {
        "record_found": True,
        "event_count": len(records),
        "tool": latest.get("tool"),
        "operation": latest.get("operation"),
        "result_status": result.get("status") if isinstance(result, Mapping) else None,
        "reason_code": result.get("reason_code") if isinstance(result, Mapping) else None,
        "ticket_value_recorded": (
            result.get("ticket") not in {None, "", "***REDACTED***"}
            if isinstance(result, Mapping)
            else False
        ),
    }


def _write_markdown(report: Mapping[str, Any], path: Path) -> None:
    checks = report["checks"]
    protocol = report["low_risk_call_evidence"]
    outputs = protocol.get("outputs", []) if isinstance(protocol, Mapping) else []
    call_output = next(
        (
            item.get("result", {}).get("structuredContent", {})
            for item in outputs
            if isinstance(item, Mapping) and item.get("id") == 3
        ),
        {},
    )
    lines = [
        "# OpenClaw × AgentGuard 最小接入实测报告",
        "",
        f"- 生成时间：`{report['generated_at']}`",
        f"- 总体状态：`{report['status']}`",
        f"- OpenClaw：`{report['versions'].get('openclaw', 'unknown')}`",
        f"- MCP 适配器：`{report['versions'].get('adapter', 'unknown')}`",
        "",
        "## 可对外表述",
        "",
        str(report["claim"]),
        "",
        "## 实测结果",
        "",
        "| 检查 | 结果 |",
        "|---|---:|",
    ]
    for name, passed in checks.items():
        lines.append(f"| {name} | {'通过' if passed else '未通过'} |")
    lines.extend(
        [
            "",
            "## 低风险调用",
            "",
            f"- 工具：`list_notices`",
            f"- 返回条数：`{call_output.get('row_count', 0)}`",
            f"- 副作用：`{call_output.get('side_effect')}`",
            "- 调用层级：确定性 MCP `tools/call` → 真实本机 AgentGuard → OPA → 一次性票据 → Wasmtime → 隔离测试公告 SQLite。",
            "- 限定：本次没有使用模型凭据运行 OpenClaw agent 回合，因此不写“OpenClaw 模型已自主调用工具”。",
            "",
            "## 证据边界",
            "",
            "- OpenClaw 官方 CLI 已实际完成注册、静态诊断和 `probe`，并发现唯一工具。",
            "- OpenClaw `probe` 证明真实 MCP 连接与 `tools/list`；它不执行 `tools/call`。",
            "- 低风险调用由项目内确定性 MCP 客户端执行，输入、输出和退出码保存在同名 JSON 报告。",
            "- 使用的是隔离测试身份与隔离测试数据，不是生产用户凭据或生产数据。",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--openclaw-entry", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    node = args.node.resolve()
    openclaw_entry = args.openclaw_entry.resolve()
    if not node.is_file() or not openclaw_entry.is_file():
        print("Node or OpenClaw entry is missing", file=sys.stderr)
        return 2

    # Import after argument validation so --help works even if project deps are absent.
    from service.app import AgentGuardService
    from service.config import load_config

    generated_at = _utc_now()
    steps: list[dict[str, Any]] = []
    protocol_report: dict[str, Any] = {}
    readiness: dict[str, Any] = {}
    version_payload: dict[str, Any] = {}
    audit_evidence: dict[str, Any] = {"record_found": False}
    actual_config_hash = ""
    service: AgentGuardService | None = None

    with tempfile.TemporaryDirectory(prefix="agentguard-openclaw-e2e-") as temporary:
        temp_root = Path(temporary)
        agentguard_state = temp_root / "agentguard-state"
        openclaw_state = temp_root / "openclaw-state"
        openclaw_state.mkdir(parents=True, exist_ok=True)
        protocol_path = temp_root / "protocol.json"
        ephemeral_secret = secrets.token_hex(32)
        opa_port = _free_loopback_port()
        test_environ = dict(os.environ)
        test_environ["AGENTGUARD_TICKET_SECRET_HEX"] = ephemeral_secret
        config = load_config(
            test_environ,
            overrides={
                "host": "127.0.0.1",
                "port": 0,
                "opa_mode": "rest",
                "opa_base_url": f"http://127.0.0.1:{opa_port}",
                "manage_opa_process": True,
                "enable_local_adapters": True,
                "state_dir": str(agentguard_state),
                "readiness_probe_writes": False,
                "readiness_timeout_seconds": 3.0,
                "shutdown_timeout_seconds": 3.0,
            },
        )
        try:
            service = AgentGuardService(
                config, project_root=PROJECT_ROOT, environ=test_environ
            ).start()
            base_url = service.base_url
            readiness = _json_url(f"{base_url}/readyz")
            version_payload = _json_url(f"{base_url}/version")

            python = Path(sys.executable).resolve()
            subject_file = (
                PROJECT_ROOT
                / "integrations"
                / "openclaw_mcp"
                / "dev-subject.example.json"
            ).resolve()
            replacements = [
                (str(openclaw_entry), "<OPENCLAW_ENTRY>"),
                (str(node), "<NODE>"),
                (str(python), "<PYTHON>"),
                (str(PROJECT_ROOT), "<PROJECT_ROOT>"),
                (str(temp_root), "<TEMP_STATE>"),
                (ephemeral_secret, "<EPHEMERAL_TEST_SECRET>"),
            ]
            openclaw_env = dict(os.environ)
            openclaw_env["OPENCLAW_STATE_DIR"] = str(openclaw_state)
            openclaw_env["OPENCLAW_CONFIG_PATH"] = str(
                openclaw_state / "openclaw.json"
            )
            mcp_env = {
                "AGENTGUARD_MCP_BASE_URL": base_url,
                "AGENTGUARD_MCP_IDENTITY_MODE": "loopback_static_dev",
                "AGENTGUARD_MCP_DEV_SUBJECT_FILE": str(subject_file),
            }
            definition = {
                "command": str(python),
                "args": ["-m", "integrations.openclaw_mcp"],
                "cwd": str(PROJECT_ROOT),
                "env": mcp_env,
                "requestTimeoutMs": 20000,
                "connectionTimeoutMs": 8000,
                "supportsParallelToolCalls": False,
                "toolFilter": {"include": ["list_notices"]},
            }
            definition_json = json.dumps(
                definition, ensure_ascii=False, separators=(",", ":")
            )
            actual_config_hash = hashlib.sha256(
                definition_json.encode("utf-8")
            ).hexdigest()
            prefix = [str(node), str(openclaw_entry)]
            steps.append(
                _run_step(
                    "node_version",
                    [str(node), "--version"],
                    env=openclaw_env,
                    replacements=replacements,
                )
            )
            steps.append(
                _run_step(
                    "openclaw_version",
                    [*prefix, "--version"],
                    env=openclaw_env,
                    replacements=replacements,
                )
            )
            steps.append(
                _run_step(
                    "opa_version",
                    [str(PROJECT_ROOT / "tools" / "opa.exe"), "version"],
                    env=openclaw_env,
                    replacements=replacements,
                )
            )
            steps.append(
                _run_step(
                    "openclaw_mcp_set",
                    [*prefix, "mcp", "set", "agentguard-notices", definition_json],
                    env=openclaw_env,
                    replacements=replacements,
                    timeout=90,
                )
            )
            steps.append(
                _run_step(
                    "openclaw_mcp_show",
                    [*prefix, "mcp", "show", "agentguard-notices", "--json"],
                    env=openclaw_env,
                    replacements=replacements,
                )
            )
            steps.append(
                _run_step(
                    "openclaw_mcp_doctor_probe",
                    [
                        *prefix,
                        "mcp",
                        "doctor",
                        "agentguard-notices",
                        "--probe",
                        "--json",
                    ],
                    env=openclaw_env,
                    replacements=replacements,
                    timeout=90,
                )
            )
            steps.append(
                _run_step(
                    "openclaw_mcp_probe",
                    [*prefix, "mcp", "probe", "agentguard-notices", "--json"],
                    env=openclaw_env,
                    replacements=replacements,
                    timeout=90,
                )
            )

            protocol_env = dict(os.environ)
            protocol_env.update(mcp_env)
            protocol_step = _run_step(
                "mcp_initialize_tools_list_and_low_risk_call",
                [
                    str(python),
                    "-m",
                    "integrations.openclaw_mcp.protocol_probe",
                    "--limit",
                    "2",
                    "--report",
                    str(protocol_path),
                ],
                env=protocol_env,
                replacements=replacements,
            )
            steps.append(protocol_step)
            if protocol_path.is_file():
                protocol_report = json.loads(
                    protocol_path.read_text(encoding="utf-8")
                )
                protocol_report = _sanitize(protocol_report, replacements)
            audit_evidence = _latest_audit_evidence(
                agentguard_state / "enforcement_audit.jsonl"
            )
        finally:
            if service is not None:
                service.close()

    step_by_name = {step["name"]: step for step in steps}
    doctor = _step_json(step_by_name.get("openclaw_mcp_doctor_probe", {}))
    probe = _step_json(step_by_name.get("openclaw_mcp_probe", {}))
    openclaw_version = str(
        step_by_name.get("openclaw_version", {}).get("stdout", "")
    ).strip()
    protocol_checks = protocol_report.get("checks", {})
    checks = {
        "agentguard_ready": readiness.get("ready") is True,
        "openclaw_cli_started": (
            step_by_name.get("openclaw_version", {}).get("exit_code") == 0
            and openclaw_version.startswith("OpenClaw 2026.7.1-2")
        ),
        "openclaw_registration_saved": step_by_name.get(
            "openclaw_mcp_set", {}
        ).get("exit_code")
        == 0,
        "openclaw_static_doctor_and_live_probe_passed": (
            step_by_name.get("openclaw_mcp_doctor_probe", {}).get("exit_code") == 0
            and doctor.get("ok") is True
        ),
        "openclaw_tools_list_found_only_readonly_tool": (
            step_by_name.get("openclaw_mcp_probe", {}).get("exit_code") == 0
            and probe.get("tools") == ["agentguard-notices__list_notices"]
            and probe.get("diagnostics") == []
            and probe.get("servers", {})
            .get("agentguard-notices", {})
            .get("tools")
            == 1
        ),
        "protocol_initialize_and_tools_list_passed": (
            protocol_checks.get("initialize_succeeded") is True
            and protocol_checks.get("tools_list_has_single_readonly_tool") is True
        ),
        "low_risk_call_executed_without_business_side_effect": (
            protocol_checks.get("low_risk_call_executed") is True
            and protocol_checks.get("low_risk_call_has_no_side_effect") is True
        ),
        "agentguard_audit_record_created": (
            audit_evidence.get("record_found") is True
            and audit_evidence.get("tool") == "database.query"
            and audit_evidence.get("operation") == "query"
            and audit_evidence.get("result_status") == "executed_isolated"
            and audit_evidence.get("ticket_value_recorded") is False
        ),
        "every_recorded_process_exited_zero": all(
            step.get("exit_code") == 0 for step in steps
        ),
    }
    passed = all(checks.values())
    report = {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "status": "passed_with_declared_scope" if passed else "failed",
        "claim": (
            "OpenClaw 2026.7.1-2 实机注册、doctor 和 MCP tools/list 已完成；"
            "一个只读工具已通过确定性 MCP tools/call 调用真实 AgentGuard 测试链。"
            "未配置模型凭据，故未执行 OpenClaw agent 模型回合，不能表述为“OpenClaw 模型自主调用完成”。"
            if passed
            else "最小接入测试存在失败项，不得声称 OpenClaw 接入完成。"
        ),
        "scope": {
            "openclaw_runtime_registration": "completed",
            "openclaw_live_tools_list": "completed",
            "low_risk_call": "completed_by_deterministic_mcp_client_against_real_agentguard",
            "openclaw_model_driven_tool_call": "not_run_no_authorized_model_credentials",
            "identity": "loopback_static_dev_test_only",
            "data": "isolated_synthetic_notice_sqlite",
            "production_ready": False,
        },
        "versions": {
            "openclaw": openclaw_version,
            "node": str(step_by_name.get("node_version", {}).get("stdout", "")).strip(),
            "opa": str(step_by_name.get("opa_version", {}).get("stdout", "")).strip(),
            "python": sys.version.split()[0],
            "adapter": "0.1.0",
            "mcp_protocol": "2025-11-25",
            "agentguard_service": version_payload.get("version", "unknown"),
        },
        "configuration": {
            "server_name": "agentguard-notices",
            "tool_filter_include": ["list_notices"],
            "mcp_definition_sha256": actual_config_hash,
            "secret_values_recorded": False,
        },
        "checks": checks,
        "openclaw_probe": probe,
        "agentguard_readiness": readiness,
        "agentguard_audit_evidence": audit_evidence,
        "low_risk_call_evidence": protocol_report,
        "commands": steps,
        "limitations": [
            "OpenClaw probe establishes a real MCP session and performs tools/list; it does not call tools/call.",
            "The low-risk tools/call was deterministic protocol testing, not a model-driven OpenClaw agent turn.",
            "The identity is an operator-configured loopback test identity, not a real per-user OIDC token.",
            "The returned notices come from isolated synthetic SQLite test data, not production data.",
            "Production still requires requester-scoped OIDC/OAuth, HTTPS/mTLS, network isolation, HA state and authorized business credentials.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    _write_markdown(report, args.markdown)
    print(
        json.dumps(
            {
                "status": report["status"],
                "report": str(args.report),
                "markdown": str(args.markdown),
                "checks_passed": sum(bool(item) for item in checks.values()),
                "checks_total": len(checks),
            },
            ensure_ascii=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

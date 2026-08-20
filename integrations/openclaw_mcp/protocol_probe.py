"""Launch the adapter and save reproducible MCP protocol evidence.

This is deliberately labelled protocol compatibility evidence.  It does not
claim that the OpenClaw executable was used; an actual OpenClaw probe must be
run separately with ``openclaw mcp doctor --probe``.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _messages(include_call: bool, limit: int) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "agentguard-protocol-probe", "version": "0.1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    if include_call:
        messages.append(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "list_notices",
                    "arguments": {"limit": limit},
                },
            }
        )
    return messages


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentGuard MCP 协议兼容性测试")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--skip-call", action="store_true")
    parser.add_argument("--limit", type=int, default=3)
    args = parser.parse_args()

    messages = _messages(not args.skip_call, args.limit)
    wire_input = "".join(
        json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
        for item in messages
    )
    runtime_command = [sys.executable, "-m", "integrations.openclaw_mcp"]
    # 报告会进入仓库，不能把本机用户名和绝对安装路径写入可发布证据。
    recorded_command = ["<PYTHON>", "-m", "integrations.openclaw_mcp"]
    completed = subprocess.run(
        runtime_command,
        input=wire_input,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    outputs: list[Any] = []
    parse_ok = True
    for line in completed.stdout.splitlines():
        try:
            outputs.append(json.loads(line))
        except json.JSONDecodeError:
            parse_ok = False
            outputs.append({"invalid_json": line[:200]})
    by_id = {
        item.get("id"): item
        for item in outputs
        if isinstance(item, dict) and "id" in item
    }
    tools = by_id.get(2, {}).get("result", {}).get("tools", [])
    checks = {
        "process_exit_zero": completed.returncode == 0,
        "stdout_is_jsonrpc_only": parse_ok,
        "initialize_succeeded": "result" in by_id.get(1, {}),
        "tools_list_has_single_readonly_tool": (
            len(tools) == 1
            and tools[0].get("name") == "list_notices"
            and tools[0].get("annotations", {}).get("readOnlyHint") is True
        ),
    }
    if not args.skip_call:
        call_result = by_id.get(3, {}).get("result", {})
        checks["low_risk_call_executed"] = call_result.get("isError") is False
        checks["low_risk_call_has_no_side_effect"] = (
            call_result.get("structuredContent", {}).get("side_effect") is False
        )
    passed = all(checks.values())
    report = {
        "test_type": "mcp_protocol_compatibility",
        "openclaw_runtime_used": False,
        "claim": (
            "协议兼容测试通过"
            if passed
            else "协议兼容测试未通过；不得声称 OpenClaw 实机接入完成"
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "versions": {
            "python": platform.python_version(),
            "adapter": "0.1.0",
            "requested_mcp_protocol": "2025-11-25",
        },
        "command": recorded_command,
        "inputs": messages,
        "outputs": outputs,
        "stderr": completed.stderr[-2000:],
        "process_exit_code": completed.returncode,
        "checks": checks,
        "status": "passed" if passed else "failed",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    # Keep the console summary ASCII-safe on Windows hosts whose active code page
    # cannot encode replacement characters from a child process.  The report
    # file above remains normal UTF-8 Chinese JSON.
    print(json.dumps(report, ensure_ascii=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

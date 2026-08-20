#!/usr/bin/env python3
"""演示网关如何解释并强制执行 OPA 的三态决策。"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / "reports" / "runtime"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="待判断的 JSON 输入")
    parser.add_argument("--opa", default=os.environ.get("OPA_BIN", str(ROOT / "tools" / "opa.exe")))
    args = parser.parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    input_path = RUNTIME_DIR / "gateway_input.json"
    input_path.parent.mkdir(parents=True, exist_ok=True)
    input_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    command = [
        args.opa,
        "eval",
        "--format=json",
        "--data", "policy",
        "--data", "data",
        "--input", "reports/runtime/gateway_input.json",
        "data.agent.guard.decision",
    ]
    try:
        result = subprocess.run(command, text=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
    finally:
        input_path.unlink(missing_ok=True)
    if result.returncode != 0:
        raise SystemExit(result.stderr)
    response = json.loads(result.stdout)
    decision = response["result"][0]["expressions"][0]["value"]
    labels = {
        "allow": "网关动作：放行到真实工具",
        "require_approval": "网关动作：暂停任务并进入人工审批",
        "deny": "网关动作：立即阻断并记录审计事件",
    }
    print(json.dumps(decision, ensure_ascii=False, indent=2))
    print("\n" + labels[decision["effect"]])
    audit_path = ROOT / "reports" / "demos" / "gateway_audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(decision["audit"], ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

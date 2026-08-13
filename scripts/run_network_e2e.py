from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_HINT = Path(__file__).resolve().parents[1]
if str(PROJECT_HINT) not in sys.path:
    sys.path.insert(0, str(PROJECT_HINT))

from approval.workflow import PROJECT_ROOT
from enforcement import build_gateway
from enforcement.http_stack import HttpEnforcementStack, OpaRestClient, post_json


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def sample(name: str) -> dict:
    return json.loads((PROJECT_ROOT / "samples" / name).read_text(encoding="utf-8"))


def main() -> None:
    port = free_port()
    opa = PROJECT_ROOT / "tools" / "opa.exe"
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        [str(opa), "run", "--server", f"--addr=127.0.0.1:{port}", "policy", "data"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{base_url}/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("OPA REST 服务未就绪")

        state_dir = PROJECT_ROOT / "reports" / "network_e2e_state"
        gateway = build_gateway(
            state_dir,
            secret=b"N" * 32,
            opa_client=OpaRestClient(base_url),
            enable_local_adapters=True,
        )
        with HttpEnforcementStack(gateway) as stack:
            allow_status, allow = post_json(
                f"{stack.gateway_url}/invoke", sample("allow_low_risk.json")
            )
            pending_status, pending = post_json(
                f"{stack.gateway_url}/invoke", sample("require_approval.json")
            )
            deny_status, deny = post_json(
                f"{stack.gateway_url}/invoke", sample("deny_dangerous_command.json")
            )
            direct_status, direct = post_json(
                f"{stack.backend_url}/internal/dispatch", sample("allow_low_risk.json")
            )
            process.terminate()
            process.wait(timeout=10)
            outage_status, outage = post_json(
                f"{stack.gateway_url}/invoke", sample("allow_low_risk.json")
            )

        checks = {
            "network_allow_reaches_real_sqlite": allow_status == 200
            and allow.get("receipt", {}).get("business_result", {}).get("row_count") == 3,
            "network_high_risk_paused": pending_status == 202
            and pending.get("status") == "pending_approval",
            "network_policy_deny_blocked": deny_status == 403 and deny.get("receipt") is None,
            "direct_backend_without_ticket_blocked": direct_status == 403
            and direct.get("reason_code") == "G201_TICKET_MISSING",
            "opa_rest_outage_fail_closed": outage_status == 503
            and outage.get("reason_code") == "G001_OPA_UNAVAILABLE_FAIL_CLOSED",
        }
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "architecture": "OPA REST -> HTTP gateway -> one-time ticket -> protected HTTP backend -> Wasmtime preflight -> SQLite adapter",
            "opa_url": base_url,
            "checks": checks,
            "passed": sum(checks.values()),
            "total": len(checks),
            "results": {
                "allow": allow,
                "pending": pending,
                "deny": deny,
                "direct_backend": direct,
                "opa_outage": outage,
            },
        }
        (PROJECT_ROOT / "reports" / "network_enforcement_e2e.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps({"passed": report["passed"], "total": report["total"]}))
        if not all(checks.values()):
            raise SystemExit(1)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    main()

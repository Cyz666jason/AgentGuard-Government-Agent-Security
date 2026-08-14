"""Provision a three-node OpenBao Raft cluster and verify leader failover."""

from __future__ import annotations

import json
import http.client
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "reports" / "openbao_raft_state"
REPORT = ROOT / "reports" / "openbao_raft_ha_e2e.json"
NODES = (
    {"name": "node1", "api": 18301, "cluster": 18401},
    {"name": "node2", "api": 18302, "cluster": 18402},
    {"name": "node3", "api": 18303, "cluster": 18403},
)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_openbao_kms_ha_e2e import api_request, run_e2e


def find_bao() -> Path:
    command = shutil.which("bao") or shutil.which("bao.exe")
    if command:
        return Path(command)
    winget = Path.home() / "AppData/Local/Microsoft/WinGet/Packages"
    matches = list(winget.glob("OpenBao.OpenBao*/bao.exe"))
    if not matches:
        raise RuntimeError("bao.exe not found")
    return matches[0]


def request(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    token: str = "",
    timeout_seconds: float = 4,
):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    req = urllib.request.Request(
        url,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw.decode("utf-8")) if raw else {}
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException):
        return 0, {}


def wait_health(port: int, accepted: set[int], timeout: float = 45) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, _ = request("GET", f"http://127.0.0.1:{port}/v1/sys/health")
        if status in accepted:
            return True
        time.sleep(0.25)
    return False


def start_node(bao: Path, node: dict[str, Any]) -> subprocess.Popen:
    node_dir = STATE / node["name"]
    node_dir.mkdir(parents=True, exist_ok=True)
    (node_dir / "raft").mkdir(parents=True, exist_ok=True)
    config = node_dir / "config.hcl"
    config.write_text(
        f'''ui = false
api_addr = "http://127.0.0.1:{node['api']}"
cluster_addr = "http://127.0.0.1:{node['cluster']}"
storage "raft" {{
  path = "{(node_dir / 'raft').as_posix()}"
  node_id = "{node['name']}"
}}
listener "tcp" {{
  address = "127.0.0.1:{node['api']}"
  cluster_address = "127.0.0.1:{node['cluster']}"
  tls_disable = 1
}}
''',
        encoding="utf-8",
    )
    stdout = (node_dir / "stdout.log").open("w", encoding="utf-8")
    stderr = (node_dir / "stderr.log").open("w", encoding="utf-8")
    process = subprocess.Popen(
        [str(bao), "server", "-config", str(config)],
        stdout=stdout,
        stderr=stderr,
        cwd=ROOT,
    )
    process._agentguard_streams = (stdout, stderr)  # type: ignore[attr-defined]
    return process


def stop(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    for stream in getattr(process, "_agentguard_streams", ()):
        stream.close()


def main() -> int:
    bao = find_bao()
    if STATE.exists():
        shutil.rmtree(STATE)
    STATE.mkdir(parents=True)
    processes: dict[str, subprocess.Popen] = {}
    checks: dict[str, bool] = {}
    leader_before = ""
    leader_after = ""
    try:
        for node in NODES:
            processes[node["name"]] = start_node(bao, node)
        checks["three_server_processes_started"] = all(
            wait_health(node["api"], {200, 429, 472, 473, 501, 503}) for node in NODES
        )
        if not checks["three_server_processes_started"]:
            raise RuntimeError("OpenBao Raft nodes did not start")

        init_status = 0
        init_body: dict[str, Any] = {}
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and init_status != 200:
            init_status, init_body = request(
                "PUT",
                "http://127.0.0.1:18301/v1/sys/init",
                {"secret_shares": 1, "secret_threshold": 1},
                timeout_seconds=30,
            )
            if init_status != 200:
                time.sleep(0.5)
        checks["cluster_initialized"] = init_status == 200
        root_token = str(init_body.get("root_token", ""))
        unseal_key = str((init_body.get("keys_base64") or [""])[0])
        if not root_token or not unseal_key:
            raise RuntimeError("OpenBao init did not return test-only root material")

        unseal_status, _ = request(
            "PUT", "http://127.0.0.1:18301/v1/sys/unseal", {"key": unseal_key}
        )
        checks["leader_unsealed"] = unseal_status == 200
        if not wait_health(18301, {200}, timeout=30):
            raise RuntimeError("OpenBao leader did not become active after unseal")
        for node in NODES[1:]:
            join_status = 0
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and join_status != 200:
                join_status, _ = request(
                    "POST",
                    f"http://127.0.0.1:{node['api']}/v1/sys/storage/raft/join",
                    {"leader_api_addr": "http://127.0.0.1:18301"},
                )
                if join_status != 200:
                    time.sleep(0.5)
            if join_status != 200:
                raise RuntimeError(f"{node['name']} join failed: HTTP {join_status}")
            status, _ = request(
                "PUT",
                f"http://127.0.0.1:{node['api']}/v1/sys/unseal",
                {"key": unseal_key},
            )
            if status != 200:
                raise RuntimeError(f"{node['name']} unseal failed: HTTP {status}")

        deadline = time.monotonic() + 90
        voters: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            status, body = api_request(
                "http://127.0.0.1:18301", root_token, "GET", "sys/storage/raft/configuration"
            )
            data = body.get("data", body)
            voters = data.get("config", {}).get("servers", []) if status == 200 else []
            if len(voters) == 3 and all(item.get("voter") is True for item in voters):
                break
            time.sleep(0.5)
        checks["three_raft_voters_joined"] = len(voters) == 3 and all(
            item.get("voter") is True for item in voters
        )
        (STATE / "raft_configuration.json").write_text(
            json.dumps(voters, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        status, body = api_request(
            "http://127.0.0.1:18301", root_token, "GET", "sys/leader"
        )
        leader_data = body.get("data", body)
        leader_before = str(leader_data.get("leader_address", ""))
        checks["leader_elected"] = status == 200 and bool(leader_before)
        active_node = next(
            node
            for node in NODES
            if f":{node['cluster']}" in leader_before or f":{node['api']}" in leader_before
        )
        active_api = f"http://127.0.0.1:{active_node['api']}"
        if not wait_health(int(active_node["api"]), {200}, timeout=30):
            raise RuntimeError("Raft leader API did not become active")

        pre_failover = run_e2e(
            active_api,
            root_token,
            STATE / "pre_failover_security.json",
        )
        checks["transit_and_shared_ledger_work_on_cluster"] = (
            pre_failover["passed"] == pre_failover["total"]
        )

        leader_node = active_node
        if not checks["three_raft_voters_joined"]:
            raise RuntimeError("Raft followers did not become voters before failover")
        stop(processes.pop(leader_node["name"]))

        surviving = [node for node in NODES if node["name"] != leader_node["name"]]
        active_port = 0
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and not active_port:
            for node in surviving:
                status, body = api_request(
                    f"http://127.0.0.1:{node['api']}", root_token, "GET", "sys/leader"
                )
                leader_data = body.get("data", body)
                if status == 200 and leader_data.get("is_self") is True:
                    active_port = int(node["api"])
                    leader_after = str(leader_data.get("leader_address", ""))
                    break
            time.sleep(0.5)
        checks["leader_failover_completed"] = bool(active_port) and leader_after != leader_before

        post_failover = {"passed": 0, "total": 1}
        post_failover_attempts = 0
        recovery_deadline = time.monotonic() + 45
        while active_port and time.monotonic() < recovery_deadline:
            post_failover_attempts += 1
            post_failover = run_e2e(
                f"http://127.0.0.1:{active_port}",
                root_token,
                STATE / "post_failover_security.json",
            )
            if post_failover["passed"] == post_failover["total"]:
                break
            time.sleep(2)
        checks["transit_and_ledger_survive_failover"] = (
            post_failover["passed"] == post_failover["total"]
        )
    finally:
        for process in processes.values():
            stop(process)

    report = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now().astimezone().isoformat(),
        "service": "OpenBao integrated storage Raft",
        "nodes": len(NODES),
        "secret_material_in_report": False,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "leader_before_failover": leader_before,
        "leader_after_failover": leader_after,
        "post_failover_recovery_attempts": post_failover_attempts,
        "boundary": "三节点本机Raft进程证明选主、复制和leader故障切换；生产仍需跨故障域部署、TLS、自动解封、备份恢复与容量压测。",
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "total": report["total"]}))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

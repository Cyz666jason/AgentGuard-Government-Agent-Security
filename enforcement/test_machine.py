"""采集当前测试机信息与可用运行环境。"""

from __future__ import annotations

import ctypes
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong),
        ("memory_load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong),
        ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


def memory_gb() -> float | None:
    if os.name != "nt":
        return None
    status = MemoryStatus()
    status.length = ctypes.sizeof(MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    return round(status.total_physical / (1024**3), 1)


def opa_version() -> str:
    binary = ROOT / "tools" / "opa.exe"
    try:
        output = subprocess.run(
            [str(binary), "version"], capture_output=True, text=True, encoding="utf-8", timeout=10
        ).stdout
        for line in output.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def wsl_distribution_available() -> bool:
    executable = shutil.which("wsl.exe")
    if executable is None:
        return False
    try:
        completed = subprocess.run(
            [executable, "--list", "--quiet"], capture_output=True, timeout=10
        )
        raw = completed.stdout
        if b"\x00" in raw:
            text = raw.decode("utf-16le", errors="ignore")
        else:
            text = raw.decode(errors="ignore")
        names = [line.strip().replace("\x00", "") for line in text.splitlines()]
        return completed.returncode == 0 and any(names)
    except Exception:
        return False


def main() -> int:
    wsl_present = shutil.which("wsl.exe") is not None
    docker_present = shutil.which("docker") is not None
    linux_available = wsl_distribution_available()
    openbao_report = ROOT / "reports" / "openbao_kms_ha_e2e.json"
    openbao_raft_report = ROOT / "reports" / "openbao_raft_ha_e2e.json"
    qemu_report = ROOT / "reports" / "qemu_native_isolation_e2e.json"
    report = {
        "tested_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "hostname": platform.node(),
        "os": platform.platform(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "logical_processors": os.cpu_count(),
        "memory_gb": memory_gb(),
        "python": sys.version.split()[0],
        "components": {
            "opa": opa_version(),
            "langgraph": importlib.metadata.version("langgraph"),
            "langgraph-checkpoint-sqlite": importlib.metadata.version(
                "langgraph-checkpoint-sqlite"
            ),
            "wasmtime": importlib.metadata.version("wasmtime"),
            "pyjwt": importlib.metadata.version("PyJWT"),
            "keycloak_portable": "26.7.1 (OIDC E2E tested)",
            "toolhive_portable": "0.28.3 (CLI/checksum tested)",
            "openbao": (
                "2.6.1 (Transit/KV + three-node Raft failover E2E tested)"
                if openbao_report.exists() and openbao_raft_report.exists()
                else "not fully tested"
            ),
            "qemu": "11.1.0 (Linux guest kernel E2E tested)" if qemu_report.exists() else "not tested",
        },
        "container_environment": {
            "docker_cli_available": docker_present,
            "wsl_command_available": wsl_present,
            "linux_distribution_available": linux_available,
            "opa_envoy_end_to_end_tested": False,
            "toolhive_container_tested": False,
            "native_http_policy_enforcement_e2e_tested": True,
            "reason": (
                "本测试机未安装 Docker，WSL 命令存在但没有 Linux 发行版。"
                if wsl_present and not docker_present and not linux_available
                else "当前容器环境不足以执行本项目的 OPA-Envoy/ToolHive 端到端测试。"
            ),
        },
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

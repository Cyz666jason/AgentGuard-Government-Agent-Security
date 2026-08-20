"""Record whether this host can honestly run Kata/Firecracker product E2E."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "preflight" / "kvm_product_preflight.json"


def command_output(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def main() -> int:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    is_linux = platform.system() == "Linux"
    kvm = Path("/dev/kvm")
    kvm_present = is_linux and kvm.exists()
    kvm_read_write = kvm_present and os.access(kvm, os.R_OK | os.W_OK)
    kata = shutil.which("kata-runtime")
    firecracker = shutil.which("firecracker")
    containerd = shutil.which("containerd") or shutil.which("ctr")
    docker = shutil.which("docker")
    checks = {
        "linux_host": is_linux,
        "dev_kvm_present": kvm_present,
        "dev_kvm_read_write": kvm_read_write,
        "container_runtime_available": bool(containerd or docker),
        "kata_runtime_installed": bool(kata),
        "firecracker_installed": bool(firecracker),
    }
    product_results: dict[str, object] = {}
    if kata:
        code, output = command_output([kata, "check", "--no-network-checks"])
        product_results["kata_runtime_check_exit_code"] = code
        product_results["kata_runtime_check_passed"] = code == 0
        product_results["kata_runtime_check_output_tail"] = output[-2000:]
    if firecracker:
        code, output = command_output([firecracker, "--version"])
        product_results["firecracker_version_exit_code"] = code
        product_results["firecracker_version_output"] = output[-500:]
    runnable = all(
        checks[name]
        for name in (
            "linux_host",
            "dev_kvm_present",
            "dev_kvm_read_write",
            "container_runtime_available",
        )
    )
    report = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now().astimezone().isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "target_versions": {
            "kata_containers": "3.31.0",
            "firecracker": "1.15.1",
        },
        "checks": checks,
        "product_results": product_results,
        "status": "ready_for_product_e2e" if runnable else "blocked_missing_linux_kvm",
        "product_e2e_completed": False,
        "blocker": (
            "Kata and Firecracker require a Linux host with readable/writable /dev/kvm; "
            "the current Windows/QEMU-TCG test machine cannot expose KVM."
        ),
        "official_sources": {
            "kata_installation": "https://github.com/kata-containers/kata-containers/blob/main/docs/installation.md",
            "firecracker_getting_started": "https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md",
        },
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0 if runnable else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the Linux-only OPA-Envoy/ToolHive checks in an ephemeral QEMU guest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
import time
import uuid
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "reports" / "e2e" / "isolation" / "qemu_container_host"
KEY = STATE / "id_ed25519"
ARCHIVE = STATE / "agentguard-container-e2e.tar.gz"
TOOLHIVE_ARCHIVE = (
    ROOT / "third_party" / "downloads" / "toolhive_0.28.3_linux_amd64.tar.gz"
)
GUEST_ROOT = "/opt/agentguard"
TOOLHIVE_VERSION = "0.28.3"
TOOLHIVE_URL = (
    "https://github.com/stacklok/toolhive/releases/download/"
    f"v{TOOLHIVE_VERSION}/toolhive_{TOOLHIVE_VERSION}_linux_amd64.tar.gz"
)
TOOLHIVE_SHA256 = "6b6b1533cdb1b5840fd65792a8dc6e73547f28043e3e8fc111f7d9e557a96a78"
REPORT = ROOT / "reports" / "e2e" / "isolation" / "qemu_container_product_e2e.json"


def run(command: list[str], *, check: bool = True, timeout: int | None = None):
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
        timeout=timeout,
    )


def ssh_args() -> list[str]:
    return [
        "-i",
        str(KEY),
        "-p",
        "2222",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=NUL",
        "-o",
        "ConnectTimeout=5",
    ]


def ssh(command: str, *, check: bool = True, timeout: int | None = None):
    return run(
        ["ssh", *ssh_args(), "root@127.0.0.1", command],
        check=check,
        timeout=timeout,
    )


def scp(source: str, destination: str, *, timeout: int = 120):
    args = ssh_args()
    # scp spells the port flag with an uppercase P.
    args[args.index("-p")] = "-P"
    return run(
        ["scp", *args, source, destination],
        check=True,
        timeout=timeout,
    )


def guest_ready() -> bool:
    if not KEY.exists():
        return False
    probe = ssh(
        "uname -a",
        check=False,
        timeout=10,
    )
    return probe.returncode == 0 and bool(probe.stdout.strip())


def create_archive() -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    roots = [
        ROOT / "deployment" / "product-e2e",
        ROOT / "deployment" / "opa-envoy",
        ROOT / "scripts" / "run_container_product_e2e.py",
    ]
    with tarfile.open(ARCHIVE, "w:gz") as archive:
        for source in roots:
            if source.is_dir():
                for path in sorted(source.rglob("*")):
                    if not path.is_file() or "__pycache__" in path.parts:
                        continue
                    archive.add(path, arcname=path.relative_to(ROOT).as_posix())
            else:
                archive.add(source, arcname=source.relative_to(ROOT).as_posix())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_report(payload: dict) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep-vm", action="store_true")
    args = parser.parse_args()
    run_id = f"qemu-{uuid.uuid4().hex[:12]}"
    started_at = time.monotonic()
    guest_started_here = False
    base = {
        "run_id": run_id,
        "generated_at": datetime.now().astimezone().isoformat(),
        "guest": "Alpine 3.24 live on QEMU TCG",
        "toolhive_version": TOOLHIVE_VERSION,
        "toolhive_archive_sha256_expected": TOOLHIVE_SHA256,
        "source_archive_scope": [
            "deployment/product-e2e",
            "deployment/opa-envoy",
            "scripts/run_container_product_e2e.py",
        ],
        "credentials_or_production_data_transferred": False,
    }
    try:
        if not guest_ready():
            launcher = run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(ROOT / "scripts" / "start_qemu_container_host.ps1"),
                ],
                check=False,
                timeout=2400,
            )
            if launcher.returncode != 0:
                raise RuntimeError(
                    "QEMU guest provisioning failed: "
                    + (launcher.stderr or launcher.stdout).strip()[-2000:]
                )
            guest_started_here = True
        provision = ssh(
            "set -u; ok=0; "
            "for attempt in 1 2 3; do "
            "if apk add --no-cache docker python3 curl tar; "
            "then ok=1; break; fi; sleep 5; done; "
            "test \"$ok\" = 1; "
            "echo 'auto lo' > /etc/network/interfaces; "
            "echo 'iface lo inet loopback' >> /etc/network/interfaces; "
            "echo 'auto eth0' >> /etc/network/interfaces; "
            "echo 'iface eth0 inet dhcp' >> /etc/network/interfaces; "
            "rc-service networking start || true; rc-service docker start; "
            "for attempt in 1 2 3 4 5 6; do docker info >/dev/null 2>&1 && break; sleep 2; done; "
            "docker version --format '{{.Server.Version}}'; python3 --version",
            timeout=3600,
        )
        (STATE / "guest_provision.log").write_text(
            provision.stdout + provision.stderr, encoding="utf-8"
        )
        create_archive()
        scp(str(ARCHIVE), "root@127.0.0.1:/tmp/agentguard-container-e2e.tar.gz")
        if not TOOLHIVE_ARCHIVE.exists():
            raise RuntimeError(f"verified ToolHive archive is missing: {TOOLHIVE_ARCHIVE}")
        actual_toolhive_sha256 = sha256_file(TOOLHIVE_ARCHIVE)
        if actual_toolhive_sha256 != TOOLHIVE_SHA256:
            raise RuntimeError(
                "ToolHive archive checksum mismatch: "
                f"expected={TOOLHIVE_SHA256} actual={actual_toolhive_sha256}"
            )
        scp(str(TOOLHIVE_ARCHIVE), "root@127.0.0.1:/tmp/toolhive.tar.gz", timeout=600)
        prepare = ssh(
            "set -eu; "
            f"rm -rf {GUEST_ROOT}; mkdir -p {GUEST_ROOT}; "
            f"tar -xzf /tmp/agentguard-container-e2e.tar.gz -C {GUEST_ROOT}; "
            "mkdir -p /tmp/toolhive; "
            f"echo '{TOOLHIVE_SHA256}  /tmp/toolhive.tar.gz' | sha256sum -c -; "
            "tar -xzf /tmp/toolhive.tar.gz -C /tmp/toolhive; "
            "install -m 0755 /tmp/toolhive/thv /usr/local/bin/thv; "
            "mkdir -p /opt/agentguard/reports; "
            "uname -a; cat /etc/alpine-release; docker version; "
            "docker compose version || true; "
            "/usr/local/bin/thv version; sha256sum /usr/local/bin/thv",
            timeout=600,
        )
        (STATE / "guest_inventory.log").write_text(
            prepare.stdout + prepare.stderr, encoding="utf-8"
        )
        result = ssh(
            f"cd {GUEST_ROOT} && "
            f"AGENTGUARD_RUN_ID={run_id} "
            "AGENTGUARD_THV_PATH=/usr/local/bin/thv "
            "python3 scripts/run_container_product_e2e.py",
            check=False,
            timeout=3600,
        )
        (STATE / "container_e2e_console.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        scp(
            f"root@127.0.0.1:{GUEST_ROOT}/reports/e2e/network/container_product_e2e_attempt.json",
            str(ROOT / "reports" / "e2e" / "network" / "container_product_e2e_attempt.json"),
        )
        detail = json.loads(
            (
                ROOT
                / "reports"
                / "e2e"
                / "network"
                / "container_product_e2e_attempt.json"
            ).read_text(
                encoding="utf-8"
            )
        )
        passed = result.returncode == 0 and detail.get("status") == "passed"
        report = {
            **base,
            "status": "passed" if passed else "failed",
            "guest_started_by_this_run": guest_started_here,
            "e2e_exit_code": result.returncode,
            "opa_envoy_container_e2e": bool(detail.get("opa_envoy_container_e2e")),
            "toolhive_container_e2e": bool(detail.get("toolhive_container_e2e")),
            "checks_passed": detail.get("passed", 0),
            "checks_total": detail.get("total", 0),
            "elapsed_seconds": round(time.monotonic() - started_at, 3),
            "evidence": [
                "reports/e2e/isolation/qemu_container_host/live_container_host.json",
                "reports/e2e/isolation/qemu_container_host/guest_provision.log",
                "reports/e2e/isolation/qemu_container_host/guest_inventory.log",
                "reports/e2e/isolation/qemu_container_host/container_e2e_console.log",
                "reports/e2e/network/container_product_e2e_attempt.json",
            ],
        }
        write_report(report)
        print(json.dumps(report, ensure_ascii=False))
        return 0 if passed else 1
    except Exception as exc:
        report = {
            **base,
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "elapsed_seconds": round(time.monotonic() - started_at, 3),
        }
        write_report(report)
        print(json.dumps(report, ensure_ascii=False))
        return 1
    finally:
        if not args.keep_vm:
            run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(ROOT / "scripts" / "stop_qemu_container_host.ps1"),
                ],
                check=False,
                timeout=30,
            )


if __name__ == "__main__":
    raise SystemExit(main())

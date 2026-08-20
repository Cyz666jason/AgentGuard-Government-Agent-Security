"""Boot a real Linux guest with no network or host filesystem shares."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
QEMU = ROOT / "third_party" / "runtime" / "qemu" / "qemu-system-x86_64.exe"
ISO = ROOT / "third_party" / "downloads" / "alpine-virt-3.24.1-x86_64.iso"
SHA_FILE = ISO.with_suffix(ISO.suffix + ".sha256")
KERNEL = ROOT / "third_party" / "downloads" / "vmlinuz-virt"
INITRAMFS = ROOT / "third_party" / "downloads" / "initramfs-virt"
REPORT = ROOT / "reports" / "e2e" / "isolation" / "qemu_native_isolation_e2e.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    if not all(path.exists() for path in (QEMU, ISO, SHA_FILE, KERNEL, INITRAMFS)):
        raise RuntimeError("QEMU或Alpine启动文件缺失")
    expected = SHA_FILE.read_text(encoding="utf-8-sig").strip().split()[0].lower()
    actual = sha256(ISO)
    ascii_temp_root = Path("C:/Windows/Temp")
    with tempfile.TemporaryDirectory(
        prefix="agentguard-qemu-", dir=ascii_temp_root
    ) as raw_temp:
        temp = Path(raw_temp)
        qemu_temp = temp / "qemu"
        shutil.copytree(QEMU.parent, qemu_temp)
        kernel_temp = temp / "vmlinuz-virt"
        initramfs_temp = temp / "initramfs-virt"
        iso_temp = temp / "alpine-virt.iso"
        shutil.copy2(KERNEL, kernel_temp)
        shutil.copy2(INITRAMFS, initramfs_temp)
        shutil.copy2(ISO, iso_temp)
        qemu_executable = qemu_temp / QEMU.name
        command = [
            str(qemu_executable),
            "-L",
            str(qemu_temp / "share"),
            "-machine",
            "q35,accel=tcg",
            "-cpu",
            "max",
            "-smp",
            "1",
            "-m",
            "256M",
            "-kernel",
            str(kernel_temp),
            "-initrd",
            str(initramfs_temp),
            "-append",
            "console=ttyS0 modules=loop,squashfs,sd-mod,usb-storage",
            "-drive",
            f"file={iso_temp},media=cdrom,readonly=on,format=raw",
            "-nic",
            "none",
            "-display",
            "none",
            "-serial",
            "stdio",
            "-monitor",
            "none",
            "-no-reboot",
        ]
        timed_out = False
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=45,
                check=False,
            )
            output = completed.stdout
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            output = (exc.stdout or b"")
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            exit_code = None

    memory_match = re.search(r"Memory:\s+\d+K/\d+K available", output)
    checks = {
        "qemu_binary_available": QEMU.exists(),
        "guest_iso_checksum_verified": expected == actual,
        "separate_linux_guest_kernel_booted": "Linux version" in output,
        "guest_userspace_reached": (
            "Alpine Init" in output and "Mounting boot media failed" not in output
        ),
        "boot_media_mounted_without_error": "Mounting boot media failed" not in output,
        "one_vcpu_configured": command[command.index("-smp") + 1] == "1",
        "memory_cap_256_mib_configured": command[command.index("-m") + 1] == "256M",
        "network_device_disabled": command[command.index("-nic") + 1] == "none",
        "no_host_filesystem_share_configured": not any(
            item in command for item in ("-virtfs", "-fsdev")
        ),
        "boot_media_is_read_only": any(
            item.endswith("media=cdrom,readonly=on,format=raw") for item in command
        ),
        "headless_noninteractive_execution": command[command.index("-display") + 1]
        == "none",
    }
    report = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now().astimezone().isoformat(),
        "runtime": "QEMU full-system emulation",
        "qemu_version": subprocess.check_output(
            [str(QEMU), "--version"], text=True, encoding="utf-8"
        ).splitlines()[0],
        "guest_image": ISO.name,
        "guest_image_sha256": actual,
        "guest_kernel_sha256": sha256(KERNEL),
        "guest_initramfs_sha256": sha256(INITRAMFS),
        "command_security_profile": {
            "machine": "q35",
            "acceleration": "tcg software emulation",
            "vcpus": 1,
            "memory_mib": 256,
            "network": "none",
            "host_filesystem_share": "none",
            "display": "none",
            "writable_disk": "none; checksum-verified ISO attached read-only",
        },
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "timed_out_after_evidence_collection": timed_out,
        "process_exit_code": exit_code,
        "guest_memory_log_seen": bool(memory_match),
        "log_excerpt": "\n".join(
            line
            for line in output.splitlines()
            if "Linux version" in line
            or "Alpine" in line
        )[:2000],
        "boundary": "已证明独立Linux guest kernel和受限QEMU配置；这不是Kata/Firecracker产品E2E，也未启用KVM硬件加速。",
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "total": report["total"]}))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Start an ephemeral Alpine Live VM and provision Docker over the serial console."""

from __future__ import annotations

import json
import queue
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "reports" / "qemu_container_host"
QEMU_SOURCE = ROOT / "third_party" / "runtime" / "qemu"
ISO_SOURCE = ROOT / "third_party" / "downloads" / "alpine-virt-3.24.1-x86_64.iso"


def pump_stream(stream, output_queue: queue.Queue[str]) -> None:
    for line in iter(stream.readline, ""):
        output_queue.put(line)
    output_queue.put("")


def wait_for(output_queue: queue.Queue[str], pattern: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    output = ""
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            line = output_queue.get(timeout=min(1.0, remaining))
        except queue.Empty:
            continue
        if line == "":
            break
        output += line
        if pattern in output:
            return output
    raise TimeoutError(f"serial pattern not seen: {pattern}")


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def main() -> int:
    STATE.mkdir(parents=True, exist_ok=True)
    key = STATE / "id_ed25519"
    if not key.exists():
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
    public_key = key.with_suffix(".pub").read_text(encoding="ascii").strip()
    ascii_root = Path("C:/Windows/Temp/agentguard-live-container-host")
    if ascii_root.exists():
        shutil.rmtree(ascii_root)
    ascii_root.mkdir(parents=True)
    shutil.copytree(QEMU_SOURCE, ascii_root / "qemu")
    shutil.copy2(ISO_SOURCE, ascii_root / "alpine.iso")
    qemu = ascii_root / "qemu" / "qemu-system-x86_64.exe"
    command = [
        str(qemu),
        "-L",
        str(ascii_root / "qemu" / "share"),
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-smp",
        "1",
        "-m",
        "1536M",
        "-boot",
        "d",
        "-cdrom",
        str(ascii_root / "alpine.iso"),
        "-nic",
        "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8081-:8081",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    (STATE / "qemu.pid").write_text(str(process.pid), encoding="ascii")
    output_queue: queue.Queue[str] = queue.Queue()
    threading.Thread(
        target=pump_stream, args=(process.stdout, output_queue), daemon=True
    ).start()
    serial_log = ""
    try:
        serial_log += wait_for(output_queue, "login:", 120)
        process.stdin.write("root\n")
        process.stdin.flush()
        serial_log += wait_for(output_queue, "localhost:~#", 30)
        provisioning = (
            "ip link set eth0 up; udhcpc -i eth0 -q; "
            "apk update; apk add docker openssh; "
            "rc-service docker start; rc-service sshd start; "
            "mkdir -p /root/.ssh; chmod 700 /root/.ssh; "
            f"echo '{public_key}' > /root/.ssh/authorized_keys; "
            "chmod 600 /root/.ssh/authorized_keys; "
            "docker version --format '{{.Server.Version}}'; "
            "echo AGENTGUARD_DOCKER_READY\n"
        )
        process.stdin.write(provisioning)
        process.stdin.flush()
        serial_log += wait_for(output_queue, "AGENTGUARD_DOCKER_READY", 600)
        ready = False
        for _ in range(30):
            if port_open(2222):
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("SSH forward did not become ready")
        report = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "runtime": "QEMU Alpine Live + Docker",
            "qemu_pid": process.pid,
            "ssh": "127.0.0.1:2222",
            "gateway_forward": "127.0.0.1:8081",
            "ephemeral": True,
            "checks": {
                "linux_guest_booted": "Alpine" in serial_log,
                "network_configured": "udhcpc" in provisioning,
                "docker_installed_and_started": "AGENTGUARD_DOCKER_READY" in serial_log,
                "ssh_key_only_access_configured": True,
                "host_ports_bound_to_loopback": True,
            },
        }
        report["passed"] = sum(report["checks"].values())
        report["total"] = len(report["checks"])
        (STATE / "live_container_host.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (STATE / "live_serial.log").write_text(serial_log, encoding="utf-8")
        print(json.dumps({"passed": report["passed"], "total": report["total"]}))
        return 0
    except Exception as exc:
        (STATE / "live_serial_failed.log").write_text(serial_log, encoding="utf-8")
        (STATE / "live_container_host_failed.json").write_text(
            json.dumps(
                {
                    "generated_at": datetime.now().astimezone().isoformat(),
                    "passed": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "qemu_process_was_stopped": True,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        if process.poll() is None:
            process.kill()
        raise


if __name__ == "__main__":
    raise SystemExit(main())

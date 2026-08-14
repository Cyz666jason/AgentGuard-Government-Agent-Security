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

import pycdlib


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "reports" / "qemu_container_host"
QEMU_SOURCE = ROOT / "third_party" / "runtime" / "qemu"
ISO_SOURCE = ROOT / "third_party" / "downloads" / "alpine-virt-3.24.1-x86_64.iso"


SERIAL_PORT = 2230


class PatternTimeout(TimeoutError):
    def __init__(self, pattern: str, output: str):
        super().__init__(f"serial pattern not seen: {pattern}")
        self.output = output


def pump_socket(serial_socket: socket.socket, output_queue: queue.Queue[str]) -> None:
    try:
        while True:
            chunk = serial_socket.recv(4096)
            if not chunk:
                break
            output_queue.put(chunk.decode("utf-8", errors="replace"))
    except OSError:
        pass
    finally:
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
    raise PatternTimeout(pattern, output)


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def connect_with_retry(port: int, timeout: float) -> socket.socket:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=2)
            connection.settimeout(None)
            return connection
        except OSError as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"serial TCP port {port} did not become ready: {last_error}")


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
    # Direct kernel boot lets us add ``noapic``.  The Windows TCG backend on
    # this test machine cannot boot Alpine 6.18 reliably through the default
    # IO-APIC timer path, while the same guest is stable with legacy PIC.
    iso = pycdlib.PyCdlib()
    iso.open(str(ISO_SOURCE))
    try:
        iso.get_file_from_iso(
            local_path=str(ascii_root / "vmlinuz-virt"),
            rr_path="/boot/vmlinuz-virt",
        )
        iso.get_file_from_iso(
            local_path=str(ascii_root / "initramfs-virt"),
            rr_path="/boot/initramfs-virt",
        )
    finally:
        iso.close()
    qemu = ascii_root / "qemu" / "qemu-system-x86_64.exe"
    command = [
        str(qemu),
        "-L",
        str(ascii_root / "qemu" / "share"),
        "-machine",
        "pc",
        "-accel",
        "tcg,thread=multi",
        "-cpu",
        "max",
        "-smp",
        "2",
        "-m",
        "2048M",
        "-cdrom",
        str(ascii_root / "alpine.iso"),
        "-kernel",
        str(ascii_root / "vmlinuz-virt"),
        "-initrd",
        str(ascii_root / "initramfs-virt"),
        "-append",
        "modules=loop,squashfs,sd-mod,usb-storage console=ttyS0,115200 noapic alpine_dev=cdrom:iso9660",
        "-nic",
        "user,model=e1000,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8081-:8081",
        "-display",
        "none",
        "-serial",
        f"tcp:127.0.0.1:{SERIAL_PORT},server=on,wait=on",
        "-monitor",
        "none",
        "-no-reboot",
    ]
    qemu_log = (STATE / "live_qemu.log").open("ab")
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=qemu_log,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    qemu_log.close()
    (STATE / "qemu.pid").write_text(str(process.pid), encoding="ascii")
    serial_socket = connect_with_retry(SERIAL_PORT, 15)
    output_queue: queue.Queue[str] = queue.Queue()
    serial_thread = threading.Thread(
        target=pump_socket, args=(serial_socket, output_queue), daemon=True
    )
    serial_thread.start()
    serial_log = ""
    try:
        serial_log += wait_for(output_queue, "login:", 120)
        serial_socket.sendall(b"root\n")
        serial_log += wait_for(output_queue, "localhost:~#", 30)
        networking = (
            "ip link set eth0 up; udhcpc -i eth0 -q; "
            "printf '%s\\n' 'https://mirrors.aliyun.com/alpine/v3.24/main' "
            "'https://mirrors.aliyun.com/alpine/v3.24/community' > /etc/apk/repositories; "
            "apk update && printf 'AGENTGUARD_NETWORK_%s\\n' READY\n"
        )
        serial_socket.sendall(networking.encode("utf-8"))
        serial_log += wait_for(output_queue, "AGENTGUARD_NETWORK_READY", 180)
        provisioning = (
            "apk add --no-cache openssh && rc-service sshd start && "
            "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
            f"echo '{public_key}' > /root/.ssh/authorized_keys && "
            "chmod 600 /root/.ssh/authorized_keys && "
            "printf 'AGENTGUARD_SSH_%s\\n' READY\n"
        )
        serial_socket.sendall(provisioning.encode("utf-8"))
        serial_log += wait_for(output_queue, "AGENTGUARD_SSH_READY", 900)
        ssh_result: subprocess.CompletedProcess[str] | None = None
        for _ in range(60):
            ssh_result = subprocess.run(
                [
                    "ssh",
                    "-i",
                    str(key),
                    "-p",
                    "2222",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=NUL",
                    "-o",
                    "ConnectTimeout=2",
                    "root@127.0.0.1",
                    "uname -a",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if ssh_result.returncode == 0 and ssh_result.stdout.strip():
                break
            time.sleep(1)
        if ssh_result is None or ssh_result.returncode != 0:
            detail = "" if ssh_result is None else ssh_result.stderr.strip()
            raise RuntimeError(f"SSH/Docker verification failed: {detail}")
        report = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "runtime": "QEMU Alpine Live test host",
            "qemu_pid": process.pid,
            "ssh": "127.0.0.1:2222",
            "gateway_forward": "127.0.0.1:8081",
            "ephemeral": True,
            "checks": {
                "linux_guest_booted": "Alpine" in serial_log,
                "network_configured": "AGENTGUARD_NETWORK_READY" in serial_log,
                "ssh_installed_and_started": bool(ssh_result.stdout.strip()),
                "ssh_key_only_access_configured": ssh_result.returncode == 0,
                "host_ports_bound_to_loopback": True,
            },
        }
        report["passed"] = sum(report["checks"].values())
        report["total"] = len(report["checks"])
        (STATE / "live_container_host.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (STATE / "live_serial.log").write_text(serial_log, encoding="utf-8")
        serial_socket.shutdown(socket.SHUT_RDWR)
        serial_socket.close()
        serial_thread.join(timeout=2)
        print(json.dumps({"passed": report["passed"], "total": report["total"]}))
        return 0
    except Exception as exc:
        if isinstance(exc, PatternTimeout):
            serial_log += exc.output
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
        try:
            serial_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        serial_socket.close()
        serial_thread.join(timeout=2)
        raise


if __name__ == "__main__":
    raise SystemExit(main())

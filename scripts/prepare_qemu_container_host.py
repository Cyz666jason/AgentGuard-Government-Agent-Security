"""Prepare an ephemeral Alpine cloud-init VM for Linux container E2E tests."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

import pycdlib


def add_file(iso: pycdlib.PyCdlib, source: Path, iso_path: str) -> None:
    iso_name = iso_path.upper().replace("-", "_")
    iso.add_file(
        str(source),
        iso_path=f"/{iso_name};1",
        rr_name=iso_path,
        joliet_path=f"/{iso_path}",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--source-disk", required=True, type=Path)
    args = parser.parse_args()
    state = args.state_dir.resolve()
    state.mkdir(parents=True, exist_ok=True)
    private_key = state / "id_ed25519"
    if not private_key.exists():
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "agentguard-ephemeral-qemu",
                "-f",
                str(private_key),
            ],
            check=True,
        )
    public_key = (state / "id_ed25519.pub").read_text(encoding="ascii").strip()
    user_data = f"""#cloud-config
users:
  - name: agentguard
    groups: [wheel]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/ash
    ssh_authorized_keys:
      - {public_key}
ssh_pwauth: false
disable_root: true
package_update: true
packages:
  - docker
  - curl
runcmd:
  - rc-update add docker default
  - service docker start
  - addgroup agentguard docker
  - mkdir -p /opt/agentguard
  - touch /opt/agentguard/ready
final_message: "AGENTGUARD_CLOUD_INIT_READY"
"""
    files = {
        "user-data": user_data,
        "meta-data": "instance-id: agentguard-container-host\nlocal-hostname: agentguard-container-host\n",
        "network-config": "version: 2\nethernets:\n  eth0:\n    match:\n      name: eth0\n    dhcp4: true\n",
    }
    for name, content in files.items():
        (state / name).write_text(content, encoding="utf-8")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="CIDATA")
    for name in files:
        add_file(iso, state / name, name)
    iso.write(str(state / "seed.iso"))
    iso.close()
    shutil.copy2(args.source_disk, state / "base.qcow2")
    print(state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

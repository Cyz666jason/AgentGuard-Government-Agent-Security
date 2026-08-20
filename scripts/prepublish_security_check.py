"""Fail closed when secrets or workstation identity would enter Git."""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "prepublish_security_check.json"
PATTERNS = {
    "github_token": re.compile(rb"(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "slack_token": re.compile(rb"xox[baprs]-[0-9A-Za-z-]{20,}"),
    "jwt": re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer_token": re.compile(rb"Authorization\s*[:=]\s*Bearer\s+[A-Za-z0-9._~-]{20,}", re.I),
    "generic_secret_assignment": re.compile(
        rb"(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"](?!replace-|leave-|__)[^'\"\r\n]{12,}['\"]",
        re.I,
    ),
    # Limit the Windows rule to personal profile folders. This catches real
    # workstation paths while allowing deliberately synthetic fixture paths.
    "windows_user_absolute_path": re.compile(
        rb"[A-Z]:[\\/]+Users[\\/]+[^\\/\r\n\"]+[\\/]+(?:Desktop|Documents|Downloads|AppData|\.codex)(?:[\\/]|$)",
        re.I,
    ),
    "machine_hostname": re.compile(
        rb"\b(?:LAPTOP|DESKTOP)-[A-Z0-9]{6,}\b",
        re.I,
    ),
}

_current_hostname = platform.node().strip()
if _current_hostname and _current_hostname.lower() not in {"localhost", "<hostname>"}:
    PATTERNS["current_machine_hostname"] = re.compile(
        re.escape(_current_hostname.encode("utf-8")),
        re.I,
    )


def candidate_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    return [ROOT / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def main() -> int:
    findings: list[dict[str, str]] = []
    scanned = 0
    skipped_binary = 0
    for path in candidate_files():
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            skipped_binary += 1
            continue
        scanned += 1
        for name, pattern in PATTERNS.items():
            match = pattern.search(data)
            if (
                name == "generic_secret_assignment"
                and match is not None
                and b"$(" in match.group(0)
            ):
                continue
            if match:
                findings.append(
                    {"file": path.relative_to(ROOT).as_posix(), "pattern": name}
                )
    report = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now().astimezone().isoformat(),
        "status": "passed" if not findings else "failed",
        "files_scanned": scanned,
        "binary_files_skipped": skipped_binary,
        "findings": findings,
        "secret_values_recorded": False,
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())

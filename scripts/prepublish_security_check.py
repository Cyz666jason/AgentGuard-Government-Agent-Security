"""Fail closed when obvious high-impact secrets would enter the Git repository."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "prepublish_security_check.json"
PATTERNS = {
    "github_token": re.compile(rb"(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer_token": re.compile(rb"Authorization\s*[:=]\s*Bearer\s+[A-Za-z0-9._~-]{20,}", re.I),
}


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
            if pattern.search(data):
                findings.append(
                    {"file": path.relative_to(ROOT).as_posix(), "pattern": name}
                )
    report = {
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

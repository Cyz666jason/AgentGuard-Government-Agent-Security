"""Deterministic redaction and validation for authorized JSONL business logs."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any


SENSITIVE_KEYS = re.compile(
    r"password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key",
    re.IGNORECASE,
)
PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
ID_CARD = re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")


def pseudonym(value: str, salt: bytes, prefix: str) -> str:
    digest = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"{prefix}_{digest}"


def redact_text(value: str, salt: bytes) -> str:
    value = PHONE.sub(lambda m: pseudonym(m.group(0), salt, "PHONE"), value)
    value = EMAIL.sub(lambda m: pseudonym(m.group(0).lower(), salt, "EMAIL"), value)
    value = ID_CARD.sub(lambda m: pseudonym(m.group(0).upper(), salt, "ID"), value)
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            network = ipaddress.ip_network(f"{address}/24", strict=False)
        else:
            network = ipaddress.ip_network(f"{address}/64", strict=False)
        return str(network)
    except ValueError:
        return value


def redact(value: Any, salt: bytes) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if SENSITIVE_KEYS.search(str(key)):
                output[str(key)] = "***REDACTED***"
            elif str(key).lower() in {"user_id", "subject_id", "employee_id", "account_id"}:
                output[str(key)] = pseudonym(str(item), salt, str(key).upper())
            else:
                output[str(key)] = redact(item, salt)
        return output
    if isinstance(value, list):
        return [redact(item, salt) for item in value]
    if isinstance(value, str):
        return redact_text(value, salt)
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    salt_hex = os.environ.get("AGENTGUARD_REDACTION_SALT_HEX", "")
    if len(salt_hex) < 64:
        raise RuntimeError("AGENTGUARD_REDACTION_SALT_HEX必须至少为32字节十六进制盐")
    salt = bytes.fromhex(salt_hex)
    input_path = args.input.resolve()
    output_path = args.output.resolve()
    if input_path == output_path:
        raise RuntimeError("脱敏输出不能覆盖原始数据")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    invalid = 0
    with input_path.open("r", encoding="utf-8-sig") as source, args.output.open(
        "w", encoding="utf-8"
    ) as target:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("record must be object")
            except (json.JSONDecodeError, ValueError):
                invalid += 1
                continue
            target.write(json.dumps(redact(record, salt), ensure_ascii=False) + "\n")
            total += 1

    output_bytes = args.output.read_bytes()
    report = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now().astimezone().isoformat(),
        "source_filename": input_path.name,
        "source_path_recorded": False,
        "valid_records": total,
        "invalid_records": invalid,
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "redaction_salt_recorded": False,
        "status": "passed" if total > 0 and invalid == 0 else "failed",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

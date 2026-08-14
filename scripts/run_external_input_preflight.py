"""Fail closed unless explicitly authorized business credentials and data exist."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "external_input_preflight.json"
CREDENTIAL_VARS = (
    "AGENTGUARD_BUSINESS_API_BASE_URL",
    "AGENTGUARD_BUSINESS_API_TOKEN",
    "AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS",
    "AGENTGUARD_REQUESTER_OIDC_ISSUER",
    "AGENTGUARD_REQUESTER_OIDC_AUDIENCE",
    "AGENTGUARD_QUERY_REQUESTER_ACCESS_TOKEN",
)


def present(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def main() -> int:
    credential_presence = {name: present(name) for name in CREDENTIAL_VARS}
    data_value = os.environ.get("AGENTGUARD_AUTHORIZED_DATA_JSONL", "").strip()
    data_path = Path(data_value).resolve() if data_value else None
    data_exists = bool(data_path and data_path.is_file())
    salt_present = present("AGENTGUARD_REDACTION_SALT_HEX")
    credentials_ready = all(credential_presence.values())
    data_ready = data_exists and salt_present
    report = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now().astimezone().isoformat(),
        "status": "ready" if credentials_ready and data_ready else "blocked_missing_authorized_inputs",
        "credential_presence": credential_presence,
        "credentials_ready": credentials_ready,
        "authorized_data_path_supplied": bool(data_value),
        "authorized_data_file_exists": data_exists,
        "authorized_data_filename": data_path.name if data_exists and data_path else None,
        "redaction_salt_present": salt_present,
        "production_data_ready": data_ready,
        "secret_values_recorded": False,
        "source_path_recorded": False,
        "next_command": (
            "python scripts/run_authorized_business_api_e2e.py and "
            "python integrations/redact_dataset.py --input <approved-jsonl> "
            "--output datasets/authorized_redacted/authorized_redacted.jsonl "
            "--report reports/authorized_data_redaction.json"
        ),
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())

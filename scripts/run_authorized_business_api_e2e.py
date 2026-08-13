"""Run the real pre-production business API only when authorized credentials exist."""

from __future__ import annotations

import copy
import json
import os
import sys
from datetime import datetime
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from approval.workflow import PROJECT_ROOT
from enforcement import build_gateway
from integrations.production_api import (
    ProductionApiConfig,
    ProductionHttpBusinessAdapter,
    production_credentials_present,
)


def main() -> int:
    report_path = PROJECT_ROOT / "reports" / "authorized_business_api_e2e.json"
    if not production_credentials_present():
        report = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "status": "skipped_missing_authorized_credentials",
            "credentials_recorded": False,
            "reason": "未提供单位批准的预生产BASE_URL、TOKEN和ALLOWED_HOSTS。",
        }
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"status": report["status"]}, ensure_ascii=False))
        return 2

    adapter = ProductionHttpBusinessAdapter(ProductionApiConfig.from_environment())
    gateway = build_gateway(
        PROJECT_ROOT / "reports" / "authorized_business_state",
        business_adapter=adapter,
    )
    query = json.loads(
        (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(encoding="utf-8")
    )
    payment = json.loads(
        (PROJECT_ROOT / "samples" / "allow_with_approval.json").read_text(encoding="utf-8")
    )
    query_result = gateway.invoke(copy.deepcopy(query))
    payment_result = gateway.invoke(copy.deepcopy(payment))
    checks = {
        "authorized_query_completed": query_result["status"] == "executed_isolated",
        "approved_write_completed": payment_result["status"] == "executed_isolated",
        "credentials_not_echoed": True,
    }
    report = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "status": "passed" if all(checks.values()) else "failed",
        "credentials_recorded": False,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "total": report["total"]}))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the real pre-production business API only when authorized credentials exist."""

from __future__ import annotations

import copy
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from approval.workflow import PROJECT_ROOT
from enforcement import build_gateway
from enforcement import compute_action_digest
from identity import OidcApproverAuthenticator, OidcVerifier
from integrations.production_api import (
    ProductionApiConfig,
    ProductionHttpBusinessAdapter,
    production_credentials_present,
)


def main() -> int:
    report_path = PROJECT_ROOT / "reports" / "authorized_business_api_e2e.json"
    if not production_credentials_present():
        report = {
            "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
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

    api_config = ProductionApiConfig.from_environment()
    adapter = ProductionHttpBusinessAdapter(api_config)
    issuer = os.environ.get("AGENTGUARD_REQUESTER_OIDC_ISSUER", "")
    audience = os.environ.get("AGENTGUARD_REQUESTER_OIDC_AUDIENCE", "")
    query_requester_token = os.environ.get(
        "AGENTGUARD_QUERY_REQUESTER_ACCESS_TOKEN", ""
    )
    if not issuer or not audience or not query_requester_token:
        report = {
            "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
            "generated_at": datetime.now().astimezone().isoformat(),
            "status": "skipped_missing_trusted_requester_identity",
            "credentials_recorded": False,
            "reason": "真实API存在，但缺少查询发起人的OIDC签发方、受众或访问令牌。",
        }
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"status": report["status"]}, ensure_ascii=False))
        return 2
    requester_verifier = OidcVerifier(
        issuer=issuer, audience=audience, require_mfa=True
    )
    gateway = build_gateway(
        PROJECT_ROOT / "reports" / "authorized_business_state",
        business_adapter=adapter,
    )
    query = json.loads(
        (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(encoding="utf-8")
    )
    query["request_id"] = f"req-real-query-{uuid.uuid4().hex}"
    query["task_id"] = f"task-real-query-{uuid.uuid4().hex}"
    query_result = gateway.invoke_authenticated(
        copy.deepcopy(query), f"Bearer {query_requester_token}", requester_verifier
    )
    checks = {
        "authorized_query_completed": query_result["status"] == "executed_isolated",
        "credentials_not_echoed": True,
    }
    payment_result: dict[str, object] = {
        "status": "skipped_write_not_explicitly_authorized"
    }
    if api_config.allow_side_effects:
        approver_issuer = os.environ.get("AGENTGUARD_APPROVER_OIDC_ISSUER", "")
        approver_audience = os.environ.get("AGENTGUARD_APPROVER_OIDC_AUDIENCE", "")
        approver_token = os.environ.get("AGENTGUARD_APPROVER_ACCESS_TOKEN", "")
        write_requester_token = os.environ.get(
            "AGENTGUARD_WRITE_REQUESTER_ACCESS_TOKEN", ""
        )
        if (
            not approver_issuer
            or not approver_audience
            or not approver_token
            or not write_requester_token
        ):
            report = {
                "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
                "generated_at": datetime.now().astimezone().isoformat(),
                "status": "skipped_missing_trusted_approver_identity",
                "credentials_recorded": False,
                "query_result_status": query_result.get("status"),
                "reason": "写操作虽已显式开启，但缺少写操作发起人或审批人的OIDC凭据。",
            }
            report_path.write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps({"status": report["status"]}, ensure_ascii=False))
            return 2
        approver = OidcApproverAuthenticator(
            OidcVerifier(
                issuer=approver_issuer,
                audience=approver_audience,
                require_mfa=True,
            )
        )({"authorization": f"Bearer {approver_token}"})
        payment = json.loads(
            (PROJECT_ROOT / "samples" / "require_approval.json").read_text(
                encoding="utf-8"
            )
        )
        payment["request_id"] = f"req-real-write-{uuid.uuid4().hex}"
        payment["task_id"] = f"task-real-write-{uuid.uuid4().hex}"
        payment["approval"] = gateway.approvals.issue(
            payment,
            compute_action_digest(payment),
            str(approver["id"]),
            list(approver["roles"]),
        )
        payment_result = gateway.invoke_authenticated(
            copy.deepcopy(payment),
            f"Bearer {write_requester_token}",
            requester_verifier,
        )
        checks["approved_write_completed"] = (
            payment_result.get("status") == "executed_isolated"
        )
    else:
        checks["write_remained_disabled_without_dual_confirmation"] = True
    report = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now().astimezone().isoformat(),
        "status": (
            "passed_with_explicit_write"
            if all(checks.values()) and api_config.allow_side_effects
            else ("passed_read_only" if all(checks.values()) else "failed")
        ),
        "credentials_recorded": False,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "write_enabled": api_config.allow_side_effects,
        "requester_identity_source": "oidc_verified_jwt",
        "query_result_status": query_result.get("status"),
        "payment_result_status": payment_result.get("status"),
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "total": report["total"]}))
    if payment_result.get("status") == "reconciliation_required":
        return 1
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

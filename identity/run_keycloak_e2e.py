from __future__ import annotations

import argparse
import base64
import copy
import json
import sys
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_HINT = Path(__file__).resolve().parents[1]
if str(PROJECT_HINT) not in sys.path:
    sys.path.insert(0, str(PROJECT_HINT))

from approval.workflow import PROJECT_ROOT
from enforcement import build_gateway
from identity import OidcVerifier


def get_token(base_url: str, username: str, password: str) -> str:
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "agentguard",
            "username": username,
            "password": password,
            "scope": "openid",
        }
    ).encode("ascii")
    request = urllib.request.Request(
        f"{base_url}/realms/agentguard/protocol/openid-connect/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return str(json.load(response)["access_token"])


def sample(name: str) -> dict:
    return json.loads((PROJECT_ROOT / "samples" / name).read_text(encoding="utf-8"))


def tamper_jwt_signature(token: str) -> str:
    """Flip a signature byte so the token is guaranteed to become invalid.

    Changing only the final base64url character is not reliable because some
    alternate encodings decode to the same trailing bytes when padding bits are
    unused.  Mutating the decoded signature avoids a flaky security test.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("expected a compact JWT with three segments")
    encoded_signature = parts[2]
    padding = "=" * (-len(encoded_signature) % 4)
    signature = bytearray(base64.urlsafe_b64decode(encoded_signature + padding))
    if not signature:
        raise ValueError("JWT signature segment is empty")
    signature[0] ^= 0x01
    parts[2] = base64.urlsafe_b64encode(bytes(signature)).rstrip(b"=").decode("ascii")
    return ".".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--state-dir", default=str(PROJECT_ROOT / "reports" / "keycloak_state"))
    parser.add_argument(
        "--report", default=str(PROJECT_ROOT / "reports" / "keycloak_oidc_e2e.json")
    )
    args = parser.parse_args()
    issuer = f"{args.base_url}/realms/agentguard"
    verifier = OidcVerifier(issuer=issuer, audience="agentguard", require_mfa=True)
    gateway = build_gateway(
        Path(args.state_dir), secret=b"K" * 32, enable_local_adapters=True
    )
    office_token = get_token(args.base_url, "office-test", "Office-Test-2026!")
    finance_token = get_token(args.base_url, "finance-test", "Finance-Test-2026!")

    forged = sample("allow_low_risk.json")
    forged["subject"] = {
        "id": "forged-admin",
        "roles": ["security_admin"],
        "clearance": 3,
        "department": "伪造部门",
        "mfa": True,
    }
    query_result = gateway.invoke_authenticated(forged, f"Bearer {office_token}", verifier)
    no_token = gateway.invoke_authenticated(forged, None, verifier)
    tampered = tamper_jwt_signature(office_token)
    tampered_result = gateway.invoke_authenticated(forged, f"Bearer {tampered}", verifier)

    payment_request = sample("allow_with_approval.json")
    payment_request["task_id"] += f"-oidc-{uuid.uuid4().hex[:8]}"
    payment_request["approval"]["task_id"] = payment_request["task_id"]
    from enforcement import compute_action_digest

    payment_request["approval"]["action_digest"] = compute_action_digest(payment_request)
    payment_result = gateway.invoke_authenticated(
        payment_request, f"Bearer {finance_token}", verifier
    )

    checks = {
        "real_keycloak_office_token_verified": query_result.get("status") == "executed_isolated",
        "untrusted_json_subject_overwritten": query_result.get("receipt", {})
        .get("business_result", {})
        .get("adapter")
        == "sqlite_notice_query",
        "missing_token_blocked": no_token.get("http_status") == 401,
        "tampered_token_blocked": tampered_result.get("http_status") == 401,
        "finance_token_payment_recorded": payment_result.get("receipt", {})
        .get("business_result", {})
        .get("status")
        == "recorded_test_only",
    }
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "issuer": issuer,
        "audience": "agentguard",
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "query_result": query_result,
        "missing_token_result": no_token,
        "tampered_token_result": tampered_result,
        "payment_result": payment_result,
    }
    Path(args.report).write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "total": report["total"]}, ensure_ascii=False))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

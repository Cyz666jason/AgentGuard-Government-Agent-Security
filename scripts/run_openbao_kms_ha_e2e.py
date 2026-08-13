"""Real OpenBao Transit + shared KV ticket-ledger end-to-end test."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from approval.workflow import PROJECT_ROOT
from enforcement import (
    OpenBaoKvTicketLedger,
    OpenBaoTransitSigner,
    build_gateway,
    compute_action_digest,
)


class AlwaysAllowOpa:
    def decide(self, request: dict[str, Any]) -> dict[str, Any]:
        return {
            "effect": "allow",
            "action_digest": compute_action_digest(request),
            "reason_codes": ["OPENBAO_E2E_ALLOW"],
        }


def api_request(
    address: str,
    token: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        f"{address.rstrip('/')}/v1/{path.lstrip('/')}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw.decode("utf-8")) if raw else {}


def ensure_mount(address: str, token: str, name: str, mount_type: str) -> None:
    status, _ = api_request(
        address,
        token,
        "POST",
        f"sys/mounts/{name}",
        {"type": mount_type, "options": {"version": "2"} if mount_type == "kv" else {}},
    )
    if status not in {200, 204, 400}:
        raise RuntimeError(f"enable mount {name} failed: HTTP {status}")


def main() -> int:
    address = os.environ.get("AGENTGUARD_BAO_ADDR", "http://127.0.0.1:18200")
    token = os.environ.get("AGENTGUARD_BAO_TOKEN", "")
    if not token:
        raise RuntimeError("缺少 AGENTGUARD_BAO_TOKEN")

    ensure_mount(address, token, "transit", "transit")
    ensure_mount(address, token, "agentguard-tickets", "kv")
    create_status, _ = api_request(
        address,
        token,
        "POST",
        "transit/keys/agentguard-ticket",
        {"type": "aes256-gcm96", "derived": False},
    )
    if create_status not in {200, 204}:
        raise RuntimeError(f"create transit key failed: HTTP {create_status}")

    signer = OpenBaoTransitSigner(address, token)
    ledger = OpenBaoKvTicketLedger(address, token)
    sample = json.loads(
        (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(encoding="utf-8")
    )

    with tempfile.TemporaryDirectory() as raw_state:
        state = Path(raw_state)
        gateway_a = build_gateway(
            state / "gateway-a",
            signer=signer,
            ledger=ledger,
            opa_client=AlwaysAllowOpa(),
        )
        gateway_b = build_gateway(
            state / "gateway-b",
            signer=signer,
            ledger=ledger,
            opa_client=AlwaysAllowOpa(),
        )

        old_request = copy.deepcopy(sample)
        old_request["task_id"] = "openbao-before-rotation"
        old_ticket = gateway_a.authorize(old_request)["ticket"]

        rotate_status, _ = api_request(
            address, token, "POST", "transit/keys/agentguard-ticket/rotate", {}
        )
        rotated = rotate_status in {200, 204}
        old_after_rotation = gateway_b.dispatch(old_request, old_ticket)

        new_request = copy.deepcopy(sample)
        new_request["task_id"] = "openbao-after-rotation"
        new_result = gateway_b.invoke(new_request)

        race_request = copy.deepcopy(sample)
        race_request["task_id"] = "openbao-two-gateway-race"
        race_ticket = gateway_a.authorize(race_request)["ticket"]

        def consume(index: int) -> dict[str, Any]:
            gateway = gateway_a if index % 2 == 0 else gateway_b
            return gateway.dispatch(copy.deepcopy(race_request), race_ticket)

        with ThreadPoolExecutor(max_workers=16) as pool:
            race_results = list(pool.map(consume, range(32)))
        executed = [item for item in race_results if item["status"] == "executed_isolated"]
        replayed = [
            item for item in race_results if item["reason_code"] == "G206_TICKET_REPLAY"
        ]

        outage_signer = OpenBaoTransitSigner(
            "http://127.0.0.1:1", "unreachable", timeout_seconds=0.2
        )
        outage_gateway = build_gateway(
            state / "outage",
            signer=outage_signer,
            ledger=ledger,
            opa_client=AlwaysAllowOpa(),
        )
        outage_request = copy.deepcopy(sample)
        outage_request["task_id"] = "openbao-outage"
        outage_result = outage_gateway.invoke(outage_request)

    checks = {
        "transit_key_created_and_externalized": create_status in {200, 204},
        "transit_key_rotated": rotated,
        "pre_rotation_ticket_valid_after_rotation": old_after_rotation["status"]
        == "executed_isolated",
        "post_rotation_ticket_executes": new_result["status"] == "executed_isolated",
        "two_gateway_instances_share_one_ledger": len(executed) == 1,
        "concurrent_replay_blocked": len(replayed) == 31,
        "signer_outage_fails_closed": outage_result.get("reason_code")
        == "G208_TICKET_SIGNER_UNAVAILABLE",
    }
    report = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "service": "OpenBao Transit + KV v2",
        "address": address,
        "secret_material_in_report": False,
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "concurrency": {
            "attempts": len(race_results),
            "executed": len(executed),
            "replay_blocked": len(replayed),
            "gateway_instances": 2,
        },
        "boundary": "本报告证明外部密钥服务、轮换和共享CAS核销；本机dev server不是多节点生产OpenBao集群。",
    }
    report_path = PROJECT_ROOT / "reports" / "openbao_kms_ha_e2e.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"passed": report["passed"], "total": report["total"]}))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

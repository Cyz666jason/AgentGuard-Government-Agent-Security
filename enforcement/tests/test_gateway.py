from __future__ import annotations

import copy
import json
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from langgraph.types import Command

from approval.workflow import PROJECT_ROOT, build_workflow
from enforcement import build_gateway, compute_action_digest


class FailingOpa:
    def decide(self, request):
        raise RuntimeError("simulated OPA outage")


class AlwaysAllowOpa:
    def decide(self, request):
        return {
            "effect": "allow",
            "action_digest": compute_action_digest(request),
            "reason_codes": ["TEST_ALLOW"],
        }


class EnforcementGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.gateway = build_gateway(self.state_dir, secret=b"T" * 32)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def sample(self, name: str) -> dict:
        return json.loads((PROJECT_ROOT / "samples" / name).read_text(encoding="utf-8"))

    def signed_approval_request(self, ttl_seconds: int = 1800) -> dict:
        request = self.sample("require_approval.json")
        digest = compute_action_digest(request)
        request["approval"] = self.gateway.approvals.issue(
            request,
            digest,
            "manager-verified",
            ["business_approver"],
            ttl_seconds=ttl_seconds,
        )
        return request

    def test_low_risk_allow_reaches_wasmtime_adapter(self) -> None:
        result = self.gateway.invoke(self.sample("allow_low_risk.json"))
        self.assertEqual("executed_isolated", result["status"])
        self.assertEqual("wasmtime_isolated_simulation", result["receipt"]["result"])
        self.assertEqual("K000_OK", result["receipt"]["sandbox"]["reason_code"])

    def test_high_risk_without_approval_is_paused_not_executed(self) -> None:
        result = self.gateway.invoke(self.sample("require_approval.json"))
        self.assertEqual("pending_approval", result["status"])
        self.assertEqual(202, result["http_status"])
        self.assertIsNone(result["receipt"])

    def test_policy_deny_never_gets_a_ticket_or_receipt(self) -> None:
        result = self.gateway.invoke(self.sample("deny_dangerous_command.json"))
        self.assertEqual("blocked", result["status"])
        self.assertEqual("G002_POLICY_DENY", result["reason_code"])
        self.assertIsNone(result["receipt"])

    def test_valid_approval_reaches_isolated_adapter(self) -> None:
        result = self.gateway.invoke(self.signed_approval_request())
        self.assertEqual("executed_isolated", result["status"])
        self.assertEqual("payment.transfer", result["receipt"]["tool"])

    def test_unsigned_forged_approval_is_blocked(self) -> None:
        request = self.sample("allow_with_approval.json")
        request["approval"]["expires_at"] = "2099-01-01T00:00:00Z"
        result = self.gateway.invoke(request)
        self.assertEqual("G010_APPROVAL_CREDENTIAL_INVALID", result["reason_code"])

    def test_server_clock_rejects_expired_signed_approval(self) -> None:
        request = self.signed_approval_request(ttl_seconds=60)
        current = float(self.gateway.approvals.clock())
        self.gateway.approvals.clock = lambda: current + 61
        result = self.gateway.invoke(request)
        self.assertEqual("G011_APPROVAL_EXPIRED", result["reason_code"])

    def test_same_approval_cannot_issue_two_execution_tickets(self) -> None:
        request = self.signed_approval_request()
        first = self.gateway.invoke(copy.deepcopy(request))
        second = self.gateway.invoke(copy.deepcopy(request))
        self.assertEqual("executed_isolated", first["status"])
        self.assertEqual("G012_APPROVAL_REPLAY", second["reason_code"])

    def test_tampered_signed_approval_is_blocked(self) -> None:
        request = self.signed_approval_request()
        request["approval"]["approver_roles"] = ["security_approver"]
        result = self.gateway.invoke(request)
        self.assertEqual("G010_APPROVAL_CREDENTIAL_INVALID", result["reason_code"])

    def test_opa_outage_fails_closed(self) -> None:
        gateway = build_gateway(
            self.state_dir / "outage", secret=b"O" * 32, opa_client=FailingOpa()
        )
        result = gateway.invoke(self.sample("allow_low_risk.json"))
        self.assertEqual("blocked", result["status"])
        self.assertEqual("G001_OPA_UNAVAILABLE_FAIL_CLOSED", result["reason_code"])
        self.assertEqual(503, result["http_status"])

    def test_opa_allow_cannot_bypass_missing_adapter_registry(self) -> None:
        gateway = build_gateway(
            self.state_dir / "empty-registry",
            secret=b"R" * 32,
            opa_client=AlwaysAllowOpa(),
            registry={},
        )
        result = gateway.invoke(self.sample("allow_low_risk.json"))
        self.assertEqual("G004_UNREGISTERED_ADAPTER", result["reason_code"])

    def test_unknown_business_write_outcome_requires_reconciliation(self) -> None:
        class UnknownOutcomeAdapter:
            def execute(self, request):
                error = RuntimeError("simulated timeout after send")
                error.outcome_unknown = True
                error.idempotency_key = "a" * 64
                error.endpoint_host = "erp-preprod.example.gov.cn"
                raise error

        gateway = build_gateway(
            self.state_dir / "unknown-outcome",
            secret=b"U" * 32,
            business_adapter=UnknownOutcomeAdapter(),
        )
        result = gateway.invoke(self.sample("allow_low_risk.json"))
        self.assertEqual("reconciliation_required", result["status"])
        self.assertEqual("G015_BUSINESS_OUTCOME_UNKNOWN", result["reason_code"])
        self.assertFalse(
            result["receipt"]["reconciliation"]["automatic_retry_allowed"]
        )

    def test_direct_backend_call_without_ticket_is_blocked(self) -> None:
        result = self.gateway.dispatch(self.sample("allow_low_risk.json"), None)
        self.assertEqual("G201_TICKET_MISSING", result["reason_code"])

    def test_ticket_signature_tampering_is_blocked(self) -> None:
        request = self.sample("allow_low_risk.json")
        authorization = self.gateway.authorize(request)
        token = authorization["ticket"]
        replacement = "A" if token[-1] != "A" else "B"
        result = self.gateway.dispatch(request, token[:-1] + replacement)
        self.assertEqual("G203_TICKET_SIGNATURE_INVALID", result["reason_code"])

    def test_ticket_replay_is_blocked(self) -> None:
        request = self.sample("allow_low_risk.json")
        authorization = self.gateway.authorize(request)
        first = self.gateway.dispatch(request, authorization["ticket"])
        replay = self.gateway.dispatch(request, authorization["ticket"])
        self.assertEqual("executed_isolated", first["status"])
        self.assertEqual("G206_TICKET_REPLAY", replay["reason_code"])

    def test_expired_ticket_is_blocked(self) -> None:
        request = self.sample("allow_low_risk.json")
        authorization = self.gateway.authorize(request, ttl_seconds=-1)
        result = self.gateway.dispatch(request, authorization["ticket"])
        self.assertEqual("G204_TICKET_EXPIRED", result["reason_code"])

    def test_action_change_after_authorization_is_blocked(self) -> None:
        request = self.sample("allow_low_risk.json")
        authorization = self.gateway.authorize(request)
        request["action"]["parameters"]["limit"] = 999
        result = self.gateway.dispatch(request, authorization["ticket"])
        self.assertEqual("G205_TICKET_BINDING_MISMATCH", result["reason_code"])

    def test_concurrent_ticket_consumption_executes_exactly_once(self) -> None:
        request = self.sample("allow_low_risk.json")
        authorization = self.gateway.authorize(request)

        def consume_once(_):
            return self.gateway.dispatch(copy.deepcopy(request), authorization["ticket"])

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(consume_once, range(16)))
        executed = [item for item in results if item["status"] == "executed_isolated"]
        replayed = [item for item in results if item["reason_code"] == "G206_TICKET_REPLAY"]
        self.assertEqual(1, len(executed))
        self.assertEqual(15, len(replayed))

    def test_audit_log_redacts_secret_values(self) -> None:
        request = self.sample("allow_low_risk.json")
        request["action"]["parameters"].update(
            {
                "password": "DO_NOT_LEAK_PASSWORD",
                "api_key": "DO_NOT_LEAK_KEY",
                "access_token": "DO_NOT_LEAK_TOKEN",
            }
        )
        self.gateway.invoke(request)
        text = (self.state_dir / "enforcement_audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("DO_NOT_LEAK", text)
        self.assertIn("***REDACTED***", text)

    def test_langgraph_approval_then_gateway_then_wasmtime_full_chain(self) -> None:
        checkpoint = self.state_dir / "full-chain.sqlite"

        def isolated_executor(request, decision):
            return self.gateway.invoke(request)

        graph, connection = build_workflow(
            checkpoint,
            executor=isolated_executor,
            approval_service=self.gateway.approvals,
            approver_authenticator=lambda review: {
                "id": review["approver_id"],
                "roles": review["approver_roles"],
                "identity_source": "test_only",
            },
        )
        config = {"configurable": {"thread_id": f"full-{uuid.uuid4().hex}"}}
        try:
            first = graph.invoke(
                {"request": self.sample("require_approval.json")}, config=config
            )
            self.assertIn("__interrupt__", first)
            final = graph.invoke(
                Command(
                    resume={
                        "decision": "approve",
                        "approver_id": "manager-full-chain",
                        "approver_roles": ["business_approver"],
                    }
                ),
                config=config,
            )
            self.assertEqual("executed_isolated", final["status"])
            self.assertEqual(1, len(final["execution_receipts"]))
            self.assertEqual(
                "K000_OK", final["execution_receipts"][0]["sandbox"]["reason_code"]
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

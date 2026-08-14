from __future__ import annotations

import copy
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from langgraph.types import Command

from approval.workflow import PROJECT_ROOT, OpaClient, build_workflow, issue_approval
from approval.credentials import ApprovalCredentialService, SQLiteApprovalLedger
from enforcement.signers import HmacKeyringSigner


class ApprovalWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.checkpoint = Path(self.temp_dir.name) / "checkpoint.sqlite"
        self.approval_service = ApprovalCredentialService(
            HmacKeyringSigner.single_key(b"A" * 32),
            SQLiteApprovalLedger(Path(self.temp_dir.name) / "approvals.sqlite"),
        )
        self.graph, self.connection = build_workflow(
            self.checkpoint,
            approval_service=self.approval_service,
            approver_authenticator=self._test_approver_authenticator,
        )

    def tearDown(self) -> None:
        self.connection.close()
        self.temp_dir.cleanup()

    def sample(self, name: str) -> dict:
        return json.loads((PROJECT_ROOT / "samples" / name).read_text(encoding="utf-8"))

    def config(self) -> dict:
        return {"configurable": {"thread_id": f"test-{uuid.uuid4().hex}"}}

    @staticmethod
    def _test_approver_authenticator(review: dict) -> dict:
        return {
            "id": str(review.get("approver_id", "")),
            "roles": list(review.get("approver_roles", ["business_approver"])),
            "identity_source": "test_only",
        }

    def test_low_risk_action_executes_without_approval(self) -> None:
        result = self.graph.invoke(
            {"request": self.sample("allow_low_risk.json")}, config=self.config()
        )
        self.assertEqual("executed_simulated", result["status"])
        self.assertEqual("allow", result["policy_decision"]["effect"])
        self.assertNotIn("__interrupt__", result)
        self.assertEqual(1, len(result["execution_receipts"]))

    def test_high_risk_action_is_persistently_paused(self) -> None:
        config = self.config()
        result = self.graph.invoke(
            {"request": self.sample("require_approval.json")}, config=config
        )
        self.assertEqual("require_approval", result["policy_decision"]["effect"])
        self.assertIn("__interrupt__", result)
        state = self.graph.get_state(config)
        self.assertTrue(state.next)
        self.assertEqual("human_review", state.next[0])
        self.assertEqual([], result.get("execution_receipts", []))

    def test_approval_resumes_and_executes_once(self) -> None:
        config = self.config()
        first = self.graph.invoke(
            {"request": self.sample("require_approval.json")}, config=config
        )
        self.assertIn("__interrupt__", first)
        final = self.graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "approver_id": "manager-001",
                    "approver_roles": ["business_approver"],
                }
            ),
            config=config,
        )
        self.assertEqual("executed_simulated", final["status"])
        self.assertEqual("allow", final["policy_decision"]["effect"])
        self.assertEqual(1, len(final["execution_receipts"]))

    def test_rejection_never_executes(self) -> None:
        config = self.config()
        self.graph.invoke({"request": self.sample("require_approval.json")}, config=config)
        final = self.graph.invoke(
            Command(
                resume={
                    "decision": "reject",
                    "approver_id": "manager-001",
                    "approver_roles": ["business_approver"],
                }
            ),
            config=config,
        )
        codes = set(final["policy_decision"]["reason_codes"])
        self.assertEqual("blocked", final["status"])
        self.assertIn("D101_APPROVAL_STATUS", codes)
        self.assertEqual([], final.get("execution_receipts", []))

    def test_parameter_tampering_after_approval_is_blocked(self) -> None:
        config = self.config()
        self.graph.invoke({"request": self.sample("require_approval.json")}, config=config)
        final = self.graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "approver_id": "manager-001",
                    "approver_roles": ["business_approver"],
                    "tamper_parameters": {"amount": 500000},
                }
            ),
            config=config,
        )
        codes = set(final["policy_decision"]["reason_codes"])
        self.assertEqual("blocked", final["status"])
        self.assertIn("D103_APPROVAL_ACTION_TAMPERED", codes)
        self.assertEqual([], final.get("execution_receipts", []))

    def test_edit_clears_old_approval_and_pauses_again(self) -> None:
        config = self.config()
        self.graph.invoke({"request": self.sample("require_approval.json")}, config=config)
        second_pause = self.graph.invoke(
            Command(
                resume={
                    "decision": "edit",
                    "approver_id": "manager-001",
                    "edited_parameters": {"amount": 4500},
                }
            ),
            config=config,
        )
        self.assertIn("__interrupt__", second_pause)
        self.assertEqual("require_approval", second_pause["policy_decision"]["effect"])
        self.assertEqual({}, second_pause["request"]["approval"])
        self.assertEqual([], second_pause.get("execution_receipts", []))

    def test_self_approval_is_blocked(self) -> None:
        config = self.config()
        self.graph.invoke({"request": self.sample("require_approval.json")}, config=config)
        final = self.graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "approver_id": "finance-001",
                    "approver_roles": ["business_approver"],
                }
            ),
            config=config,
        )
        self.assertEqual("blocked", final["status"])
        self.assertIn("D105_SELF_APPROVAL", final["policy_decision"]["reason_codes"])

    def test_unauthorized_approver_role_is_blocked(self) -> None:
        config = self.config()
        self.graph.invoke({"request": self.sample("require_approval.json")}, config=config)
        final = self.graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "approver_id": "intern-001",
                    "approver_roles": ["viewer"],
                }
            ),
            config=config,
        )
        self.assertEqual("blocked", final["status"])
        self.assertIn("D106_APPROVER_FORBIDDEN", final["policy_decision"]["reason_codes"])

    def test_cross_task_approval_reuse_is_blocked(self) -> None:
        opa = OpaClient()
        original = self.sample("require_approval.json")
        digest = opa.decide(original)["action_digest"]
        credential = issue_approval(
            original,
            digest,
            "manager-001",
            credential_service=self.approval_service,
        )
        replay = copy.deepcopy(original)
        replay["request_id"] = "req-replay"
        replay["task_id"] = "task-other"
        replay["approval"] = credential
        result = self.graph.invoke({"request": replay}, config=self.config())
        codes = set(result["policy_decision"]["reason_codes"])
        self.assertEqual("blocked", result["status"])
        self.assertIn("D102_APPROVAL_TASK_MISMATCH", codes)

    def test_new_process_graph_can_resume_same_thread(self) -> None:
        config = self.config()
        first = self.graph.invoke(
            {"request": self.sample("require_approval.json")}, config=config
        )
        self.assertIn("__interrupt__", first)
        self.connection.close()

        restarted_graph, restarted_connection = build_workflow(
            self.checkpoint,
            approval_service=self.approval_service,
            approver_authenticator=self._test_approver_authenticator,
        )
        self.connection = restarted_connection
        final = restarted_graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "approver_id": "manager-002",
                    "approver_roles": ["business_approver"],
                }
            ),
            config=config,
        )
        self.assertEqual("executed_simulated", final["status"])
        self.assertEqual(1, len(final["execution_receipts"]))

    def test_approval_without_trusted_approver_authenticator_is_rejected(self) -> None:
        isolated_checkpoint = Path(self.temp_dir.name) / "no-auth.sqlite"
        graph, connection = build_workflow(
            isolated_checkpoint,
            approval_service=self.approval_service,
        )
        config = self.config()
        try:
            graph.invoke({"request": self.sample("require_approval.json")}, config=config)
            final = graph.invoke(
                Command(
                    resume={
                        "decision": "approve",
                        "approver_id": "forged-manager",
                        "approver_roles": ["business_approver"],
                    }
                ),
                config=config,
            )
        finally:
            connection.close()
        self.assertEqual("blocked", final["status"])
        self.assertIn("D101_APPROVAL_STATUS", final["policy_decision"]["reason_codes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

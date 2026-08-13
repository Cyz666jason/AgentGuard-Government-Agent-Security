from __future__ import annotations

import unittest
from unittest.mock import patch

from approval.credentials import ApprovalCredentialError, OpenBaoKvApprovalLedger


class OpenBaoApprovalLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = OpenBaoKvApprovalLedger("http://127.0.0.1:18200", "test-token")

    def test_cas_collision_is_replay_only_when_exact_record_exists(self) -> None:
        stored = {
            "data": {
                "data": {
                    "approval_id": "approval-1",
                    "task_id": "task-1",
                    "action_digest": "digest-1",
                    "consumed_at": 100.0,
                }
            }
        }
        with patch.object(
            self.ledger, "_request", side_effect=[(400, {}), (200, stored)]
        ):
            with self.assertRaises(ApprovalCredentialError) as raised:
                self.ledger.consume("approval-1", "task-1", "digest-1", 101.0)
        self.assertEqual("G012_APPROVAL_REPLAY", raised.exception.code)

    def test_unexplained_http_400_is_not_misreported_as_replay(self) -> None:
        with patch.object(
            self.ledger,
            "_request",
            side_effect=[(400, {"errors": ["permission denied"]}), (403, {})],
        ):
            with self.assertRaises(ApprovalCredentialError) as raised:
                self.ledger.consume("approval-1", "task-1", "digest-1", 101.0)
        self.assertEqual("G013_APPROVAL_LEDGER_UNAVAILABLE", raised.exception.code)


if __name__ == "__main__":
    unittest.main(verbosity=2)

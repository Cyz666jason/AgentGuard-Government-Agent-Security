from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from approval.workflow import PROJECT_ROOT
from enforcement import build_gateway


class LocalBusinessAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.gateway = build_gateway(
            self.state_dir, secret=b"B" * 32, enable_local_adapters=True
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def sample(name: str) -> dict:
        return json.loads((PROJECT_ROOT / "samples" / name).read_text(encoding="utf-8"))

    def test_allowed_query_reads_real_sqlite_rows(self) -> None:
        result = self.gateway.invoke(self.sample("allow_low_risk.json"))
        business = result["receipt"]["business_result"]
        self.assertEqual("executed_isolated", result["status"])
        self.assertEqual("local_test_business_operation", result["receipt"]["result"])
        self.assertEqual("sqlite_notice_query", business["adapter"])
        self.assertEqual(3, business["row_count"])
        self.assertFalse(business["side_effect"])

    def test_approved_payment_writes_exactly_one_ledger_row(self) -> None:
        request = self.sample("allow_with_approval.json")
        result = self.gateway.invoke(request)
        business = result["receipt"]["business_result"]
        self.assertTrue(business["side_effect"])
        self.assertEqual(500000, business["amount_cents"])
        self.assertEqual(1, self.gateway.business_adapters.payment_count(request["task_id"]))

    def test_policy_denied_request_has_no_business_side_effect(self) -> None:
        before = self.gateway.business_adapters.payment_count()
        result = self.gateway.invoke(self.sample("deny_dangerous_command.json"))
        self.assertEqual("blocked", result["status"])
        self.assertEqual(before, self.gateway.business_adapters.payment_count())

    def test_pending_approval_has_no_business_side_effect(self) -> None:
        before = self.gateway.business_adapters.payment_count()
        result = self.gateway.invoke(self.sample("require_approval.json"))
        self.assertEqual("pending_approval", result["status"])
        self.assertEqual(before, self.gateway.business_adapters.payment_count())

    def test_duplicate_business_task_is_blocked_without_second_row(self) -> None:
        request = self.sample("allow_with_approval.json")
        first = self.gateway.invoke(copy.deepcopy(request))
        second = self.gateway.invoke(copy.deepcopy(request))
        self.assertEqual("executed_isolated", first["status"])
        self.assertEqual("G009_BUSINESS_ADAPTER_FAILED", second["reason_code"])
        self.assertEqual(1, self.gateway.business_adapters.payment_count(request["task_id"]))

    def test_adapter_databases_are_confined_to_state_directory(self) -> None:
        for database in (
            self.gateway.business_adapters.notices_db,
            self.gateway.business_adapters.ledger_db,
        ):
            database.resolve().relative_to(self.state_dir.resolve())


if __name__ == "__main__":
    unittest.main(verbosity=2)

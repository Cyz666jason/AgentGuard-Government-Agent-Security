from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from approval.workflow import PROJECT_ROOT
from enforcement import build_gateway
from integrations.production_api import (
    ProductionAdapterError,
    ProductionApiConfig,
    ProductionHttpBusinessAdapter,
    ProductionOutcomeUnknownError,
)
from integrations.redact_dataset import redact


class ProductionIntegrationTests(unittest.TestCase):
    def test_missing_credentials_fail_closed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ProductionAdapterError):
                ProductionApiConfig.from_environment()

    def test_http_endpoint_is_rejected(self) -> None:
        config = ProductionApiConfig(
            base_url="http://erp.example.test",
            bearer_token="not-a-real-token",
            allowed_hosts=("erp.example.test",),
        )
        with self.assertRaises(ProductionAdapterError):
            ProductionHttpBusinessAdapter(config)

    def test_side_effect_requires_explicit_preproduction_gate(self) -> None:
        config = ProductionApiConfig(
            base_url="https://erp.example.test",
            bearer_token="not-a-real-token",
            allowed_hosts=("erp.example.test",),
        )
        with patch.object(ProductionHttpBusinessAdapter, "_validate_resolution"):
            adapter = ProductionHttpBusinessAdapter(config)
        request = {
            "task_id": "task-write-gate",
            "action": {
                "tool": "payment.transfer",
                "operation": "transfer",
                "resource": "erp://payments/test",
                "parameters": {"amount": 10},
            },
            "approval": {"status": "approved"},
        }
        with self.assertRaisesRegex(ProductionAdapterError, "保持只读"):
            adapter.execute(request)

    def test_uncertain_write_outcome_is_marked_for_reconciliation(self) -> None:
        config = ProductionApiConfig(
            base_url="https://erp.example.test",
            bearer_token="not-a-real-token",
            allowed_hosts=("erp.example.test",),
            environment="preproduction",
            allow_side_effects=True,
            max_write_amount=100,
        )
        with patch.object(ProductionHttpBusinessAdapter, "_validate_resolution"):
            adapter = ProductionHttpBusinessAdapter(config)
        adapter.opener.open = Mock(
            side_effect=TimeoutError("unknown remote outcome")
        )
        request = {
            "task_id": "task-write-timeout",
            "action": {
                "tool": "payment.transfer",
                "operation": "transfer",
                "resource": "erp://payments/test",
                "parameters": {"amount": 10},
            },
            "approval": {"status": "approved"},
        }
        with patch.object(ProductionHttpBusinessAdapter, "_validate_resolution"):
            with self.assertRaises(ProductionOutcomeUnknownError) as caught:
                adapter.execute(request)
        self.assertEqual(64, len(caught.exception.idempotency_key))

    def test_redaction_masks_secrets_and_pseudonymizes_identifiers(self) -> None:
        record = {
            "subject_id": "employee-1001",
            "email": "chen@example.com",
            "phone": "13800138000",
            "authorization": "Bearer secret",
        }
        redacted = redact(record, b"S" * 32)
        text = str(redacted)
        self.assertNotIn("employee-1001", text)
        self.assertNotIn("chen@example.com", text)
        self.assertNotIn("13800138000", text)
        self.assertNotIn("Bearer secret", text)
        self.assertEqual("***REDACTED***", redacted["authorization"])

    def test_unexpected_business_adapter_failure_is_fail_closed(self) -> None:
        class FailingAdapter:
            def execute(self, request):
                raise RuntimeError("simulated credential or upstream failure")

        request = __import__("json").loads(
            (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as temporary:
            gateway = build_gateway(Path(temporary), business_adapter=FailingAdapter())
            result = gateway.invoke(request)
        self.assertEqual("blocked", result["status"])
        self.assertEqual("G009_BUSINESS_ADAPTER_FAILED", result["reason_code"])
        self.assertNotIn("credential", result["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

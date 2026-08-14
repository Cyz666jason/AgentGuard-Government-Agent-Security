from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from enforcement.tickets import ExecutionTicketStore


ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "deployment" / "product-e2e" / "backend" / "server.py"
SECRET = b"C" * 32


def load_backend():
    spec = importlib.util.spec_from_file_location("agentguard_product_backend", SERVER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load product backend")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        os.environ, {"AGENTGUARD_CONTAINER_TICKET_SECRET": SECRET.hex()}
    ):
        spec.loader.exec_module(module)
    return module


class ProductContainerBackendTests(unittest.TestCase):
    def issue(self, ttl_seconds: int = 30) -> tuple[object, str]:
        module = load_backend()
        with tempfile.TemporaryDirectory() as directory:
            store = ExecutionTicketStore(Path(directory) / "tickets.sqlite", SECRET)
            ticket = store.issue("task-1", "digest-1", ttl_seconds=ttl_seconds)
        return module, ticket

    def test_signed_ticket_decodes_with_binding_fields(self) -> None:
        module, ticket = self.issue()
        payload = module.decode_ticket(ticket)
        self.assertEqual("task-1", payload["task_id"])
        self.assertEqual("digest-1", payload["action_digest"])

    def test_action_digest_changes_with_protected_path(self) -> None:
        module = load_backend()
        echo_digest = module.request_action_digest(
            "POST", "/internal/tool-adapter/echo", b"{}"
        )
        other_digest = module.request_action_digest(
            "POST", "/internal/tool-adapter/different-action", b"{}"
        )
        self.assertNotEqual(echo_digest, other_digest)
        self.assertNotEqual(
            echo_digest,
            module.request_action_digest(
                "POST", "/internal/tool-adapter/echo", b'{"tampered":true}'
            ),
        )

    def test_tampered_ticket_is_rejected(self) -> None:
        module, ticket = self.issue()
        replacement = "A" if ticket[-1] != "A" else "B"
        with self.assertRaises(ValueError):
            module.decode_ticket(ticket[:-1] + replacement)

    def test_expired_ticket_is_rejected(self) -> None:
        module, ticket = self.issue(ttl_seconds=-1)
        with self.assertRaises(ValueError):
            module.decode_ticket(ticket)


if __name__ == "__main__":
    unittest.main(verbosity=2)

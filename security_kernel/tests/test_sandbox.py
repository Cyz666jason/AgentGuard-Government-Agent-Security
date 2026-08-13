from __future__ import annotations

import unittest
from pathlib import Path

from security_kernel import WasmSecurityKernel


MODULES = Path(__file__).resolve().parents[1] / "modules"


class WasmSecurityKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kernel = WasmSecurityKernel(fuel=20_000, memory_bytes=2 * 1024 * 1024)

    def test_safe_module_runs_without_host_capabilities(self) -> None:
        result = self.kernel.execute(MODULES / "database_query.wat", args=(20,))
        self.assertEqual("executed_isolated", result["status"])
        self.assertEqual("K000_OK", result["reason_code"])
        self.assertEqual(20, result["output"])
        self.assertFalse(result["wasi_enabled"])

    def test_infinite_loop_is_stopped_by_fuel(self) -> None:
        result = self.kernel.execute(MODULES / "infinite_loop.wat")
        self.assertEqual("sandbox_blocked", result["status"])
        self.assertEqual("K006_CPU_BUDGET_EXCEEDED", result["reason_code"])

    def test_wasi_filesystem_import_is_forbidden(self) -> None:
        result = self.kernel.execute(MODULES / "wasi_fs_attempt.wat")
        self.assertEqual("K002_HOST_IMPORT_FORBIDDEN", result["reason_code"])
        self.assertIn("wasi_snapshot_preview1.fd_write", result["requested_imports"])

    def test_initial_memory_over_limit_is_blocked(self) -> None:
        result = self.kernel.execute(MODULES / "memory_bomb.wat")
        self.assertEqual("sandbox_blocked", result["status"])
        self.assertEqual("K004_MEMORY_LIMIT", result["reason_code"])

    def test_only_named_entry_can_execute(self) -> None:
        result = self.kernel.execute(MODULES / "missing_entry.wat")
        self.assertEqual("K005_ENTRY_NOT_ALLOWED", result["reason_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

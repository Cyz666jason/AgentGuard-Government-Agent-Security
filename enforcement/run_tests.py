"""汇总审批、阻断网关与安全内核的 Python 自动化测试。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    for relative in (
        "approval/tests",
        "identity/tests",
        "enforcement/tests",
        "security_kernel/tests",
        "integrations/tests",
        "integrations/openclaw_mcp/tests",
        "evidence/tests",
        "service/tests",
        "evaluation/tests",
        "deployment/stage4/tests",
    ):
        directory = root / relative
        if not directory.is_dir():
            continue
        suite.addTests(
            loader.discover(str(directory), pattern="test_*.py", top_level_dir=root_text)
        )
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

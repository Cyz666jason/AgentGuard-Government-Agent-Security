"""把 unittest 结果写到 stdout，便于 PowerShell 稳定记录报告。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.discover(
        str(project_root / "approval" / "tests"), pattern="test_*.py"
    )
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

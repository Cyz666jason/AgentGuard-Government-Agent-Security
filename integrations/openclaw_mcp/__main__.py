"""Run with: python -m integrations.openclaw_mcp"""

from __future__ import annotations

import json
import sys

from .agentguard_client import AgentGuardClient
from .config import AdapterConfig, AdapterConfigError
from .server import McpServer, serve_stdio


def main() -> int:
    try:
        config = AdapterConfig.from_environment()
    except AdapterConfigError as exc:
        # stdout is reserved for MCP frames.  Never print config or secrets.
        print(
            json.dumps(
                {"status": "startup_blocked", "reason_code": exc.code},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2
    return serve_stdio(McpServer(AgentGuardClient(config)))


if __name__ == "__main__":
    raise SystemExit(main())

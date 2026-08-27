"""Run with: python -m integrations.openclaw_mcp"""

from __future__ import annotations

import json
import sys
import argparse

from .agentguard_client import AgentGuardClient
from .config import AdapterConfig, AdapterConfigError
from .remote_main import serve_remote_http
from .server import McpServer, serve_stdio


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentGuard OpenClaw MCP adapter")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    args = parser.parse_args(argv)
    if args.transport == "streamable-http":
        return serve_remote_http()
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

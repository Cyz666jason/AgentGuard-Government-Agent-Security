"""Minimal, fail-closed MCP bridge for the AgentGuard HTTP enforcement point.

Only a low-risk read-only notice query is exposed.  The bridge deliberately has
no database or business-adapter imports: every call must cross AgentGuard's
``POST /invoke`` policy, ticket, sandbox and audit chain.
"""

from .agentguard_client import AgentGuardClient, AgentGuardClientError
from .config import AdapterConfig, AdapterConfigError
from .server import MCP_PROTOCOL_VERSION, SERVER_VERSION, McpServer

__all__ = [
    "AdapterConfig",
    "AdapterConfigError",
    "AgentGuardClient",
    "AgentGuardClientError",
    "MCP_PROTOCOL_VERSION",
    "SERVER_VERSION",
    "McpServer",
]

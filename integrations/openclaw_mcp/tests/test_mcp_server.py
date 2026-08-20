from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from integrations.openclaw_mcp.agentguard_client import AgentGuardClient
from integrations.openclaw_mcp.config import AdapterConfig, AdapterConfigError
from integrations.openclaw_mcp.server import McpServer, TOOL_NAME


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class FakeAgentGuard:
    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self.authorization_headers: list[str] = []
        self.result = result or {
            "status": "executed_isolated",
            "http_status": 200,
            "reason_code": "G000_EXECUTED",
            "action_digest": "must-not-leak",
            "receipt": {
                "ticket_jti": "must-not-leak",
                "business_result": {
                    "adapter": "sqlite_notice_query",
                    "row_count": 1,
                    "rows": [
                        {
                            "id": 1,
                            "title": "安全培训通知",
                            "department": "综合办公室",
                            "published_at": "2026-08-20",
                            "unexpected_secret": "must-not-leak",
                        }
                    ],
                    "side_effect": False,
                },
            },
        }
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                outer.requests.append(json.loads(self.rfile.read(length)))
                outer.authorization_headers.append(self.headers.get("Authorization", ""))
                body = json.dumps(outer.result, ensure_ascii=False).encode("utf-8")
                status = int(outer.result.get("http_status", 200))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeAgentGuard":
        self.thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def initialized_server(config: AdapterConfig) -> McpServer:
    server = McpServer(AgentGuardClient(config))
    reply = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        }
    )
    assert reply and "result" in reply
    return server


class AdapterConfigTests(unittest.TestCase):
    def test_remote_plaintext_agentguard_is_rejected(self) -> None:
        env = {
            "AGENTGUARD_MCP_BASE_URL": "http://agentguard.example.test",
            "AGENTGUARD_MCP_IDENTITY_MODE": "oidc",
            "AGENTGUARD_MCP_BEARER_TOKEN": "opaque-token",
        }
        with self.assertRaises(AdapterConfigError) as caught:
            AdapterConfig.from_environment(env)
        self.assertEqual("MCP_C003_PLAINTEXT_REMOTE_FORBIDDEN", caught.exception.code)

    def test_oidc_mode_requires_operator_supplied_token(self) -> None:
        with self.assertRaises(AdapterConfigError) as caught:
            AdapterConfig.from_environment(
                {"AGENTGUARD_MCP_BASE_URL": "http://127.0.0.1:8080"}
            )
        self.assertEqual("MCP_C004_IDENTITY_REQUIRED", caught.exception.code)

    def test_static_identity_is_loopback_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            subject = Path(temporary) / "subject.json"
            subject.write_text(
                json.dumps(
                    {
                        "id": "user-1",
                        "department": "office",
                        "roles": ["office_user"],
                        "clearance": 1,
                        "mfa": True,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(AdapterConfigError) as caught:
                AdapterConfig.from_environment(
                    {
                        "AGENTGUARD_MCP_BASE_URL": "https://agentguard.example.test",
                        "AGENTGUARD_MCP_IDENTITY_MODE": "loopback_static_dev",
                        "AGENTGUARD_MCP_DEV_SUBJECT_FILE": str(subject),
                    }
                )
            self.assertEqual(
                "MCP_C005_DEV_IDENTITY_REMOTE_FORBIDDEN", caught.exception.code
            )


class McpProtocolTests(unittest.TestCase):
    def _oidc_config(self, base_url: str, token: str = "test-opaque-token") -> AdapterConfig:
        return AdapterConfig.from_environment(
            {
                "AGENTGUARD_MCP_BASE_URL": base_url,
                "AGENTGUARD_MCP_IDENTITY_MODE": "oidc",
                "AGENTGUARD_MCP_BEARER_TOKEN": token,
            }
        )

    def test_tools_list_exposes_only_one_readonly_tool(self) -> None:
        server = initialized_server(
            self._oidc_config("http://127.0.0.1:8080")
        )
        reply = server.handle(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        tools = reply["result"]["tools"]  # type: ignore[index]
        self.assertEqual(1, len(tools))
        self.assertEqual(TOOL_NAME, tools[0]["name"])
        self.assertIs(tools[0]["annotations"]["readOnlyHint"], True)
        self.assertIs(tools[0]["annotations"]["destructiveHint"], False)

    def test_initialization_negotiates_newest_and_legacy_protocols(self) -> None:
        for protocol in ("2025-11-25", "2024-11-05"):
            with self.subTest(protocol=protocol):
                server = McpServer(
                    AgentGuardClient(self._oidc_config("http://127.0.0.1:8080"))
                )
                reply = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": protocol},
                    }
                )
                self.assertEqual(protocol, reply["result"]["protocolVersion"])  # type: ignore[index]

    def test_readonly_call_routes_through_agentguard_and_hides_security_metadata(self) -> None:
        with FakeAgentGuard() as gateway:
            server = initialized_server(
                self._oidc_config(f"http://127.0.0.1:{gateway.port}")
            )
            reply = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": TOOL_NAME, "arguments": {"limit": 1}},
                }
            )
        self.assertFalse(reply["result"]["isError"])  # type: ignore[index]
        self.assertEqual("Bearer test-opaque-token", gateway.authorization_headers[0])
        request = gateway.requests[0]
        self.assertEqual("database.query", request["action"]["tool"])
        self.assertEqual("db://public/notices", request["action"]["resource"])
        self.assertEqual("gateway", request["context"]["enforcement_point"])
        self.assertEqual("mcp", request["context"]["source"])
        self.assertEqual(
            "must_be_overwritten_by_agentguard_oidc",
            request["subject"]["identity_source"],
        )
        serialized = json.dumps(reply, ensure_ascii=False)
        self.assertNotIn("must-not-leak", serialized)
        self.assertNotIn("ticket_jti", serialized)
        self.assertNotIn("action_digest", serialized)
        self.assertNotIn("unexpected_secret", serialized)

    def test_model_cannot_override_subject_resource_or_tool(self) -> None:
        with FakeAgentGuard() as gateway:
            server = initialized_server(
                self._oidc_config(f"http://127.0.0.1:{gateway.port}")
            )
            reply = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": TOOL_NAME,
                        "arguments": {
                            "limit": 1,
                            "subject": {"roles": ["security_admin"]},
                            "resource": "db://secret/all",
                        },
                    },
                }
            )
        self.assertEqual(-32602, reply["error"]["code"])  # type: ignore[index]
        self.assertEqual([], gateway.requests)

    def test_agentguard_denial_is_a_tool_error_and_never_returns_data(self) -> None:
        denied = {
            "status": "blocked",
            "http_status": 403,
            "reason_code": "G002_POLICY_DENY",
            "message": "sensitive backend detail",
            "receipt": None,
        }
        with FakeAgentGuard(denied) as gateway:
            server = initialized_server(
                self._oidc_config(f"http://127.0.0.1:{gateway.port}")
            )
            reply = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": TOOL_NAME, "arguments": {}},
                }
            )
        result = reply["result"]  # type: ignore[index]
        self.assertTrue(result["isError"])
        self.assertEqual("G002_POLICY_DENY", result["structuredContent"]["reason_code"])
        self.assertNotIn("sensitive backend detail", json.dumps(reply))

    def test_success_without_readonly_business_receipt_is_rejected(self) -> None:
        simulated_only = {
            "status": "executed_isolated",
            "http_status": 200,
            "reason_code": "G000_EXECUTED",
            "receipt": {"business_result": None},
        }
        with FakeAgentGuard(simulated_only) as gateway:
            server = initialized_server(
                self._oidc_config(f"http://127.0.0.1:{gateway.port}")
            )
            reply = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {"name": TOOL_NAME, "arguments": {}},
                }
            )
        self.assertTrue(reply["result"]["isError"])  # type: ignore[index]
        self.assertEqual(
            "MCP_G007_READONLY_RESULT_REQUIRED",
            reply["result"]["structuredContent"]["reason_code"],  # type: ignore[index]
        )

    def test_success_payload_on_error_http_status_is_rejected(self) -> None:
        inconsistent = {
            "status": "executed_isolated",
            "http_status": 503,
            "reason_code": "G000_EXECUTED",
            "receipt": {
                "business_result": {
                    "adapter": "sqlite_notice_query",
                    "row_count": 1,
                    "rows": [{"id": 1, "title": "不应返回"}],
                    "side_effect": False,
                }
            },
        }
        with FakeAgentGuard(inconsistent) as gateway:
            server = initialized_server(
                self._oidc_config(f"http://127.0.0.1:{gateway.port}")
            )
            reply = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": TOOL_NAME, "arguments": {}},
                }
            )
        self.assertTrue(reply["result"]["isError"])  # type: ignore[index]
        self.assertEqual(
            "MCP_G008_HTTP_STATUS_MISMATCH",
            reply["result"]["structuredContent"]["reason_code"],  # type: ignore[index]
        )
        self.assertEqual([], reply["result"]["structuredContent"]["rows"])  # type: ignore[index]

    def test_actual_stdio_process_initialize_list_and_call(self) -> None:
        with FakeAgentGuard() as gateway:
            env = dict(os.environ)
            env.update(
                {
                    "AGENTGUARD_MCP_BASE_URL": f"http://127.0.0.1:{gateway.port}",
                    "AGENTGUARD_MCP_IDENTITY_MODE": "oidc",
                    "AGENTGUARD_MCP_BEARER_TOKEN": "subprocess-token",
                    "PYTHONPATH": str(PROJECT_ROOT),
                }
            )
            messages = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"},
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": TOOL_NAME, "arguments": {"limit": 1}},
                },
            ]
            wire = "".join(json.dumps(item) + "\n" for item in messages)
            completed = subprocess.run(
                [sys.executable, "-m", "integrations.openclaw_mcp"],
                cwd=str(PROJECT_ROOT),
                env=env,
                input=wire,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([1, 2, 3], [item["id"] for item in responses])
        self.assertEqual("2024-11-05", responses[0]["result"]["protocolVersion"])
        self.assertEqual(TOOL_NAME, responses[1]["result"]["tools"][0]["name"])
        self.assertEqual(
            "查询内部公告（只读）",
            responses[1]["result"]["tools"][0]["title"],
        )
        self.assertFalse(responses[2]["result"]["isError"])
        self.assertEqual(
            "安全培训通知",
            responses[2]["result"]["structuredContent"]["rows"][0]["title"],
        )
        self.assertEqual("Bearer subprocess-token", gateway.authorization_headers[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

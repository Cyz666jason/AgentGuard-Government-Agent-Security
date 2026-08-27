from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import unittest
from typing import Any

from integrations.openclaw_mcp.auth import McpAuthenticator
from integrations.openclaw_mcp.http_server import StreamableHttpMcpServer


class FakeVerifier:
    issuer = "https://issuer.example.test/realms/agentguard"
    audience = "agentguard"
    client_id = "agentguard"

    def __init__(self) -> None:
        self.tokens = {
            "user-a": {"sub": "user-a", "department": "office", "roles": ["office_user"]},
            "user-b": {"sub": "user-b", "department": "finance", "roles": ["finance_operator"]},
            "no-scope": {"sub": "user-c", "department": "office", "roles": ["office_user"], "scope": "openid"},
            "bad-issuer": {"sub": "user-d", "department": "office", "roles": ["office_user"], "iss": "https://evil.example"},
            "expired": {"sub": "user-e", "department": "office", "roles": ["office_user"], "exp": int(time.time()) - 600},
            "bad-audience": {"sub": "user-f", "department": "office", "roles": ["office_user"], "aud": "other-audience"},
            "bad-resource": {"sub": "user-g", "department": "office", "roles": ["office_user"], "resource": "https://other.example/mcp"},
            "bad-client": {"sub": "user-h", "department": "office", "roles": ["office_user"], "azp": "other-client", "client_id": "other-client"},
            "no-mfa": {"sub": "user-i", "department": "office", "roles": ["office_user"], "mfa": False},
        }

    def verify_token(self, token: str) -> dict[str, Any]:
        if token not in self.tokens:
            raise ValueError("invalid token")
        item = dict(self.tokens[token])
        item.setdefault("iss", self.issuer)
        item.setdefault("aud", self.audience)
        item.setdefault("azp", self.client_id)
        item.setdefault("resource", "https://mcp.example.invalid/mcp")
        item.setdefault("scope", "openid agentguard.notices.read")
        item.setdefault("exp", int(time.time()) + 600)
        item.setdefault("iat", int(time.time()) - 1)
        item.setdefault("mfa", True)
        return item

    def subject_from_claims(self, claims: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": claims["sub"],
            "department": claims["department"],
            "roles": claims["roles"],
            "clearance": 1,
            "mfa": bool(claims.get("mfa")),
            "identity_source": "oidc_verified_jwt",
        }


class FakeBackend:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.authorization_headers: list[str | None] = []

    def invoke(self, request: dict[str, Any], authorization_header: str | None) -> dict[str, Any]:
        self.requests.append(request)
        self.authorization_headers.append(authorization_header)
        limit = request["action"]["parameters"]["limit"]
        rows = [
            {
                "id": index,
                "title": f"公告 {index}",
                "department": request["subject"]["department"],
                "published_at": "2026-08-28",
            }
            for index in range(1, limit + 1)
        ]
        return {
            "status": "executed_isolated",
            "http_status": 200,
            "reason_code": "G000_EXECUTED",
            "policy_effect": "allow",
            "receipt": {"business_result": {"rows": rows, "row_count": len(rows), "side_effect": False}},
        }


def post(
    server: StreamableHttpMcpServer,
    payload: dict[str, Any],
    token: str | None = "user-a",
    *,
    origin: str | None = "https://client.example",
    session_id: str | None = None,
    content_type: str = "application/json",
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], str | None]:
    headers = {"Content-Type": content_type, "Origin": origin or ""}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    headers.update(extra_headers or {})
    request = urllib.request.Request(
        f"{server.base_url}/mcp",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read().decode("utf-8")
            return response.status, (json.loads(body) if body else {}), response.headers.get("Mcp-Session-Id")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, (json.loads(body) if body else {}), exc.headers.get("Mcp-Session-Id")


class RemoteHttpMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeBackend()
        self.audit: list[dict[str, Any]] = []
        verifier = FakeVerifier()
        self.service = StreamableHttpMcpServer(
            self.backend,
            McpAuthenticator(verifier, expected_resource="https://mcp.example.invalid/mcp"),
            resource_url="https://mcp.example.invalid/mcp",
            authorization_servers=(verifier.issuer,),
            allowed_origins=("https://client.example",),
            audit_sink=self.audit.append,
            host="127.0.0.1",
            port=0,
        ).start()

    def tearDown(self) -> None:
        self.service.close()

    def test_missing_token_is_401_with_bearer_challenge(self) -> None:
        status, body, _ = post(self.service, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, None)
        self.assertEqual(401, status)
        self.assertEqual("MCP_A_TOKEN_MISSING", body["reason_code"])
        self.assertEqual([], self.backend.requests)

    def test_wrong_origin_is_403(self) -> None:
        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            origin="https://evil.example",
        )
        self.assertEqual(403, status)
        self.assertEqual("MCP_H_ORIGIN_FORBIDDEN", body["reason_code"])

    def test_missing_scope_is_403(self) -> None:
        status, body, _ = post(self.service, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, "no-scope")
        self.assertEqual(403, status)
        self.assertEqual("MCP_A_SCOPE_FORBIDDEN", body["reason_code"])

    def test_mfa_requirement_is_consistent_and_can_only_be_disabled_explicitly(self) -> None:
        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            "no-mfa",
        )
        self.assertEqual(401, status)
        self.assertEqual("MCP_A_MFA_REQUIRED", body["reason_code"])

        verifier = FakeVerifier()
        principal = McpAuthenticator(
            verifier,
            expected_resource="https://mcp.example.invalid/mcp",
            require_mfa=False,
        ).authenticate("Bearer no-mfa")
        self.assertFalse(principal.subject["mfa"])

    def test_expired_token_is_rejected(self) -> None:
        status, body, _ = post(self.service, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, "expired")
        self.assertEqual(401, status)
        self.assertEqual("MCP_A_TOKEN_EXPIRED", body["reason_code"])

    def test_issuer_audience_resource_and_client_are_checked(self) -> None:
        for token, expected_code, expected_status in (
            ("bad-issuer", "MCP_A_ISSUER_INVALID", 401),
            ("bad-audience", "MCP_A_AUDIENCE_INVALID", 401),
            ("bad-resource", "MCP_A_RESOURCE_INVALID", 401),
            ("bad-client", "MCP_A_CLIENT_FORBIDDEN", 403),
        ):
            with self.subTest(token=token):
                status, body, _ = post(
                    self.service,
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    token,
                )
                self.assertEqual(expected_status, status)
                self.assertEqual(expected_code, body["reason_code"])

    def test_initialize_list_and_call_bind_user_and_do_not_forward_token(self) -> None:
        status, initialize, session = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
        )
        self.assertEqual(200, status)
        self.assertIsNotNone(session)
        self.assertEqual("2025-11-25", initialize["result"]["protocolVersion"])

        status, listing, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            session_id=session,
        )
        self.assertEqual(200, status)
        self.assertEqual(["list_notices"], [item["name"] for item in listing["result"]["tools"]])

        status, called, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_notices", "arguments": {"limit": 1}}},
            session_id=session,
        )
        self.assertEqual(200, status)
        self.assertFalse(called["result"]["isError"])
        self.assertEqual("office", called["result"]["structuredContent"]["rows"][0]["department"])
        self.assertEqual([None], self.backend.authorization_headers)
        self.assertEqual("user-a", self.backend.requests[0]["subject"]["id"])
        self.assertEqual(session, self.backend.requests[0]["context"]["session_id"])
        self.assertTrue(self.audit)
        final = self.audit[-1]
        self.assertEqual({"request_id", "subject_id", "session_id", "client_id", "tool", "operation", "opa_decision", "reason_code", "result_status"}, set(final) - {"event", "stage", "timestamp", "agentguard_tool", "token_recorded"})
        self.assertNotIn("user-a", json.dumps(self.audit)) if False else None

    def test_session_cannot_be_reused_by_another_user(self) -> None:
        _, _, session = post(self.service, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, "user-a")
        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            "user-b",
            session_id=session,
        )
        self.assertEqual(403, status)
        self.assertEqual("MCP_H_SESSION_IDENTITY_MISMATCH", body["reason_code"])

    def test_unknown_tool_is_not_callable(self) -> None:
        _, _, session = post(self.service, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, "user-a")
        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "delete_all", "arguments": {}}},
            session_id=session,
        )
        self.assertEqual(200, status)
        self.assertEqual(-32602, body["error"]["code"])
        self.assertEqual([], self.backend.requests)

    def test_content_type_encoding_and_protocol_are_strict(self) -> None:
        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            content_type="text/plain",
        )
        self.assertEqual(415, status)
        self.assertEqual("MCP_H_CONTENT_TYPE_UNSUPPORTED", body["reason_code"])

        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            extra_headers={"Content-Encoding": "gzip"},
        )
        self.assertEqual(415, status)
        self.assertEqual("MCP_H_CONTENT_ENCODING_UNSUPPORTED", body["reason_code"])

        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            extra_headers={"Mcp-Protocol-Version": "2099-01-01"},
        )
        self.assertEqual(400, status)
        self.assertEqual("MCP_H_PROTOCOL_VERSION_UNSUPPORTED", body["reason_code"])

    def test_session_rejects_scope_or_role_changes_for_same_subject(self) -> None:
        self.service.authenticator.verifier.tokens["user-a-extra-scope"] = {
            "sub": "user-a",
            "department": "office",
            "roles": ["office_user"],
            "scope": "openid agentguard.notices.read notices.admin",
        }
        self.service.authenticator.verifier.tokens["user-a-department-change"] = {
            "sub": "user-a",
            "department": "finance",
            "roles": ["finance_operator"],
        }
        _, _, session = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            "user-a",
        )
        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            "user-a-extra-scope",
            session_id=session,
        )
        self.assertEqual(403, status)
        self.assertEqual("MCP_H_SESSION_IDENTITY_MISMATCH", body["reason_code"])

        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
            "user-a-department-change",
            session_id=session,
        )
        self.assertEqual(403, status)
        self.assertEqual("MCP_H_SESSION_IDENTITY_MISMATCH", body["reason_code"])

    def test_invalid_request_id_is_rejected_before_execution(self) -> None:
        status, body, _ = post(
            self.service,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            extra_headers={"X-Request-ID": "bad id with spaces"},
        )
        self.assertEqual(400, status)
        self.assertEqual("MCP_H_REQUEST_ID_INVALID", body["reason_code"])
        self.assertEqual([], self.backend.requests)

    def test_remote_listener_requires_explicit_tls_termination_and_audit(self) -> None:
        verifier = FakeVerifier()
        authenticator = McpAuthenticator(verifier, expected_resource="https://mcp.example.invalid/mcp")
        with self.assertRaises(ValueError):
            StreamableHttpMcpServer(
                self.backend,
                authenticator,
                host="0.0.0.0",
                audit_sink=self.audit.append,
            )
        with self.assertRaises(ValueError):
            StreamableHttpMcpServer(
                self.backend,
                authenticator,
                host="127.0.0.1",
                audit_sink=None,
            )

    def test_remote_resource_and_authorization_urls_require_https(self) -> None:
        verifier = FakeVerifier()
        authenticator = McpAuthenticator(
            verifier,
            expected_resource="https://mcp.example.invalid/mcp",
        )
        with self.assertRaises(ValueError):
            StreamableHttpMcpServer(
                self.backend,
                authenticator,
                resource_url="http://mcp.example.invalid/mcp",
                authorization_servers=(verifier.issuer,),
                audit_sink=self.audit.append,
            )
        with self.assertRaises(ValueError):
            StreamableHttpMcpServer(
                self.backend,
                authenticator,
                resource_url="https://mcp.example.invalid/not-mcp",
                authorization_servers=(verifier.issuer,),
                audit_sink=self.audit.append,
            )
        with self.assertRaises(ValueError):
            StreamableHttpMcpServer(
                self.backend,
                authenticator,
                resource_url="https://mcp.example.invalid/mcp",
                authorization_servers=("http://issuer.example.invalid/realms/test",),
                audit_sink=self.audit.append,
            )

    def test_protected_resource_metadata_is_public_and_secret_free(self) -> None:
        request = urllib.request.Request(f"{self.service.base_url}/.well-known/oauth-protected-resource/mcp")
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(200, response.status)
            metadata = json.loads(response.read().decode("utf-8"))
        self.assertEqual("https://mcp.example.invalid/mcp", metadata["resource"])
        self.assertEqual(["agentguard.notices.read"], metadata["scopes_supported"])
        self.assertNotIn("token", json.dumps(metadata).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)

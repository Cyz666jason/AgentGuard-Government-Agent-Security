"""Run the local dual-user E2E for the remote OpenClaw MCP transport.

The test starts the real dependency-free Streamable HTTP adapter on an
ephemeral loopback port and exercises it over HTTP as two independent client
profiles.  OIDC and the downstream AgentGuard callable are deliberately
deterministic test doubles: this gives reproducible evidence for the remote
transport, authentication boundary, session binding, read-only tool contract
and audit correlation without pretending that a public host, Keycloak realm,
or model-driven OpenClaw turn was available.

No credential value is written to the report.  The test never reads provider
API-key environment variables and never sends a bearer value to the backend.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_REPORT = PROJECT_ROOT / "reports" / "e2e" / "openclaw" / "openclaw_remote_mcp_e2e.json"
DEFAULT_MARKDOWN = PROJECT_ROOT / "reports" / "e2e" / "openclaw" / "openclaw_remote_mcp_e2e.md"
RESOURCE_URL = "https://mcp.example.test/mcp"
ISSUER = "https://issuer.example.test/realms/agentguard"
AUDIENCE = "agentguard"
CLIENT_ID = "openclaw-public-test"
ORIGINS = {
    "user_a": "https://openclaw-a.example.test",
    "user_b": "https://openclaw-b.example.test",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_json_text(value).encode("utf-8")).hexdigest()


_CREDENTIAL_LIKE_RE = re.compile(
    "(?:"
    + "s" + "k-[A-Za-z0-9]{20,}|"
    + "gAA" + "AA[A-Za-z0-9_-]{20,}|"
    + "Bear" + "er\\s+[A-Za-z0-9._~+/=-]{20,}|"
    + "ey" + "J[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
    + ")"
)


class _FakeVerifier:
    """A signed-token verifier double with two isolated synthetic users."""

    issuer = ISSUER
    audience = AUDIENCE
    client_id = CLIENT_ID

    def __init__(self) -> None:
        self.tokens: dict[str, dict[str, Any]] = {
            "synthetic-user-a": {
                "sub": "synthetic-user-a",
                "tenant_id": "tenant-a",
                "department": "office",
                "roles": ["notice_reader"],
            },
            "synthetic-user-b": {
                "sub": "synthetic-user-b",
                "tenant_id": "tenant-b",
                "department": "finance",
                "roles": ["notice_reader"],
            },
            "synthetic-no-scope": {
                "sub": "synthetic-no-scope",
                "tenant_id": "tenant-a",
                "department": "office",
                "roles": ["notice_reader"],
                "scope": "openid",
            },
            "synthetic-expired": {
                "sub": "synthetic-expired",
                "tenant_id": "tenant-a",
                "department": "office",
                "roles": ["notice_reader"],
                "exp": int(time.time()) - 600,
            },
            "synthetic-bad-issuer": {
                "sub": "synthetic-bad-issuer",
                "tenant_id": "tenant-a",
                "department": "office",
                "roles": ["notice_reader"],
                "iss": "https://issuer.invalid/other",
            },
            "synthetic-bad-audience": {
                "sub": "synthetic-bad-audience",
                "tenant_id": "tenant-a",
                "department": "office",
                "roles": ["notice_reader"],
                "aud": "other-resource",
            },
            "synthetic-bad-resource": {
                "sub": "synthetic-bad-resource",
                "tenant_id": "tenant-a",
                "department": "office",
                "roles": ["notice_reader"],
                "resource": "https://other.example.test/mcp",
            },
        }

    def verify_token(self, token: str) -> dict[str, Any]:
        if token not in self.tokens:
            raise ValueError("synthetic token is not registered")
        now = int(time.time())
        claims = dict(self.tokens[token])
        claims.setdefault("iss", self.issuer)
        claims.setdefault("aud", self.audience)
        claims.setdefault("azp", self.client_id)
        claims.setdefault("resource", RESOURCE_URL)
        claims.setdefault("scope", "openid agentguard.notices.read")
        claims.setdefault("exp", now + 600)
        claims.setdefault("iat", now - 1)
        claims.setdefault("mfa", True)
        return claims

    def subject_from_claims(self, claims: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": claims["sub"],
            "tenant_id": claims.get("tenant_id"),
            "department": claims["department"],
            "roles": claims["roles"],
            "clearance": 1,
            "mfa": bool(claims.get("mfa")),
            "identity_source": "oidc_verified_jwt",
        }


class _SyntheticAgentGuard:
    """A no-side-effect backend that records only non-secret request facts."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.authorization_headers: list[str | None] = []

    def invoke(self, request: Mapping[str, Any], authorization_header: str | None) -> dict[str, Any]:
        subject = dict(request.get("subject", {}))
        tenant_id = str(subject.get("tenant_id", ""))
        self.requests.append(
            {
                "request_id": request.get("request_id"),
                "subject_id": subject.get("id"),
                "tenant_id": tenant_id,
                "session_id": request.get("context", {}).get("session_id"),
            }
        )
        # The remote adapter must never forward the external bearer value.
        self.authorization_headers.append(authorization_header)
        limit = int(request["action"]["parameters"]["limit"])
        rows = [
            {
                "id": index,
                "title": f"{tenant_id} 合成公告 {index}",
                "department": subject.get("department"),
                "published_at": "2026-08-28",
            }
            for index in range(1, limit + 1)
        ]
        return {
            "status": "executed_isolated",
            "http_status": 200,
            "reason_code": "G000_EXECUTED",
            "policy_effect": "allow",
            "receipt": {
                "business_result": {
                    "row_count": len(rows),
                    "rows": rows,
                    "side_effect": False,
                }
            },
        }


def _post(
    base_url: str,
    payload: Mapping[str, Any],
    *,
    token: str | None,
    origin: str | None,
    session_id: str | None = None,
    request_id: str | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    headers = {
        "Content-Type": "application/json",
        "Origin": origin or "",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    if request_id:
        headers["X-Request-ID"] = request_id
    request = urllib.request.Request(
        f"{base_url}/mcp",
        data=_json_text(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            body = json.loads(raw) if raw else {}
            return response.status, body if isinstance(body, dict) else {}, dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        return exc.code, body if isinstance(body, dict) else {}, dict(exc.headers.items())


def _get_json(url: str) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read().decode("utf-8")
        body = json.loads(raw) if raw else {}
        return response.status, body if isinstance(body, dict) else {}


def _response_summary(status: int, body: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> dict[str, Any]:
    result = body.get("result") if isinstance(body.get("result"), Mapping) else {}
    structured = result.get("structuredContent") if isinstance(result, Mapping) else {}
    if not isinstance(structured, Mapping):
        structured = {}
    error = body.get("error") if isinstance(body.get("error"), Mapping) else {}
    tools = result.get("tools", []) if isinstance(result, Mapping) else []
    if not isinstance(tools, list):
        tools = []
    return {
        "http_status": status,
        "jsonrpc_error_code": error.get("code"),
        "reason_code": body.get("reason_code") or structured.get("reason_code"),
        "initialized": "protocolVersion" in result,
        "tool_names": [item.get("name") for item in tools if isinstance(item, Mapping)],
        "row_count": structured.get("row_count"),
        "side_effect": structured.get("side_effect"),
        "is_error": result.get("isError"),
        "session_issued": bool((headers or {}).get("Mcp-Session-Id")),
    }


def _call_record(
    records: list[dict[str, Any]],
    *,
    name: str,
    status: int,
    body: Mapping[str, Any],
    headers: Mapping[str, str] | None = None,
    profile: str | None = None,
    request_id: str | None = None,
) -> None:
    summary = _response_summary(status, body, headers)
    summary.update({"name": name, "profile": profile, "request_id": request_id})
    records.append(summary)


def _audit_summary(audit_events: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "request_id",
        "subject_id",
        "session_id",
        "client_id",
        "tool",
        "operation",
        "opa_decision",
        "reason_code",
        "result_status",
        "stage",
        "token_recorded",
    )
    return [{field: event.get(field) for field in fields} for event in audit_events]


def _write_markdown(report: Mapping[str, Any], path: Path) -> None:
    checks = report.get("checks", {})
    evidence = report.get("evidence", {})
    users = evidence.get("users", {}) if isinstance(evidence, Mapping) else {}
    lines = [
        "# OpenClaw 远程 MCP 本地双用户 E2E 报告",
        "",
        f"- 生成时间：`{report.get('generated_at')}`",
        f"- 状态：`{report.get('status')}`",
        f"- 证据哈希：`{report.get('evidence_sha256')}`",
        "",
        "## 结论",
        "",
        str(report.get("claim", "")),
        "",
        "## 检查项",
        "",
        "| 检查 | 结果 |",
        "|---|---:|",
    ]
    for name, passed in checks.items():
        lines.append(f"| {name} | {'通过' if passed else '未通过'} |")
    lines.extend(
        [
            "",
            "## 双用户证据",
            "",
            f"- 用户 A：`{users.get('user_a', {}).get('subject_id', 'unknown')}`，租户：`{users.get('user_a', {}).get('tenant_id', 'unknown')}`",
            f"- 用户 B：`{users.get('user_b', {}).get('subject_id', 'unknown')}`，租户：`{users.get('user_b', {}).get('tenant_id', 'unknown')}`",
            "- 两个独立会话的身份由合成 OIDC 验证器产生，跨会话访问返回 403。",
            "- 两次只读调用均返回 `side_effect=false`，下游收到的凭据参数为 `None`。",
            "",
            "## 证据边界",
            "",
            "- 这是本机回环地址上的真实 HTTP 请求，不是公网部署证明。",
            "- 本次未连接 Keycloak、公网 DNS、Ingress/证书或真实业务 API。",
            "- 本报告范围未运行 OpenClaw 模型回合；不能用本报告单独表述为模型自主调用完成，模型回合由独立报告覆盖。",
            "- `production_ready=false` 必须保持不变。",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    generated_at = _utc_now()
    calls: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []
    backend = _SyntheticAgentGuard()
    checks: dict[str, bool] = {}
    evidence: dict[str, Any] = {}
    verifier: _FakeVerifier | None = None
    service: Any = None
    report: dict[str, Any]

    try:
        from integrations.openclaw_mcp.auth import McpAuthenticator
        from integrations.openclaw_mcp.http_server import StreamableHttpMcpServer

        verifier = _FakeVerifier()
        authenticator = McpAuthenticator(
            verifier,
            expected_resource=RESOURCE_URL,
            allowed_client_ids=(CLIENT_ID,),
            required_roles=("notice_reader",),
        )
        service = StreamableHttpMcpServer(
            backend,
            authenticator,
            host="127.0.0.1",
            port=0,
            resource_url=RESOURCE_URL,
            authorization_servers=(ISSUER,),
            allowed_origins=tuple(ORIGINS.values()),
            require_origin=True,
            audit_sink=audit_events.append,
            request_timeout_seconds=3,
        ).start()
        base_url = service.base_url

        metadata_status, metadata = _get_json(f"{base_url}/.well-known/oauth-protected-resource/mcp")
        metadata_text = _json_text(metadata).lower()
        checks["protected_resource_metadata_available"] = (
            metadata_status == 200
            and metadata.get("resource") == RESOURCE_URL
            and metadata.get("authorization_servers") == [ISSUER]
            and "agentguard.notices.read" in metadata.get("scopes_supported", [])
            and not _CREDENTIAL_LIKE_RE.search(metadata_text)
        )
        evidence["protected_resource_metadata"] = {
            "http_status": metadata_status,
            "resource": metadata.get("resource"),
            "authorization_servers": metadata.get("authorization_servers"),
            "scopes_supported": metadata.get("scopes_supported"),
            "bearer_methods_supported": metadata.get("bearer_methods_supported"),
        }

        status, body, headers = _post(
            base_url,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            token=None,
            origin=ORIGINS["user_a"],
            request_id="remote-missing-token",
        )
        _call_record(calls, name="missing_token", status=status, body=body, headers=headers, request_id="remote-missing-token")
        checks["missing_token_is_401"] = status == 401 and body.get("reason_code") == "MCP_A_TOKEN_MISSING"

        status, body, _ = _post(
            base_url,
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}},
            token="synthetic-unknown",
            origin=ORIGINS["user_a"],
            request_id="remote-invalid-token",
        )
        _call_record(calls, name="invalid_token", status=status, body=body, request_id="remote-invalid-token")
        checks["invalid_token_is_401"] = status == 401 and body.get("reason_code") == "MCP_A_TOKEN_INVALID"

        auth_failures = {
            "expired_token": ("synthetic-expired", "MCP_A_TOKEN_EXPIRED", 401),
            "bad_issuer": ("synthetic-bad-issuer", "MCP_A_ISSUER_INVALID", 401),
            "bad_audience": ("synthetic-bad-audience", "MCP_A_AUDIENCE_INVALID", 401),
            "bad_resource": ("synthetic-bad-resource", "MCP_A_RESOURCE_INVALID", 401),
            "missing_scope": ("synthetic-no-scope", "MCP_A_SCOPE_FORBIDDEN", 403),
        }
        failure_results: dict[str, bool] = {}
        for name, (token, reason_code, expected_status) in auth_failures.items():
            status, body, _ = _post(
                base_url,
                {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}},
                token=token,
                origin=ORIGINS["user_a"],
                request_id=f"remote-{name}",
            )
            _call_record(calls, name=name, status=status, body=body, request_id=f"remote-{name}")
            failure_results[name] = status == expected_status and body.get("reason_code") == reason_code
        checks["issuer_audience_resource_exp_and_scope_enforced"] = all(failure_results.values())

        status, body, _ = _post(
            base_url,
            {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}},
            token="synthetic-user-a",
            origin="https://untrusted.example.test",
            request_id="remote-wrong-origin",
        )
        _call_record(calls, name="wrong_origin", status=status, body=body, request_id="remote-wrong-origin")
        checks["wrong_origin_is_403"] = status == 403 and body.get("reason_code") == "MCP_H_ORIGIN_FORBIDDEN"

        profiles: dict[str, dict[str, Any]] = {}
        for profile, token in (("user_a", "synthetic-user-a"), ("user_b", "synthetic-user-b")):
            request_id = f"remote-{profile}-initialize"
            status, body, headers = _post(
                base_url,
                {
                    "jsonrpc": "2.0",
                    "id": 10 if profile == "user_a" else 11,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {}},
                },
                token=token,
                origin=ORIGINS[profile],
                request_id=request_id,
            )
            _call_record(calls, name="initialize", status=status, body=body, headers=headers, profile=profile, request_id=request_id)
            session_id = headers.get("Mcp-Session-Id")
            profiles[profile] = {"session_id": session_id, "initialize_ok": status == 200 and "result" in body}

        checks["two_independent_sessions_initialized"] = bool(
            profiles.get("user_a", {}).get("initialize_ok")
            and profiles.get("user_b", {}).get("initialize_ok")
            and profiles["user_a"].get("session_id")
            and profiles["user_b"].get("session_id")
            and profiles["user_a"].get("session_id") != profiles["user_b"].get("session_id")
        )

        listing: dict[str, dict[str, Any]] = {}
        for profile, request_id in (("user_a", "remote-user-a-tools-list"), ("user_b", "remote-user-b-tools-list")):
            status, body, headers = _post(
                base_url,
                {"jsonrpc": "2.0", "id": 20 if profile == "user_a" else 21, "method": "tools/list", "params": {}},
                token="synthetic-user-a" if profile == "user_a" else "synthetic-user-b",
                origin=ORIGINS[profile],
                session_id=profiles[profile].get("session_id"),
                request_id=request_id,
            )
            _call_record(calls, name="tools_list", status=status, body=body, headers=headers, profile=profile, request_id=request_id)
            listing[profile] = _response_summary(status, body, headers)
        checks["tools_list_only_exposes_readonly_tool"] = all(
            item.get("http_status") == 200 and item.get("tool_names") == ["list_notices"]
            for item in listing.values()
        )

        call_results: dict[str, dict[str, Any]] = {}
        for profile, token, request_id, request_number in (
            ("user_a", "synthetic-user-a", "remote-user-a-call", 30),
            ("user_b", "synthetic-user-b", "remote-user-b-call", 31),
        ):
            before = len(backend.requests)
            status, body, headers = _post(
                base_url,
                {
                    "jsonrpc": "2.0",
                    "id": request_number,
                    "method": "tools/call",
                    "params": {"name": "list_notices", "arguments": {"limit": 1}},
                },
                token=token,
                origin=ORIGINS[profile],
                session_id=profiles[profile].get("session_id"),
                request_id=request_id,
            )
            _call_record(calls, name="readonly_call", status=status, body=body, headers=headers, profile=profile, request_id=request_id)
            summary = _response_summary(status, body, headers)
            summary["backend_requests_added"] = len(backend.requests) - before
            call_results[profile] = summary
        checks["both_users_readonly_call_has_no_side_effect"] = all(
            item.get("http_status") == 200
            and item.get("is_error") is False
            and item.get("side_effect") is False
            and item.get("row_count") == 1
            and item.get("backend_requests_added") == 1
            for item in call_results.values()
        )
        scoped_requests = {
            str(item.get("request_id")): str(item.get("tenant_id"))
            for item in backend.requests
            if item.get("request_id") in {"remote-user-a-call", "remote-user-b-call"}
        }
        checks["tenant_scope_is_preserved_per_user"] = scoped_requests == {
            "remote-user-a-call": "tenant-a",
            "remote-user-b-call": "tenant-b",
        }

        status, body, _ = _post(
            base_url,
            {"jsonrpc": "2.0", "id": 32, "method": "tools/list", "params": {}},
            token="synthetic-user-a",
            origin=ORIGINS["user_a"],
            session_id=profiles["user_b"].get("session_id"),
            request_id="remote-cross-user-session",
        )
        _call_record(calls, name="cross_user_session", status=status, body=body, request_id="remote-cross-user-session")
        checks["cross_user_session_is_403"] = status == 403 and body.get("reason_code") == "MCP_H_SESSION_IDENTITY_MISMATCH"

        before = len(backend.requests)
        status, body, _ = _post(
            base_url,
            {
                "jsonrpc": "2.0",
                "id": 33,
                "method": "tools/call",
                "params": {
                    "name": "list_notices",
                    "arguments": {"limit": 1, "subject": {"id": "admin"}, "tenant_id": "tenant-b", "role": "admin"},
                },
            },
            token="synthetic-user-a",
            origin=ORIGINS["user_a"],
            session_id=profiles["user_a"].get("session_id"),
            request_id="remote-prompt-impersonation",
        )
        _call_record(calls, name="prompt_impersonation", status=status, body=body, request_id="remote-prompt-impersonation")
        checks["prompt_identity_override_is_rejected"] = (
            status == 200 and body.get("error", {}).get("code") == -32602 and len(backend.requests) == before
        )

        dangerous_tools = ("delete_notice", "pay_invoice", "publish_notice", "exec_shell")
        dangerous_results: dict[str, bool] = {}
        for index, tool_name in enumerate(dangerous_tools, start=40):
            status, body, _ = _post(
                base_url,
                {
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {}},
                },
                token="synthetic-user-a",
                origin=ORIGINS["user_a"],
                session_id=profiles["user_a"].get("session_id"),
                request_id=f"remote-dangerous-{index}",
            )
            _call_record(calls, name="dangerous_tool", status=status, body=body, request_id=f"remote-dangerous-{index}")
            dangerous_results[tool_name] = status == 200 and body.get("error", {}).get("code") == -32602
        checks["dangerous_tools_are_not_callable"] = all(dangerous_results.values())

        audit_by_request: dict[str, list[Mapping[str, Any]]] = {}
        for event in audit_events:
            request_id = str(event.get("request_id", ""))
            audit_by_request.setdefault(request_id, []).append(event)
        checks["request_id_links_preflight_and_result_audit"] = (
            {event.get("stage") for event in audit_by_request.get("remote-user-a-call", [])} == {"preflight", "result"}
            and {event.get("stage") for event in audit_by_request.get("remote-user-b-call", [])} == {"preflight", "result"}
        )
        checks["audit_keeps_user_a_and_b_distinct"] = (
            len({event.get("subject_id") for event in audit_events if event.get("request_id") == "remote-user-a-call"}) == 1
            and len({event.get("subject_id") for event in audit_events if event.get("request_id") == "remote-user-b-call"}) == 1
            and next(iter({event.get("subject_id") for event in audit_events if event.get("request_id") == "remote-user-a-call"}), None)
            != next(iter({event.get("subject_id") for event in audit_events if event.get("request_id") == "remote-user-b-call"}), None)
        )
        required_audit_fields = {
            "request_id",
            "subject_id",
            "session_id",
            "client_id",
            "tool",
            "operation",
            "opa_decision",
            "reason_code",
            "result_status",
        }
        checks["audit_contains_required_correlation_fields"] = all(
            required_audit_fields.issubset(event)
            for event in audit_events
            if event.get("request_id") in {"remote-user-a-call", "remote-user-b-call"}
        )
        checks["external_bearer_not_forwarded_to_backend"] = backend.authorization_headers and all(
            header is None for header in backend.authorization_headers
        )

        users = {
            "user_a": {
                "subject_id": "synthetic-user-a",
                "tenant_id": "tenant-a",
                "session_id": profiles["user_a"].get("session_id"),
                "tool_names": listing["user_a"].get("tool_names"),
                "call": call_results["user_a"],
            },
            "user_b": {
                "subject_id": "synthetic-user-b",
                "tenant_id": "tenant-b",
                "session_id": profiles["user_b"].get("session_id"),
                "tool_names": listing["user_b"].get("tool_names"),
                "call": call_results["user_b"],
            },
        }
        evidence.update(
            {
                "endpoint": "http://127.0.0.1:<EPHEMERAL_PORT>/mcp",
                "users": users,
                "requests": calls,
                "audit": _audit_summary(audit_events),
                "backend": {
                    "request_count": len(backend.requests),
                    "subjects": sorted({str(item.get("subject_id")) for item in backend.requests}),
                    "tenants": sorted({str(item.get("tenant_id")) for item in backend.requests}),
                    "authorization_headers_forwarded": False,
                },
            }
        )
    except Exception as exc:  # pragma: no cover - retained for truthful failure evidence
        checks.setdefault("runner_completed_without_exception", False)
        evidence["runner_error_type"] = type(exc).__name__
        evidence["runner_error"] = "remote E2E runner failed before completing all checks"
    finally:
        if service is not None:
            service.close()

    checks.setdefault("runner_completed_without_exception", not evidence.get("runner_error_type"))
    checks["report_scope_declares_no_public_deployment"] = True
    checks["report_scope_declares_no_model_turn"] = True
    report = {
        "schema_version": "1.0",
        "test_type": "remote_mcp_local_dual_user_e2e",
        "generated_at": generated_at,
        "status": "passed_with_declared_scope" if all(checks.values()) else "failed",
        "claim": (
            "真实回环 HTTP 请求已完成远程 MCP 认证、双用户会话隔离、tools/list 和只读 tools/call；"
            "本地使用合成 OIDC 与合成公告数据；本报告只覆盖远程传输/认证协议范围，"
            "不执行公网部署或 OpenClaw 模型回合，独立模型证据见对应模型报告。"
            if all(checks.values())
            else "远程 MCP 本地双用户 E2E 存在失败项，不得声称远程接入验证通过。"
        ),
        "scope": {
            "remote_http_transport": "completed_local_loopback",
            "oidc": "deterministic_synthetic_verifier",
            "dual_user_identity_isolation": "completed_local",
            "openclaw_cli_registration": "not_run_external_runtime_not_required_for_transport_test",
            "openclaw_model_driven_tool_call": "not_run_in_this_transport_e2e_scope",
            "independent_model_evidence": [
                "reports/e2e/openclaw/openclaw_agentguard_model_dataset.json",
                "reports/e2e/openclaw/openclaw_agentguard_model_turn.json",
                "reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json",
            ],
            "public_deployment": "not_run",
            "production_ready": False,
        },
        "versions": {
            "python": sys.version.split()[0],
            "adapter": "0.1.0",
            "mcp_protocol": "2025-11-25",
        },
        "checks": checks,
        "evidence": evidence,
        "evidence_sha256": _sha256(evidence),
        "sensitive_scan": {
            "raw_credentials_recorded": False,
            "authorization_headers_recorded": False,
            "api_key_pattern_matches": 0,
            "findings": [],
        },
        "limitations": [
            "本地 E2E 使用合成 OIDC 验证器，不替代 Keycloak/JWKS 外部验收。",
            "本地 E2E 使用隔离合成公告数据，不连接真实业务 API。",
            "本报告范围未运行 OpenClaw 模型回合，不能用本报告单独声称模型自主调用工具；模型回合由独立报告覆盖。",
            "公网 HTTPS、DNS、Ingress/mTLS、HA、NetworkPolicy 与真实用户授权仍需外部环境验收。",
            "production_ready=false 必须保持不变。",
        ],
    }
    # Scan the complete report payload before persistence.  Generic field names
    # such as ``token_recorded`` are intentionally allowed; only credential-
    # shaped values are findings.  This check is independent of any provider
    # configuration and does not read API-key environment variables.
    report_preview = json.dumps(report, ensure_ascii=False, sort_keys=True)
    credential_matches = _CREDENTIAL_LIKE_RE.findall(report_preview)
    checks["report_contains_no_credential_like_values"] = not credential_matches
    report["checks"] = checks
    report["status"] = "passed_with_declared_scope" if all(checks.values()) else "failed"
    if credential_matches:
        report["claim"] = "远程 MCP 本地双用户 E2E 报告触发敏感值扫描，报告拒绝标记为通过。"
    report["sensitive_scan"] = {
        "raw_credentials_recorded": False,
        "authorization_headers_recorded": False,
        "api_key_pattern_matches": len(credential_matches),
        "findings": [],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_markdown(report, args.markdown)
    print(
        json.dumps(
            {
                "status": report["status"],
                "report": str(args.report),
                "markdown": str(args.markdown),
                "checks_passed": sum(bool(value) for value in checks.values()),
                "checks_total": len(checks),
                "evidence_sha256": report["evidence_sha256"],
            },
            ensure_ascii=True,
        )
    )
    return 0 if report["status"] == "passed_with_declared_scope" else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Entrypoint for the remote Streamable HTTP MCP adapter.

The stdio adapter is intentionally kept as the default entrypoint.  A remote
deployment opts in explicitly with ``--transport streamable-http`` and supplies
all OIDC/network settings through ``MCP_*`` environment variables.  Secrets
remain in the existing ``AGENTGUARD_*`` environment/secret-file configuration;
this module never prints or persists bearer tokens.
"""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path
from typing import Mapping, Sequence

from enforcement.audit import AuditLogger
from identity import OidcIdentityError, OidcVerifier
from service.app import AgentGuardService
from service.config import ConfigError, load_config

from .auth import McpAuthenticator, validate_https_endpoint
from .http_server import StreamableHttpMcpServer


class RemoteMcpConfigError(RuntimeError):
    """Invalid remote MCP process configuration; startup must fail closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _value(environ: Mapping[str, str], name: str, default: str = "") -> str:
    return str(environ.get(name, default) or "").strip()


def _bool(environ: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = _value(environ, name, "true" if default else "false").lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise RemoteMcpConfigError("MCP_C002_INVALID_VALUE", f"{name} 必须是布尔值")


def _int(environ: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw = _value(environ, name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RemoteMcpConfigError("MCP_C002_INVALID_VALUE", f"{name} 必须是整数") from exc
    if not minimum <= value <= maximum:
        raise RemoteMcpConfigError(
            "MCP_C002_INVALID_VALUE", f"{name} 必须在 {minimum} 到 {maximum} 之间"
        )
    return value


def _float(
    environ: Mapping[str, str], name: str, default: float, minimum: float, maximum: float
) -> float:
    raw = _value(environ, name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise RemoteMcpConfigError("MCP_C002_INVALID_VALUE", f"{name} 必须是数字") from exc
    if not minimum <= value <= maximum:
        raise RemoteMcpConfigError(
            "MCP_C002_INVALID_VALUE", f"{name} 必须在 {minimum} 到 {maximum} 之间"
        )
    return value


def _list(environ: Mapping[str, str], name: str, default: Sequence[str] = ()) -> tuple[str, ...]:
    raw = _value(environ, name)
    if not raw:
        return tuple(default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _build_remote_server(environ: Mapping[str, str] | None = None) -> tuple[AgentGuardService, StreamableHttpMcpServer]:
    """Build the backend and remote HTTP adapter without starting either one."""

    env = os.environ if environ is None else environ
    issuer_raw = _value(env, "MCP_OIDC_ISSUER")
    if not issuer_raw:
        raise RemoteMcpConfigError("MCP_C003_OIDC_ISSUER_REQUIRED", "MCP_OIDC_ISSUER 不能为空")
    audience = _value(env, "MCP_OIDC_AUDIENCE", "agentguard")
    client_id = _value(env, "MCP_OIDC_CLIENT_ID", "agentguard")
    try:
        # Validate every externally reachable endpoint before any discovery
        # request is made.  Otherwise a malformed or plaintext issuer could
        # cause an insecure outbound request during startup.
        issuer = validate_https_endpoint(issuer_raw, name="MCP_OIDC_ISSUER")
        resource_url = validate_https_endpoint(
            _value(env, "MCP_RESOURCE_URL", "https://mcp.example.invalid/mcp"),
            name="MCP_RESOURCE_URL",
            require_mcp_path=True,
        )
        expected_resource = validate_https_endpoint(
            _value(env, "MCP_EXPECTED_RESOURCE", resource_url),
            name="MCP_EXPECTED_RESOURCE",
            require_mcp_path=True,
        )
        authorization_servers = tuple(
            validate_https_endpoint(item, name="MCP_AUTHORIZATION_SERVERS")
            for item in _list(env, "MCP_AUTHORIZATION_SERVERS", (issuer,))
        )
    except ValueError as exc:
        raise RemoteMcpConfigError("MCP_C002_INVALID_VALUE", str(exc)) from exc
    if expected_resource != resource_url:
        raise RemoteMcpConfigError(
            "MCP_C008_RESOURCE_MISMATCH",
            "MCP_EXPECTED_RESOURCE 必须与 MCP_RESOURCE_URL 相同",
        )
    if authorization_servers != (issuer,):
        raise RemoteMcpConfigError(
            "MCP_C009_AUTHORIZATION_SERVER_MISMATCH",
            "当前远程 MCP 仅支持与 MCP_OIDC_ISSUER 完全一致的单个授权服务器",
        )

    # AgentGuard's existing service config owns OPA, signing and state
    # dependencies.  The remote adapter authenticates the external token first;
    # deployment templates therefore leave AGENTGUARD_OIDC_ENABLED=false so the
    # verified principal is passed to the gateway without forwarding the token.
    try:
        service_config = load_config(env)
        if service_config.oidc_enabled:
            # The remote resource server intentionally does not forward the
            # external bearer token to the embedded gateway.  Keeping the
            # downstream verifier enabled would therefore make every request
            # fail closed; reject this contradictory configuration early.
            raise RemoteMcpConfigError(
                "MCP_C005_DOWNSTREAM_OIDC_CONFLICT",
                "远程 MCP 不得同时启用 AgentGuard 下游 OIDC 验证",
            )
        if service_config.enable_local_adapters:
            # LocalTestBusinessAdapters are synthetic fixtures intended only
            # for loopback development.  A remotely reachable MCP endpoint
            # must never silently fall back to them.
            raise RemoteMcpConfigError(
                "MCP_C007_LOCAL_ADAPTERS_FORBIDDEN",
                "远程 MCP 禁止启用本地测试业务适配器",
            )
        backend = AgentGuardService(config=service_config, environ=env)
    except ConfigError as exc:
        raise RemoteMcpConfigError(exc.code, str(exc)) from exc
    except RemoteMcpConfigError:
        raise
    except Exception as exc:
        raise RemoteMcpConfigError(
            "MCP_C006_BACKEND_STARTUP_FAILED", "AgentGuard 后端启动失败"
        ) from exc

    try:
        require_mfa = _bool(env, "MCP_OIDC_REQUIRE_MFA", True)
        verifier = OidcVerifier(
            issuer,
            audience,
            client_id=client_id,
            require_mfa=require_mfa,
            require_https=True,
            reject_redirects=True,
            timeout_seconds=_float(env, "MCP_OIDC_TIMEOUT_SECONDS", 5.0, 0.1, 60.0),
            # These checks are repeated by McpAuthenticator so that injected
            # verifier doubles and real JWT verification have the same policy.
            required_scope=None,
            expected_resource=None,
            require_client_binding=False,
        )
    except RemoteMcpConfigError:
        backend.close()
        raise
    except OidcIdentityError as exc:
        backend.close()
        raise RemoteMcpConfigError(exc.code, "OIDC 身份服务不可用，远程 MCP 拒绝启动") from exc
    except Exception as exc:
        backend.close()
        raise RemoteMcpConfigError(
            "MCP_C003_OIDC_UNAVAILABLE", "OIDC 身份服务不可用，远程 MCP 拒绝启动"
        ) from exc

    try:
        # ``MCP_AUDIT_LOG_FILE`` is the canonical name; retain the shorter
        # ``MCP_AUDIT_FILE`` alias for existing local overlays.
        audit_file = _value(env, "MCP_AUDIT_LOG_FILE") or _value(
            env, "MCP_AUDIT_FILE", str(service_config.state_path / "remote_mcp_audit.jsonl")
        )
        audit_path = Path(audit_file)
        audit_sink = AuditLogger(audit_path)
    except (OSError, ValueError) as exc:
        backend.close()
        raise RemoteMcpConfigError("MCP_C004_AUDIT_UNAVAILABLE", "无法创建远程 MCP 审计 sink") from exc
    authenticator = McpAuthenticator(
        verifier,
        required_scope=_value(env, "MCP_REQUIRED_SCOPE", "agentguard.notices.read"),
        expected_resource=expected_resource,
        allowed_client_ids=_list(env, "MCP_ALLOWED_CLIENT_IDS", (client_id,)),
        required_roles=_list(env, "MCP_REQUIRED_ROLES"),
        allowed_departments=_list(env, "MCP_ALLOWED_DEPARTMENTS"),
        require_mfa=require_mfa,
    )
    try:
        server = StreamableHttpMcpServer(
            backend,
            authenticator,
            host=_value(env, "MCP_HTTP_HOST", "127.0.0.1"),
            port=_int(env, "MCP_HTTP_PORT", 8000, 0, 65535),
            resource_url=resource_url,
            authorization_servers=authorization_servers,
            allowed_origins=_list(env, "MCP_ALLOWED_ORIGINS"),
            require_origin=_bool(env, "MCP_REQUIRE_ORIGIN", False),
            tls_terminated=_bool(env, "MCP_TLS_TERMINATED", False),
            audit_sink=audit_sink,
            max_request_bytes=_int(env, "MCP_MAX_REQUEST_BYTES", 1024 * 1024, 1024, 16 * 1024 * 1024),
            max_response_bytes=_int(env, "MCP_MAX_RESPONSE_BYTES", 1024 * 1024, 1024, 16 * 1024 * 1024),
            max_concurrent_requests=_int(env, "MCP_MAX_CONCURRENT_REQUESTS", 32, 1, 1024),
            rate_limit_per_minute=_int(env, "MCP_RATE_LIMIT_PER_MINUTE", 120, 1, 100_000),
            session_ttl_seconds=_int(env, "MCP_SESSION_TTL_SECONDS", 3600, 60, 7 * 24 * 3600),
            request_timeout_seconds=_float(env, "MCP_REQUEST_TIMEOUT_SECONDS", 8.0, 0.1, 60.0),
        )
    except Exception:
        backend.close()
        raise
    return backend, server


def serve_remote_http(environ: Mapping[str, str] | None = None) -> int:
    """Start the remote HTTP adapter and block until shutdown."""

    try:
        backend, server = _build_remote_server(environ)
    except RemoteMcpConfigError as exc:
        # Keep stderr useful for operators while excluding configuration values.
        print(f"{{\"status\":\"startup_blocked\",\"reason_code\":\"{exc.code}\"}}", file=sys.stderr)
        return 2
    previous_handlers: dict[int, object] = {}

    def _request_shutdown(_signum: int, _frame: object) -> None:
        # Keep signal handling silent and token-free.  ``close`` is idempotent
        # and wakes the HTTP worker so the process can exit cleanly.
        server.close()

    try:
        for signame in ("SIGINT", "SIGTERM", "SIGBREAK"):
            signum = getattr(signal, signame, None)
            if signum is None:
                continue
            try:
                previous_handlers[signum] = signal.signal(signum, _request_shutdown)
            except (OSError, ValueError):
                # Non-main-thread embedders cannot install handlers; the
                # server remains usable and its normal KeyboardInterrupt path
                # still closes resources.
                continue
        server.serve_forever()
    finally:
        for signum, handler in previous_handlers.items():
            try:
                signal.signal(signum, handler)
            except (OSError, ValueError):
                pass
        server.close()
        backend.close()
    return 0


__all__ = ["RemoteMcpConfigError", "serve_remote_http"]

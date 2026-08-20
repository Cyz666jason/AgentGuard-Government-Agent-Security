"""Configuration and trust-boundary validation for the stdio MCP bridge."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit


ENV_PREFIX = "AGENTGUARD_MCP_"
IDENTITY_MODES = ("oidc", "loopback_static_dev")


class AdapterConfigError(RuntimeError):
    """Unsafe or incomplete adapter configuration; startup must fail closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _is_loopback_literal(hostname: str) -> bool:
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _bounded_float(raw: str, name: str, minimum: float, maximum: float) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise AdapterConfigError("MCP_C002_INVALID_VALUE", f"{name} 必须是数字") from exc
    if value < minimum or value > maximum:
        raise AdapterConfigError(
            "MCP_C002_INVALID_VALUE",
            f"{name} 必须在 {minimum} 到 {maximum} 之间",
        )
    return value


def _bounded_int(raw: str, name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise AdapterConfigError("MCP_C002_INVALID_VALUE", f"{name} 必须是整数") from exc
    if value < minimum or value > maximum:
        raise AdapterConfigError(
            "MCP_C002_INVALID_VALUE",
            f"{name} 必须在 {minimum} 到 {maximum} 之间",
        )
    return value


def _validate_subject(subject: Any) -> dict[str, Any]:
    if not isinstance(subject, dict):
        raise AdapterConfigError("MCP_C008_DEV_IDENTITY_INVALID", "开发身份文件必须是 JSON 对象")
    subject_id = str(subject.get("id", "")).strip()
    department = str(subject.get("department", "")).strip()
    roles = subject.get("roles")
    clearance = subject.get("clearance")
    mfa = subject.get("mfa")
    if not subject_id or not department:
        raise AdapterConfigError(
            "MCP_C008_DEV_IDENTITY_INVALID", "开发身份缺少 id 或 department"
        )
    if not isinstance(roles, list) or not roles or not all(
        isinstance(role, str) and role.strip() for role in roles
    ):
        raise AdapterConfigError(
            "MCP_C008_DEV_IDENTITY_INVALID", "开发身份 roles 必须是非空字符串数组"
        )
    if isinstance(clearance, bool) or not isinstance(clearance, int) or not 0 <= clearance <= 3:
        raise AdapterConfigError(
            "MCP_C008_DEV_IDENTITY_INVALID", "开发身份 clearance 必须是 0 到 3 的整数"
        )
    if not isinstance(mfa, bool):
        raise AdapterConfigError(
            "MCP_C008_DEV_IDENTITY_INVALID", "开发身份 mfa 必须是布尔值"
        )
    return {
        "id": subject_id,
        "type": "user",
        "department": department,
        "roles": sorted({role.strip() for role in roles}),
        "clearance": clearance,
        "mfa": mfa,
        "identity_source": "loopback_operator_configured_test_identity",
    }


@dataclass(frozen=True)
class AdapterConfig:
    """All inputs are operator-side; MCP tool arguments cannot alter them."""

    agentguard_base_url: str
    identity_mode: str = "oidc"
    bearer_token: str = ""
    token_file: str = ""
    dev_subject_file: str = ""
    ca_bundle: str = ""
    timeout_seconds: float = 8.0
    max_response_bytes: int = 1024 * 1024

    @property
    def invoke_url(self) -> str:
        return f"{self.agentguard_base_url.rstrip('/')}/invoke"

    @property
    def is_loopback(self) -> bool:
        hostname = urlsplit(self.agentguard_base_url).hostname or ""
        return _is_loopback_literal(hostname)

    @classmethod
    def from_environment(
        cls, environ: Mapping[str, str] | None = None
    ) -> "AdapterConfig":
        env = os.environ if environ is None else environ
        raw_url = (env.get(f"{ENV_PREFIX}BASE_URL") or "http://127.0.0.1:8080").strip()
        parsed = urlsplit(raw_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise AdapterConfigError(
                "MCP_C001_BASE_URL_INVALID",
                "AgentGuard BASE_URL 必须是无凭据、查询串和路径的 HTTP(S) 根地址",
            )
        hostname = parsed.hostname
        if parsed.scheme == "http" and not _is_loopback_literal(hostname):
            raise AdapterConfigError(
                "MCP_C003_PLAINTEXT_REMOTE_FORBIDDEN",
                "非回环 AgentGuard 地址必须使用 HTTPS",
            )
        try:
            port = parsed.port
        except ValueError as exc:
            raise AdapterConfigError("MCP_C001_BASE_URL_INVALID", "AgentGuard 端口无效") from exc
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None:
            netloc = f"{netloc}:{port}"
        normalized_url = urlunsplit((parsed.scheme, netloc, "", "", ""))

        identity_mode = (env.get(f"{ENV_PREFIX}IDENTITY_MODE") or "oidc").strip().lower()
        if identity_mode not in IDENTITY_MODES:
            raise AdapterConfigError(
                "MCP_C002_INVALID_VALUE",
                f"IDENTITY_MODE 只能是 {', '.join(IDENTITY_MODES)}",
            )
        token = (env.get(f"{ENV_PREFIX}BEARER_TOKEN") or "").strip()
        token_file = (env.get(f"{ENV_PREFIX}TOKEN_FILE") or "").strip()
        dev_subject_file = (env.get(f"{ENV_PREFIX}DEV_SUBJECT_FILE") or "").strip()
        ca_bundle = (env.get(f"{ENV_PREFIX}CA_BUNDLE") or "").strip()

        if identity_mode == "oidc" and not (token or token_file):
            raise AdapterConfigError(
                "MCP_C004_IDENTITY_REQUIRED",
                "OIDC 模式必须通过 TOKEN_FILE（推荐）或 BEARER_TOKEN 提供访问令牌",
            )
        if identity_mode == "loopback_static_dev":
            if not _is_loopback_literal(hostname):
                raise AdapterConfigError(
                    "MCP_C005_DEV_IDENTITY_REMOTE_FORBIDDEN",
                    "静态开发身份只能连接 IP 字面量回环地址",
                )
            if not dev_subject_file:
                raise AdapterConfigError(
                    "MCP_C006_DEV_IDENTITY_FILE_REQUIRED",
                    "静态开发身份必须来自 DEV_SUBJECT_FILE",
                )

        for path_value, label in (
            (token_file, "TOKEN_FILE"),
            (dev_subject_file, "DEV_SUBJECT_FILE"),
            (ca_bundle, "CA_BUNDLE"),
        ):
            if path_value and not Path(path_value).is_file():
                raise AdapterConfigError(
                    "MCP_C007_FILE_MISSING", f"{label} 文件不存在"
                )

        return cls(
            agentguard_base_url=normalized_url,
            identity_mode=identity_mode,
            bearer_token=token,
            token_file=token_file,
            dev_subject_file=dev_subject_file,
            ca_bundle=ca_bundle,
            timeout_seconds=_bounded_float(
                env.get(f"{ENV_PREFIX}TIMEOUT_SECONDS", "8"),
                "TIMEOUT_SECONDS",
                0.1,
                60.0,
            ),
            max_response_bytes=_bounded_int(
                env.get(f"{ENV_PREFIX}MAX_RESPONSE_BYTES", str(1024 * 1024)),
                "MAX_RESPONSE_BYTES",
                1024,
                8 * 1024 * 1024,
            ),
        )

    def authorization_token(self) -> str:
        if self.identity_mode != "oidc":
            return ""
        token = self.bearer_token
        if self.token_file:
            path = Path(self.token_file)
            if path.stat().st_size > 16 * 1024:
                raise AdapterConfigError("MCP_C009_TOKEN_INVALID", "访问令牌文件过大")
            token = path.read_text(encoding="utf-8").strip()
        if not token or any(ord(char) < 33 or ord(char) == 127 for char in token):
            raise AdapterConfigError("MCP_C009_TOKEN_INVALID", "访问令牌为空或包含非法字符")
        return token

    def request_subject(self) -> dict[str, Any]:
        if self.identity_mode == "oidc":
            # AgentGuard's verified OIDC layer replaces this entire object before OPA.
            # An intentionally powerless placeholder keeps the action schema complete
            # and fails closed if a gateway is accidentally started without OIDC.
            return {
                "id": "unverified-mcp-placeholder",
                "type": "service_account",
                "department": "unverified",
                "roles": ["untrusted_mcp_placeholder"],
                "clearance": 0,
                "mfa": False,
                "identity_source": "must_be_overwritten_by_agentguard_oidc",
            }
        path = Path(self.dev_subject_file)
        if path.stat().st_size > 16 * 1024:
            raise AdapterConfigError("MCP_C008_DEV_IDENTITY_INVALID", "开发身份文件过大")
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AdapterConfigError(
                "MCP_C008_DEV_IDENTITY_INVALID", "无法读取合法的开发身份 JSON"
            ) from exc
        return _validate_subject(payload)

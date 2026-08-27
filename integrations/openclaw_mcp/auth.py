"""Authentication helpers for the remote OpenClaw MCP endpoint.

The stdio adapter receives an operator supplied token.  A remote MCP endpoint
must instead authenticate every HTTP request and derive the AgentGuard subject
from the verified token.  This module deliberately contains no business logic
and never returns the raw access token to callers after verification.

``OidcVerifier`` remains the single JWT signature/JWKS implementation used by
the project.  :class:`McpAuthenticator` adds the MCP resource-server checks
that are specific to a remote endpoint: scopes, resource/audience, client
identity, and a stable principal suitable for session binding and audit.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from math import isfinite
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from identity import OidcIdentityError, OidcVerifier


class McpAuthenticationError(RuntimeError):
    """An authentication or authorization failure safe to expose over HTTP."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 401,
        challenge: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.challenge = challenge


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Verified identity and non-secret request metadata.

    ``claims`` is retained for policy adapters that need an additional claim,
    but the raw access token is intentionally not retained anywhere.
    """

    subject: dict[str, Any]
    claims: dict[str, Any]
    session_id: str
    client_id: str
    scopes: frozenset[str]

    @property
    def subject_id(self) -> str:
        return str(self.subject.get("id", ""))


def _claim_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {part for part in value.split() if part}
    if isinstance(value, (list, tuple, set)):
        return {str(part).strip() for part in value if str(part).strip()}
    return set()


def _safe_session_id(value: str | None) -> str:
    if value:
        candidate = value.strip()
        # MCP session IDs are opaque.  Keep the accepted alphabet narrow so a
        # caller cannot inject headers, paths, or unbounded log data.
        if 8 <= len(candidate) <= 256 and all(
            ord(char) < 128 and (char.isalnum() or char in "._~-") for char in candidate
        ):
            return candidate
    return uuid.uuid4().hex


def validate_https_endpoint(value: str, *, name: str, require_mcp_path: bool = False) -> str:
    """Validate an externally configured OIDC/resource URL before startup.

    The remote adapter is intended to be reached through HTTPS.  Accepting an
    ``http://`` issuer or resource URL would make a deployment vulnerable to
    downgrade or token disclosure, so these values are rejected even when a
    reverse proxy is configured.  Query strings, fragments and credentials
    are not valid for either endpoint and are rejected as well.
    """

    candidate = str(value or "").strip().rstrip("/")
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"{name} 必须使用 HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{name} URL 不得包含凭据、查询参数或片段")
    if require_mcp_path and parsed.path != "/mcp":
        raise ValueError(f"{name} 必须是完整的 /mcp 资源 URL")
    # Accessing .port detects malformed values such as ``:not-a-port``.
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} URL 端口无效") from exc
    return candidate


class McpAuthenticator:
    """Validate a bearer token and produce a verified MCP principal.

    ``verifier`` performs signed JWT verification.  Tests may inject a small
    verifier double implementing ``verify_token`` and ``subject_from_claims``;
    no network or token fixture is required for unit testing the HTTP layer.
    """

    def __init__(
        self,
        verifier: OidcVerifier,
        *,
        required_scope: str = "agentguard.notices.read",
        expected_resource: str | None = None,
        allowed_client_ids: Iterable[str] | None = None,
        required_roles: Iterable[str] = (),
        allowed_departments: Iterable[str] = (),
        require_mfa: bool = True,
        clock: Any = time.time,
        clock_skew_seconds: int = 30,
    ) -> None:
        self.verifier = verifier
        self.required_scope = required_scope.strip()
        if not self.required_scope:
            raise ValueError("required_scope cannot be empty")
        self.expected_resource = (
            validate_https_endpoint(
                expected_resource,
                name="expected_resource",
                require_mcp_path=True,
            )
            if expected_resource
            else None
        )
        configured_clients = {
            str(item).strip() for item in (allowed_client_ids or ()) if str(item).strip()
        }
        if not configured_clients:
            configured_client = str(getattr(verifier, "client_id", "")).strip()
            if configured_client:
                configured_clients = {configured_client}
        self.allowed_client_ids = frozenset(configured_clients)
        self.required_roles = frozenset(
            str(item).strip() for item in required_roles if str(item).strip()
        )
        self.allowed_departments = frozenset(
            str(item).strip() for item in allowed_departments if str(item).strip()
        )
        self.require_mfa = bool(require_mfa)
        self.clock = clock
        self.clock_skew_seconds = max(0, int(clock_skew_seconds))

    @staticmethod
    def _bearer_token(authorization_header: str | None) -> str:
        if not authorization_header:
            raise McpAuthenticationError(
                "MCP_A_TOKEN_MISSING",
                "需要 Bearer 访问令牌",
                challenge='Bearer error="invalid_token"',
            )
        scheme, separator, token = authorization_header.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token.strip():
            raise McpAuthenticationError(
                "MCP_A_TOKEN_INVALID",
                "Authorization 必须使用 Bearer 令牌",
                challenge='Bearer error="invalid_token"',
            )
        token = token.strip()
        if any(ord(char) < 33 or ord(char) == 127 for char in token):
            raise McpAuthenticationError(
                "MCP_A_TOKEN_INVALID",
                "访问令牌格式无效",
                challenge='Bearer error="invalid_token"',
            )
        return token

    def authenticate(
        self,
        authorization_header: str | None,
        *,
        session_id: str | None = None,
    ) -> AuthenticatedPrincipal:
        """Authenticate one HTTP request without retaining its raw token."""

        token = self._bearer_token(authorization_header)
        try:
            claims = dict(self.verifier.verify_token(token))
        except OidcIdentityError as exc:
            # Preserve the stable project reason code, never the token or JWT
            # parser's detailed exception text.
            raise McpAuthenticationError(
                exc.code,
                "访问令牌无效或已过期",
                challenge='Bearer error="invalid_token"',
            ) from exc
        except Exception as exc:  # fail closed for verifier implementations
            raise McpAuthenticationError(
                "MCP_A_TOKEN_INVALID",
                "访问令牌无效或已过期",
                challenge='Bearer error="invalid_token"',
            ) from exc

        self._validate_registered_claims(claims)
        try:
            subject = dict(self.verifier.subject_from_claims(claims))
        except OidcIdentityError as exc:
            raise McpAuthenticationError(exc.code, "访问令牌身份声明无效") from exc
        except Exception as exc:
            raise McpAuthenticationError("MCP_A_SUBJECT_INVALID", "访问令牌身份声明无效") from exc

        subject_id = str(subject.get("id", "")).strip()
        if not subject_id or subject_id != str(claims.get("sub", "")).strip():
            raise McpAuthenticationError("MCP_A_SUBJECT_INVALID", "访问令牌缺少有效 subject")
        roles = _claim_values(subject.get("roles"))
        if not roles:
            raise McpAuthenticationError("MCP_A_ROLES_MISSING", "访问令牌缺少角色")
        department = str(subject.get("department", "")).strip()
        if not department:
            raise McpAuthenticationError("MCP_A_DEPARTMENT_MISSING", "访问令牌缺少部门")
        if self.require_mfa and subject.get("mfa") is not True:
            raise McpAuthenticationError("MCP_A_MFA_REQUIRED", "访问令牌未证明已完成 MFA")

        if self.required_roles and not self.required_roles.intersection(roles):
            raise McpAuthenticationError(
                "MCP_A_ROLE_FORBIDDEN", "当前身份没有访问该 MCP 资源的角色", status_code=403
            )
        if self.allowed_departments and department not in self.allowed_departments:
            raise McpAuthenticationError(
                "MCP_A_DEPARTMENT_FORBIDDEN", "当前身份没有访问该 MCP 资源的部门权限", status_code=403
            )

        scopes = _claim_values(claims.get("scope"))
        if self.required_scope not in scopes:
            raise McpAuthenticationError(
                "MCP_A_SCOPE_FORBIDDEN",
                "访问令牌缺少所需 scope",
                status_code=403,
            )

        client_id = self._client_id(claims)
        if self.allowed_client_ids and client_id not in self.allowed_client_ids:
            raise McpAuthenticationError(
                "MCP_A_CLIENT_FORBIDDEN",
                "访问令牌 client_id 不被该 MCP 资源接受",
                status_code=403,
            )

        return AuthenticatedPrincipal(
            subject=subject,
            claims=claims,
            session_id=_safe_session_id(session_id),
            client_id=client_id,
            scopes=frozenset(scopes),
        )

    def _validate_registered_claims(self, claims: Mapping[str, Any]) -> None:
        issuer = str(getattr(self.verifier, "issuer", "")).rstrip("/")
        if issuer and str(claims.get("iss", "")).rstrip("/") != issuer:
            raise McpAuthenticationError("MCP_A_ISSUER_INVALID", "访问令牌 issuer 不匹配")
        subject = str(claims.get("sub", "")).strip()
        if not subject:
            raise McpAuthenticationError("MCP_A_SUBJECT_INVALID", "访问令牌缺少 subject")

        expected_audience = str(getattr(self.verifier, "audience", "")).strip()
        audiences = _claim_values(claims.get("aud"))
        if expected_audience and expected_audience not in audiences:
            raise McpAuthenticationError("MCP_A_AUDIENCE_INVALID", "访问令牌 audience 不匹配")
        if self.expected_resource:
            resources = _claim_values(claims.get("resource"))
            if resources and self.expected_resource not in resources:
                raise McpAuthenticationError("MCP_A_RESOURCE_INVALID", "访问令牌 resource 不匹配")
            if not resources and self.expected_resource not in audiences:
                raise McpAuthenticationError("MCP_A_RESOURCE_INVALID", "访问令牌未授权该 MCP resource")

        now = float(self.clock())
        exp = claims.get("exp")
        if (
            isinstance(exp, bool)
            or not isinstance(exp, (int, float))
            or not isfinite(float(exp))
            or float(exp) <= now - self.clock_skew_seconds
        ):
            raise McpAuthenticationError("MCP_A_TOKEN_EXPIRED", "访问令牌已过期")
        iat = claims.get("iat")
        if (
            isinstance(iat, bool)
            or not isinstance(iat, (int, float))
            or not isfinite(float(iat))
            or float(iat) > now + self.clock_skew_seconds
        ):
            raise McpAuthenticationError("MCP_A_TOKEN_INVALID", "访问令牌签发时间无效")

    @staticmethod
    def _client_id(claims: Mapping[str, Any]) -> str:
        azp = str(claims.get("azp", "")).strip()
        client = str(claims.get("client_id", "")).strip()
        if azp and client and azp != client:
            raise McpAuthenticationError("MCP_A_CLIENT_INVALID", "访问令牌 azp 与 client_id 冲突")
        selected = azp or client
        if not selected:
            raise McpAuthenticationError("MCP_A_CLIENT_MISSING", "访问令牌缺少 azp/client_id")
        return selected

    def readiness(self) -> tuple[bool, str]:
        """Return a token-free live readiness result for the configured IdP."""

        probe = getattr(self.verifier, "readiness", None)
        if not callable(probe):
            # Lightweight verifier doubles used by local tests do not need a
            # network probe; the signed-token boundary remains enforced by
            # ``authenticate`` for every request.
            return True, "verifier=embedded"
        try:
            detail = probe()
        except Exception as exc:
            return False, type(exc).__name__
        return True, str(detail or "verifier=ok")


def protected_resource_metadata(
    resource: str,
    authorization_servers: Iterable[str],
    *,
    scopes_supported: Iterable[str] = ("agentguard.notices.read",),
) -> dict[str, Any]:
    """Return RFC 9728 Protected Resource Metadata without secrets."""

    return {
        "resource": resource,
        "authorization_servers": [str(item).rstrip("/") for item in authorization_servers if str(item).strip()],
        "scopes_supported": sorted({str(item).strip() for item in scopes_supported if str(item).strip()}),
        "bearer_methods_supported": ["header"],
    }


__all__ = [
    "AuthenticatedPrincipal",
    "McpAuthenticationError",
    "McpAuthenticator",
    "protected_resource_metadata",
    "validate_https_endpoint",
]

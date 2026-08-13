"""验证 OIDC JWT，并把经过签名的声明映射为 OPA subject。"""

from __future__ import annotations

import copy
import json
import urllib.request
from typing import Any, Mapping

import jwt


class OidcIdentityError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OidcVerifier:
    """严格校验签名、issuer、audience、时效和必要身份声明。"""

    def __init__(
        self,
        issuer: str,
        audience: str,
        client_id: str = "agentguard",
        require_mfa: bool = True,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.client_id = client_id
        self.require_mfa = require_mfa
        self.timeout_seconds = timeout_seconds
        discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        try:
            with urllib.request.urlopen(discovery_url, timeout=timeout_seconds) as response:
                discovery = json.load(response)
        except Exception as exc:
            raise OidcIdentityError("I001_DISCOVERY_FAILED", "无法读取 OIDC discovery") from exc
        if discovery.get("issuer") != self.issuer:
            raise OidcIdentityError("I002_ISSUER_MISMATCH", "discovery issuer 不匹配")
        jwks_uri = str(discovery.get("jwks_uri", ""))
        if not jwks_uri:
            raise OidcIdentityError("I003_JWKS_MISSING", "discovery 缺少 jwks_uri")
        self.jwk_client = jwt.PyJWKClient(jwks_uri, timeout=timeout_seconds)

    def verify_token(self, token: str) -> dict[str, Any]:
        if not token:
            raise OidcIdentityError("I004_TOKEN_MISSING", "缺少访问令牌")
        try:
            signing_key = self.jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "PS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise OidcIdentityError("I005_TOKEN_EXPIRED", "访问令牌已过期") from exc
        except jwt.InvalidAudienceError as exc:
            raise OidcIdentityError("I006_AUDIENCE_INVALID", "访问令牌 audience 不匹配") from exc
        except jwt.InvalidIssuerError as exc:
            raise OidcIdentityError("I007_ISSUER_INVALID", "访问令牌 issuer 不匹配") from exc
        except Exception as exc:
            raise OidcIdentityError("I008_TOKEN_INVALID", "访问令牌签名或声明无效") from exc
        return dict(claims)

    def subject_from_claims(self, claims: Mapping[str, Any]) -> dict[str, Any]:
        realm_roles = claims.get("realm_access", {}).get("roles", [])
        client_roles = claims.get("resource_access", {}).get(self.client_id, {}).get("roles", [])
        roles = sorted({str(role) for role in [*realm_roles, *client_roles]})
        if not roles:
            raise OidcIdentityError("I009_ROLES_MISSING", "令牌中没有可用角色")
        try:
            clearance = int(claims.get("clearance", -1))
        except (TypeError, ValueError) as exc:
            raise OidcIdentityError("I010_CLEARANCE_INVALID", "令牌密级声明无效") from exc
        if clearance < 0 or clearance > 3:
            raise OidcIdentityError("I010_CLEARANCE_INVALID", "令牌密级必须在 0 到 3 之间")
        department = str(claims.get("department", "")).strip()
        if not department:
            raise OidcIdentityError("I011_DEPARTMENT_MISSING", "令牌缺少部门声明")
        amr = claims.get("amr", [])
        mfa = claims.get("mfa") is True or "mfa" in amr or "otp" in amr
        if self.require_mfa and not mfa:
            raise OidcIdentityError("I012_MFA_REQUIRED", "令牌未证明已完成 MFA")
        return {
            "id": str(claims["sub"]),
            "username": str(claims.get("preferred_username", "")),
            "type": "user",
            "department": department,
            "roles": roles,
            "clearance": clearance,
            "mfa": mfa,
            "identity_source": "oidc_verified_jwt",
        }

    def authenticate_request(
        self, request: Mapping[str, Any], authorization_header: str | None
    ) -> dict[str, Any]:
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise OidcIdentityError("I004_TOKEN_MISSING", "缺少 Bearer 访问令牌")
        token = authorization_header.removeprefix("Bearer ").strip()
        claims = self.verify_token(token)
        authenticated = copy.deepcopy(dict(request))
        authenticated["subject"] = self.subject_from_claims(claims)
        return authenticated

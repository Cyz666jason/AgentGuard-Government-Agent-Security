"""验证 OIDC JWT，并把经过签名的声明映射为 OPA subject。"""

from __future__ import annotations

import copy
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping

import jwt


class OidcIdentityError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail closed instead of following an IdP discovery/JWKS redirect."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise OidcIdentityError("I017_REDIRECT_REJECTED", "OIDC endpoint 不允许重定向")


class _StrictPyJWKClient(jwt.PyJWKClient):
    """PyJWT JWKS client that never follows an HTTP redirect.

    ``PyJWKClient`` uses :func:`urllib.request.urlopen` directly.  That helper
    follows 30x responses by default, so merely rejecting redirects for the
    discovery document would leave the subsequent JWKS fetch vulnerable to a
    downgrade or host-change redirect.  Keep PyJWT's cache/error contract but
    install the same redirect handler used for discovery.
    """

    def fetch_data(self) -> Any:
        jwk_set: Any = None
        try:
            request = urllib.request.Request(url=self.uri, headers=self.headers)
            handlers: list[Any] = [_RejectRedirectHandler()]
            if self.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(request, timeout=self.timeout) as response:
                jwk_set = json.load(response)
        except OidcIdentityError as exc:
            # Do not expose the redirect target or any response details to the
            # token verifier; callers only need a stable connection failure.
            raise jwt.PyJWKClientConnectionError(
                "Fail to fetch JWKS: redirect rejected"
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise jwt.PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{exc}"'
            ) from exc
        finally:
            if self.jwk_set_cache is not None:
                self.jwk_set_cache.put(jwk_set)
        return jwk_set


def _https_url(value: str, *, name: str) -> str:
    """Validate a strict HTTPS URL without credentials or request adornments."""

    candidate = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise OidcIdentityError("I018_HTTPS_REQUIRED", f"{name} 必须使用 HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OidcIdentityError("I018_HTTPS_REQUIRED", f"{name} URL 格式无效")
    try:
        parsed.port
    except ValueError as exc:
        raise OidcIdentityError("I018_HTTPS_REQUIRED", f"{name} URL 端口无效") from exc
    return candidate


class OidcVerifier:
    """严格校验签名、issuer、audience、时效和必要身份声明。"""

    def __init__(
        self,
        issuer: str,
        audience: str,
        client_id: str = "agentguard",
        require_mfa: bool = True,
        timeout_seconds: float = 5.0,
        required_scope: str | None = None,
        expected_resource: str | None = None,
        require_client_binding: bool = False,
        require_https: bool = False,
        reject_redirects: bool = False,
    ) -> None:
        self.require_https = bool(require_https)
        self.reject_redirects = bool(reject_redirects)
        self.issuer = (
            _https_url(issuer, name="OIDC issuer")
            if self.require_https
            else issuer.rstrip("/")
        )
        self.audience = audience
        self.client_id = client_id
        self.require_mfa = require_mfa
        self.timeout_seconds = timeout_seconds
        self.required_scope = required_scope.strip() if required_scope else None
        self.expected_resource = expected_resource.rstrip("/") if expected_resource else None
        self.require_client_binding = bool(require_client_binding)
        discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        self.discovery_url = discovery_url
        try:
            discovery = self._read_json(discovery_url)
        except OidcIdentityError:
            raise
        except Exception as exc:
            raise OidcIdentityError("I001_DISCOVERY_FAILED", "无法读取 OIDC discovery") from exc
        if discovery.get("issuer") != self.issuer:
            raise OidcIdentityError("I002_ISSUER_MISMATCH", "discovery issuer 不匹配")
        jwks_uri = str(discovery.get("jwks_uri", ""))
        if not jwks_uri:
            raise OidcIdentityError("I003_JWKS_MISSING", "discovery 缺少 jwks_uri")
        if self.require_https:
            jwks_uri = _https_url(jwks_uri, name="OIDC JWKS")
        self.jwks_uri = jwks_uri
        jwk_client_cls = _StrictPyJWKClient if self.reject_redirects else jwt.PyJWKClient
        self.jwk_client = jwk_client_cls(jwks_uri, timeout=timeout_seconds)

    def _read_json(self, url: str) -> Any:
        """Fetch OIDC metadata without silently following a redirect."""

        if self.reject_redirects:
            opener = urllib.request.build_opener(_RejectRedirectHandler())
            response = opener.open(url, timeout=self.timeout_seconds)
        else:
            response = urllib.request.urlopen(url, timeout=self.timeout_seconds)
        with response:
            if getattr(response, "status", 200) != 200:
                raise OidcIdentityError("I001_DISCOVERY_FAILED", "OIDC endpoint 不可用")
            return json.load(response)

    def readiness(self) -> str:
        """Perform a bounded live discovery/JWKS check for ``/readyz``.

        Construction validates discovery once, but an IdP can become
        unavailable afterwards or rotate its endpoint.  The remote MCP
        adapter calls this method as a required dependency probe and fails
        closed when either endpoint cannot be reached or no key set is
        returned.  No token or response body is included in the error.
        """

        try:
            discovery = self._read_json(self.discovery_url)
            if str(discovery.get("issuer", "")).rstrip("/") != self.issuer:
                raise OidcIdentityError("I002_ISSUER_MISMATCH", "OIDC discovery issuer 不匹配")
            jwks_uri = str(discovery.get("jwks_uri", ""))
            if not jwks_uri or jwks_uri != self.jwks_uri:
                raise OidcIdentityError("I003_JWKS_MISSING", "OIDC discovery jwks_uri 不匹配")
            jwks = self._read_json(jwks_uri)
            if not isinstance(jwks, Mapping) or not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
                raise OidcIdentityError("I003_JWKS_MISSING", "OIDC JWKS 没有可用密钥")
        except OidcIdentityError:
            raise
        except Exception as exc:
            raise OidcIdentityError("I001_DISCOVERY_FAILED", "OIDC discovery/JWKS 不可用") from exc
        return "discovery=ok；jwks=ok"

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
        verified = dict(claims)
        self._validate_remote_claims(verified)
        return verified

    @staticmethod
    def _claim_values(value: Any) -> set[str]:
        """Normalize OAuth claims that may be a space string or JSON array."""

        if isinstance(value, str):
            return {part for part in value.split() if part}
        if isinstance(value, (list, tuple, set)):
            return {str(part).strip() for part in value if str(part).strip()}
        return set()

    def _validate_remote_claims(self, claims: Mapping[str, Any]) -> None:
        """Validate resource-server claims after JWT signature verification.

        PyJWT validates ``iss``, ``aud`` and ``exp`` above.  The checks here cover
        claims that PyJWT intentionally treats as application policy: OAuth scope,
        RFC 8707 resource, and the authorized client binding.  They are optional
        for the legacy gateway verifier and enabled by the remote MCP adapter.
        """

        if self.required_scope:
            scopes = self._claim_values(claims.get("scope"))
            if self.required_scope not in scopes:
                raise OidcIdentityError("I013_SCOPE_MISSING", "访问令牌缺少所需 scope")

        if self.expected_resource:
            audiences = self._claim_values(claims.get("aud"))
            resources = self._claim_values(claims.get("resource"))
            if resources:
                if self.expected_resource not in resources:
                    raise OidcIdentityError("I014_RESOURCE_INVALID", "访问令牌 resource 不匹配")
            elif self.expected_resource not in audiences:
                raise OidcIdentityError("I014_RESOURCE_INVALID", "访问令牌未授权该 resource")

        azp = str(claims.get("azp", "")).strip()
        client_id = str(claims.get("client_id", "")).strip()
        if azp and client_id and azp != client_id:
            raise OidcIdentityError("I015_CLIENT_BINDING_INVALID", "访问令牌 azp 与 client_id 冲突")
        if self.require_client_binding and not (azp or client_id):
            raise OidcIdentityError("I016_CLIENT_BINDING_MISSING", "访问令牌缺少 azp/client_id")

    def subject_from_claims(self, claims: Mapping[str, Any]) -> dict[str, Any]:
        realm_access = claims.get("realm_access", {})
        resource_access = claims.get("resource_access", {})
        realm_roles = realm_access.get("roles", []) if isinstance(realm_access, Mapping) else []
        client_entry = (
            resource_access.get(self.client_id, {})
            if isinstance(resource_access, Mapping)
            else {}
        )
        client_roles = client_entry.get("roles", []) if isinstance(client_entry, Mapping) else []
        roles = sorted({str(role).strip() for role in [*realm_roles, *client_roles] if str(role).strip()})
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
        amr = self._claim_values(claims.get("amr"))
        mfa = claims.get("mfa") is True or bool({"mfa", "otp"}.intersection(amr))
        if self.require_mfa and not mfa:
            raise OidcIdentityError("I012_MFA_REQUIRED", "令牌未证明已完成 MFA")
        subject = {
            "id": str(claims["sub"]),
            "username": str(claims.get("preferred_username", "")),
            "type": "user",
            "department": department,
            "roles": roles,
            "clearance": clearance,
            "mfa": mfa,
            "identity_source": "oidc_verified_jwt",
        }
        # Keep tenant context only when the IdP asserted it.  Never derive it
        # from prompt text or an untrusted request field.
        tenant_id = str(claims.get("tenant_id", claims.get("tenant", ""))).strip()
        if tenant_id:
            subject["tenant_id"] = tenant_id
        return subject

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

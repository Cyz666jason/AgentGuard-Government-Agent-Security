"""Trusted approver identity adapters."""

from __future__ import annotations

from typing import Any, Mapping

from .oidc import OidcIdentityError, OidcVerifier


class OidcApproverAuthenticator:
    """Derive approver identity only from a verified OIDC access token."""

    def __init__(self, verifier: OidcVerifier) -> None:
        self.verifier = verifier

    def __call__(self, review: Mapping[str, Any]) -> dict[str, Any]:
        authorization = str(review.get("authorization", ""))
        if not authorization.startswith("Bearer "):
            raise OidcIdentityError("I004_TOKEN_MISSING", "审批操作缺少审批人访问令牌")
        token = authorization.removeprefix("Bearer ").strip()
        claims = self.verifier.verify_token(token)
        subject = self.verifier.subject_from_claims(claims)
        return {
            "id": subject["id"],
            "roles": subject["roles"],
            "identity_source": subject["identity_source"],
        }

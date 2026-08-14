"""OIDC 身份验证与可信声明映射。"""

from .oidc import OidcIdentityError, OidcVerifier
from .approver import OidcApproverAuthenticator

__all__ = ["OidcApproverAuthenticator", "OidcIdentityError", "OidcVerifier"]

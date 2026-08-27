from __future__ import annotations

import unittest
from unittest.mock import patch

import jwt
from identity import OidcIdentityError, OidcVerifier
from identity.run_keycloak_e2e import tamper_jwt_signature
from identity.oidc import _RejectRedirectHandler, _StrictPyJWKClient


class OidcClaimMappingTests(unittest.TestCase):
    def verifier(self, require_mfa: bool = True) -> OidcVerifier:
        verifier = object.__new__(OidcVerifier)
        verifier.client_id = "agentguard"
        verifier.require_mfa = require_mfa
        return verifier

    @staticmethod
    def claims() -> dict:
        return {
            "sub": "signed-user-001",
            "preferred_username": "office-test",
            "department": "综合办公室",
            "clearance": 1,
            "mfa": True,
            "realm_access": {"roles": ["office_user"]},
            "resource_access": {"agentguard": {"roles": ["records_admin"]}},
        }

    def test_signed_claims_map_to_subject(self) -> None:
        subject = self.verifier().subject_from_claims(self.claims())
        self.assertEqual("signed-user-001", subject["id"])
        self.assertEqual(["office_user", "records_admin"], subject["roles"])
        self.assertEqual("oidc_verified_jwt", subject["identity_source"])

    def test_missing_mfa_is_rejected(self) -> None:
        claims = self.claims()
        claims["mfa"] = False
        with self.assertRaisesRegex(OidcIdentityError, "MFA"):
            self.verifier().subject_from_claims(claims)

    def test_invalid_clearance_is_rejected(self) -> None:
        claims = self.claims()
        claims["clearance"] = 99
        with self.assertRaises(OidcIdentityError) as raised:
            self.verifier().subject_from_claims(claims)
        self.assertEqual("I010_CLEARANCE_INVALID", raised.exception.code)

    def test_request_json_subject_is_overwritten(self) -> None:
        verifier = self.verifier()
        verifier.verify_token = lambda token: self.claims()
        authenticated = verifier.authenticate_request(
            {"subject": {"id": "forged", "roles": ["security_admin"]}},
            "Bearer signed-token",
        )
        self.assertEqual("signed-user-001", authenticated["subject"]["id"])
        self.assertNotIn("security_admin", authenticated["subject"]["roles"])

    def test_signature_tamper_changes_decoded_bytes(self) -> None:
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.AA"
        tampered = tamper_jwt_signature(token)
        self.assertNotEqual(token, tampered)
        self.assertNotEqual(token.rsplit(".", 1)[1], tampered.rsplit(".", 1)[1])

    def test_jwks_fetch_rejects_redirects(self) -> None:
        """The strict PyJWT client must not follow a JWKS 30x response."""

        captured: dict[str, tuple[object, ...]] = {}

        def fake_build_opener(*handlers: object) -> object:
            captured["handlers"] = tuple(handlers)

            class RedirectingOpener:
                def open(self, request: object, *, timeout: float) -> object:
                    redirect_handler = next(
                        handler
                        for handler in handlers
                        if isinstance(handler, _RejectRedirectHandler)
                    )
                    # The custom handler raises before an attacker-controlled
                    # Location can be opened.
                    redirect_handler.redirect_request(
                        request,
                        None,
                        302,
                        "Found",
                        {"Location": "https://attacker.invalid/jwks"},
                        "https://attacker.invalid/jwks",
                    )
                    raise AssertionError("redirect handler did not fail closed")

            return RedirectingOpener()

        with patch("identity.oidc.urllib.request.build_opener", side_effect=fake_build_opener):
            client = _StrictPyJWKClient("https://issuer.example/jwks", timeout=1)
            with self.assertRaises(jwt.PyJWKClientConnectionError):
                client.fetch_data()

        self.assertTrue(
            any(isinstance(handler, _RejectRedirectHandler) for handler in captured["handlers"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

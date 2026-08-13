from __future__ import annotations

import unittest

from identity import OidcIdentityError, OidcVerifier
from identity.run_keycloak_e2e import tamper_jwt_signature


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


if __name__ == "__main__":
    unittest.main(verbosity=2)

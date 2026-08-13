from __future__ import annotations

import unittest

from enforcement.signers import HmacKeyringSigner


class HmacKeyringSignerTests(unittest.TestCase):
    def test_active_key_signs_and_old_key_still_verifies_after_rotation(self) -> None:
        old = HmacKeyringSigner({"v1": b"1" * 32}, "v1")
        old_signature = old.sign(b"action")
        rotated = HmacKeyringSigner(
            {"v1": b"1" * 32, "v2": b"2" * 32}, "v2"
        )
        self.assertTrue(rotated.verify(b"action", old_signature))
        self.assertTrue(rotated.verify(b"action", rotated.sign(b"action")))

    def test_unknown_key_version_fails_closed(self) -> None:
        signer = HmacKeyringSigner({"v2": b"2" * 32}, "v2")
        self.assertFalse(signer.verify(b"action", "v1:invalid"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

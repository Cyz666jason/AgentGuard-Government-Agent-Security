"""服务配置测试：机密不入文件、缺机密不启动、来源优先级正确。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from service.config import (
    ConfigError,
    load_config,
    load_config_file,
    resolve_ticket_secret,
)


SECRET_HEX = "ab" * 32


class ConfigFileSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _write(self, payload: dict) -> Path:
        path = self.root / "service.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def test_config_file_rejects_secret_like_keys(self) -> None:
        for key in (
            "ticket_secret_hex",
            "openbao_token",
            "api_key",
            "db_password",
            "signing_private_key",
            "redaction_salt_hex",
        ):
            path = self._write({key: "whatever"})
            with self.assertRaises(ConfigError) as caught:
                load_config_file(path)
            self.assertEqual(caught.exception.code, "C001_SECRET_IN_CONFIG_FILE")

    def test_config_file_rejects_nested_secret_keys(self) -> None:
        path = self._write({"outer": {"inner": {"access_token": "x"}}})
        with self.assertRaises(ConfigError) as caught:
            load_config_file(path)
        self.assertEqual(caught.exception.code, "C001_SECRET_IN_CONFIG_FILE")

    def test_config_file_accepts_non_secret_settings(self) -> None:
        path = self._write({"port": 9100, "opa_mode": "cli"})
        payload = load_config_file(path)
        self.assertEqual(payload["port"], 9100)

    def test_missing_config_file_is_reported(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config_file(self.root / "absent.json")
        self.assertEqual(caught.exception.code, "C002_CONFIG_FILE_MISSING")

    def test_invalid_json_is_reported(self) -> None:
        path = self.root / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ConfigError) as caught:
            load_config_file(path)
        self.assertEqual(caught.exception.code, "C003_CONFIG_FILE_INVALID")

    def test_unknown_config_key_is_rejected(self) -> None:
        path = self._write({"totally_unknown": 1})
        with self.assertRaises(ConfigError) as caught:
            load_config(environ={}, config_file=path)
        self.assertEqual(caught.exception.code, "C007_UNKNOWN_CONFIG_KEY")

    def test_environment_overrides_config_file(self) -> None:
        path = self._write({"port": 9100})
        config = load_config(
            environ={
                "AGENTGUARD_SERVICE_PORT": "9200",
                "AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX,
            },
            config_file=path,
        )
        self.assertEqual(config.port, 9200)


class FailClosedStartupTests(unittest.TestCase):
    def test_missing_ticket_secret_refuses_to_start(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(environ={})
        self.assertEqual(caught.exception.code, "C008_TICKET_SECRET_REQUIRED")

    def test_short_ticket_secret_is_rejected(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(environ={"AGENTGUARD_TICKET_SECRET_HEX": "ab" * 8})
        self.assertEqual(caught.exception.code, "C005_TICKET_SECRET_INVALID")

    def test_non_hex_ticket_secret_is_rejected(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(environ={"AGENTGUARD_TICKET_SECRET_HEX": "zz" * 32})
        self.assertEqual(caught.exception.code, "C005_TICKET_SECRET_INVALID")

    def test_openbao_mode_requires_address_and_token(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(environ={"AGENTGUARD_SIGNER_MODE": "openbao_transit"})
        self.assertEqual(caught.exception.code, "C009_OPENBAO_ADDRESS_REQUIRED")

        with self.assertRaises(ConfigError) as caught:
            load_config(
                environ={
                    "AGENTGUARD_SIGNER_MODE": "openbao_transit",
                    "AGENTGUARD_OPENBAO_ADDR": "http://127.0.0.1:8200",
                }
            )
        self.assertEqual(caught.exception.code, "C010_OPENBAO_TOKEN_REQUIRED")

    def test_oidc_enabled_requires_issuer(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(
                environ={
                    "AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX,
                    "AGENTGUARD_OIDC_ENABLED": "true",
                }
            )
        self.assertEqual(caught.exception.code, "C011_OIDC_ISSUER_REQUIRED")

    def test_invalid_opa_mode_is_rejected(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(
                environ={
                    "AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX,
                    "AGENTGUARD_OPA_MODE": "grpc",
                }
            )
        self.assertEqual(caught.exception.code, "C004_INVALID_VALUE")

    def test_out_of_range_port_is_rejected(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_config(
                environ={
                    "AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX,
                    "AGENTGUARD_SERVICE_PORT": "70000",
                }
            )
        self.assertEqual(caught.exception.code, "C004_INVALID_VALUE")


class SecretSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_environment_variable_source_is_recorded(self) -> None:
        secret, source = resolve_ticket_secret({"AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX})
        self.assertEqual(len(secret or b""), 32)
        self.assertEqual(source, "environment_variable")

    def test_external_file_source_is_recorded(self) -> None:
        path = self.root / "ticket.key"
        path.write_text(SECRET_HEX, encoding="utf-8")
        secret, source = resolve_ticket_secret(
            {"AGENTGUARD_TICKET_SECRET_FILE": str(path)}
        )
        self.assertEqual(len(secret or b""), 32)
        self.assertEqual(source, "external_file")

    def test_missing_secret_file_is_reported(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            resolve_ticket_secret(
                {"AGENTGUARD_TICKET_SECRET_FILE": str(self.root / "absent.key")}
            )
        self.assertEqual(caught.exception.code, "C006_TICKET_SECRET_FILE_MISSING")

    def test_redacted_config_contains_no_secret_values(self) -> None:
        config = load_config(environ={"AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX})
        redacted = json.dumps(config.redacted(), ensure_ascii=False)
        self.assertNotIn(SECRET_HEX, redacted)
        self.assertFalse(config.redacted()["contains_secret_values"])
        self.assertEqual(config.ticket_secret_source, "environment_variable")

    def test_cli_mode_is_marked_not_performance_representative(self) -> None:
        config = load_config(
            environ={
                "AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX,
                "AGENTGUARD_OPA_MODE": "cli",
            }
        )
        self.assertFalse(config.performance_representative)

    def test_rest_mode_is_performance_representative(self) -> None:
        config = load_config(environ={"AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX})
        self.assertTrue(config.performance_representative)


if __name__ == "__main__":
    unittest.main()

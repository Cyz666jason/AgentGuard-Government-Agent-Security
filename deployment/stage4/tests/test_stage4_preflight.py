from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "run_stage4_preflight.py"
SPEC = importlib.util.spec_from_file_location("run_stage4_preflight", SCRIPT)
assert SPEC and SPEC.loader
stage4 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage4)


def ready_runtime() -> dict[str, object]:
    return {
        "system": "Linux",
        "release": "test",
        "machine": "x86_64",
        "dev_kvm_present": True,
        "dev_kvm_read_write": True,
        "binaries": {
            "kata-runtime": True,
            "firecracker": True,
            "jailer": True,
            "bao": True,
            "kubectl": True,
        },
    }


def ready_config(temp: Path) -> dict[str, object]:
    ca = temp / "ca.pem"
    kubeconfig = temp / "kubeconfig"
    dataset = temp / "authorised.jsonl"
    manifest = temp / "manifest.json"
    output = temp / "redacted"
    for path in (ca, kubeconfig):
        path.write_text("test fixture\n", encoding="utf-8")
    dataset.write_text(
        json.dumps({"event": "query", "user_id": "user-1"}) + "\n",
        encoding="utf-8",
    )
    manifest.write_text(
        json.dumps(
            {
                "manifest_version": 1,
                "dataset_id": "authorised-fixture",
                "dataset_schema_version": "v1",
                "owner_approval_reference": "approval-123",
                "approved_purpose": "agentguard-security-evaluation",
                "allowed_fields": ["event", "user_id"],
                "prohibited_fields": ["password", "token"],
                "expires_at": "2099-01-01T00:00:00+00:00",
                "source_hash_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
                "record_count": 1,
                "retention_and_deletion_reference": "retention-123",
                "side_effects_allowed": False,
            }
        ),
        encoding="utf-8",
    )
    output.mkdir()
    return {
        "schema_version": 1,
        "kata_firecracker": {
            "required_runtimes": ["kata-runtime", "firecracker", "jailer"],
            "kernel_image_reference": "sha256:kernel",
            "rootfs_image_reference": "sha256:rootfs",
            "test_workload_reference": "sha256:workload",
        },
        "openbao": {
            "nodes": [
                {
                    "id": "a",
                    "api_url": "https://a.example.invalid:8200",
                    "failure_domain": "zone-a",
                },
                {
                    "id": "b",
                    "api_url": "https://b.example.invalid:8200",
                    "failure_domain": "zone-b",
                },
                {
                    "id": "c",
                    "api_url": "https://c.example.invalid:8200",
                    "failure_domain": "zone-c",
                },
            ],
            "ca_cert_file": str(ca),
            "auto_unseal": {
                "provider": "transit",
                "key_reference": "secret-manager://openbao/seal-key",
            },
            "snapshot": {
                "target_reference": "object-store://snapshots",
                "restore_test_environment": "isolated-restore-cluster",
            },
            "network_partition_test_environment": "chaos-window-123",
            "capacity_test_environment": "load-lab-123",
        },
        "kubernetes": {
            "context": "agentguard-test",
            "namespace": "agentguard",
            "networkpolicy_enforcement_evidence_reference": "cni-doc-123",
            "mtls_provider": "istio",
            "mtls_enforcement_evidence_reference": "mesh-profile-123",
            "failure_test_environment": "cluster-lab-123",
        },
        "keycloak": {
            "public_url": "https://identity.example.invalid",
            "node_endpoints": [
                "https://identity-a.example.invalid",
                "https://identity-b.example.invalid",
            ],
            "ca_cert_file": str(ca),
            "database_ha_confirmed": True,
            "cache_ha_confirmed": True,
            "load_balancer_health_reference": "lb-config-123",
            "directory_federation": {
                "type": "ldap",
                "connection_reference": "directory-change-123",
            },
            "real_mfa": {
                "method": "webauthn",
                "authorized_test_account_reference": "test-user-123",
            },
        },
        "business_and_data": {
            "api": {
                "side_effect_test_scope": "preproduction-test-tenant",
                "rollback_or_compensation_reference": "runbook-123",
            },
            "authorized_dataset": {
                "expected_dataset_id": "authorised-fixture",
                "expected_purpose": "agentguard-security-evaluation",
                "expected_schema_version": "v1",
                "redaction_output_directory": str(output),
            },
        },
    }


def ready_environment(config: dict[str, object]) -> dict[str, str]:
    test_root = Path(
        str(
            config["business_and_data"]["authorized_dataset"][
                "redaction_output_directory"
            ]
        )
    ).parent
    return {
        "AGENTGUARD_RUN_ID": "unit-test",
        "AGENTGUARD_STAGE4_OPENBAO_TOKEN": "secret-token-not-for-report",
        "AGENTGUARD_STAGE4_KUBECONFIG": str(test_root / "kubeconfig"),
        "AGENTGUARD_STAGE4_KEYCLOAK_ADMIN_TOKEN": "secret-admin",
        "AGENTGUARD_STAGE4_LDAP_BIND_SECRET": "secret-ldap",
        "AGENTGUARD_STAGE4_MFA_TEST_CREDENTIAL": "secret-mfa",
        "AGENTGUARD_BUSINESS_API_BASE_URL": "https://business.example.invalid",
        "AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS": "business.example.invalid",
        "AGENTGUARD_BUSINESS_API_TOKEN": "secret-business",
        "AGENTGUARD_BUSINESS_API_TIMEOUT_SECONDS": "5",
        "AGENTGUARD_BUSINESS_ENVIRONMENT": "preproduction",
        "AGENTGUARD_ALLOW_PRODUCTION_SIDE_EFFECTS": "leave-empty-for-read-only",
        "AGENTGUARD_BUSINESS_MAX_WRITE_AMOUNT": "0",
        "AGENTGUARD_REQUESTER_OIDC_ISSUER": "https://identity.example.invalid/realms/test",
        "AGENTGUARD_REQUESTER_OIDC_AUDIENCE": "agentguard",
        "AGENTGUARD_QUERY_REQUESTER_ACCESS_TOKEN": "secret-query-requester",
        "AGENTGUARD_AUTHORIZED_DATA_JSONL": str(test_root / "authorised.jsonl"),
        "AGENTGUARD_AUTHORIZED_DATA_MANIFEST": str(test_root / "manifest.json"),
        "AGENTGUARD_REDACTION_SALT_HEX": "ab" * 32,
    }


class Stage4PreflightTests(unittest.TestCase):
    def test_example_config_is_truthfully_blocked_on_windows(self) -> None:
        config = json.loads(stage4.DEFAULT_CONFIG.read_text(encoding="utf-8"))
        runtime = {
            "system": "Windows",
            "release": "11",
            "machine": "AMD64",
            "dev_kvm_present": False,
            "dev_kvm_read_write": False,
            "binaries": {},
        }
        report = stage4.build_report(config, {}, runtime)
        self.assertEqual(stage4.BLOCKED, report["status"])
        self.assertFalse(report["production_ready"])
        self.assertFalse(report["product_validation_completed"])
        self.assertFalse(report["mutating_commands_performed"])
        self.assertFalse(report["network_requests_performed"])

    def test_all_inputs_can_only_reach_prepared_not_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            report = stage4.build_report(
                config, ready_environment(config), ready_runtime()
            )
        self.assertEqual(stage4.PREPARED, report["status"])
        self.assertEqual(5, report["summary"]["prepared_not_verified"])
        for domain in report["domains"].values():
            self.assertEqual(stage4.PREPARED, domain["status"])
            self.assertFalse(domain["product_validation_completed"])

    def test_ready_external_environment_without_secrets_awaits_authorisation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            environment = {
                "AGENTGUARD_STAGE4_KUBECONFIG": str(Path(directory) / "kubeconfig"),
                "AGENTGUARD_REDACTION_SALT_HEX": "ab" * 32,
            }
            report = stage4.build_report(config, environment, ready_runtime())
        self.assertEqual(stage4.AWAITING, report["status"])
        self.assertEqual(
            stage4.AWAITING, report["domains"]["openbao"]["status"]
        )
        self.assertEqual(
            stage4.AWAITING, report["domains"]["keycloak"]["status"]
        )
        self.assertEqual(
            stage4.AWAITING, report["domains"]["business_and_data"]["status"]
        )

    def test_invalid_redaction_salt_never_passes_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            environment = ready_environment(config)
            environment["AGENTGUARD_REDACTION_SALT_HEX"] = "not-hex"
            report = stage4.build_report(config, environment, ready_runtime())
        business = report["domains"]["business_and_data"]
        self.assertEqual(stage4.AWAITING, business["status"])
        self.assertFalse(
            business["checks"]["redaction_salt_is_at_least_32_bytes_hex"]
        )
        self.assertEqual(1, stage4.exit_code_for_report(report))

    def test_secret_values_are_not_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            environment = ready_environment(config)
            report = stage4.build_report(config, environment, ready_runtime())
            serialized = json.dumps(report)
        for secret in environment.values():
            if secret.startswith("secret-"):
                self.assertNotIn(secret, serialized)
        self.assertFalse(report["secret_values_recorded"])
        self.assertNotIn(str(Path(directory)), serialized)

    def test_every_domain_uses_the_restricted_status_contract(self) -> None:
        config = json.loads(stage4.DEFAULT_CONFIG.read_text(encoding="utf-8"))
        report = stage4.build_report(config, {}, ready_runtime())
        for domain in report["domains"].values():
            self.assertIn(domain["status"], stage4.ALLOWED_STATUSES)
        self.assertIn(report["status"], stage4.ALLOWED_STATUSES)

    def test_markdown_keeps_the_evidence_boundary(self) -> None:
        config = json.loads(stage4.DEFAULT_CONFIG.read_text(encoding="utf-8"))
        report = stage4.build_report(config, {}, ready_runtime())
        markdown = stage4.render_markdown(report)
        self.assertIn("Production ready: no", markdown)
        self.assertIn("does not prove product E2E", markdown)
        self.assertIn("kernel_image_reference_supplied", markdown)
        self.assertIn("AGENTGUARD_BUSINESS_API_TOKEN", markdown)

    def test_business_hostname_must_be_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            environment = ready_environment(config)
            environment["AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS"] = "other.example.invalid"
            report = stage4.build_report(config, environment, ready_runtime())
        business = report["domains"]["business_and_data"]
        self.assertFalse(business["checks"]["business_api_hostname_in_allowlist"])
        self.assertIn("business_api_hostname_not_allowlisted", business["validation_errors"])
        self.assertEqual(1, stage4.exit_code_for_report(report))

    def test_manifest_hash_expiry_side_effects_and_fields_are_enforced(self) -> None:
        mutations = {
            "hash": {"source_hash_sha256": "0" * 64},
            "expiry": {"expires_at": "2020-01-01T00:00:00+00:00"},
            "side_effect": {"side_effects_allowed": True},
            "purpose": {"approved_purpose": "unapproved-purpose"},
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                config = ready_config(Path(directory))
                manifest_path = Path(directory) / "manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest.update(mutation)
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                report = stage4.build_report(
                    config, ready_environment(config), ready_runtime()
                )
                self.assertFalse(report["preflight_valid"])
                self.assertEqual(1, stage4.exit_code_for_report(report))

    def test_dataset_with_unapproved_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            dataset = Path(directory) / "authorised.jsonl"
            dataset.write_text(
                json.dumps(
                    {"event": "query", "user_id": "user-1", "password": "leak"}
                )
                + "\n",
                encoding="utf-8",
            )
            manifest_path = Path(directory) / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["source_hash_sha256"] = hashlib.sha256(dataset.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            report = stage4.build_report(
                config, ready_environment(config), ready_runtime()
            )
        checks = report["domains"]["business_and_data"]["checks"]
        self.assertFalse(checks["records_use_only_allowed_fields"])
        self.assertFalse(checks["records_exclude_prohibited_fields"])
        self.assertEqual(1, stage4.exit_code_for_report(report))

    def test_output_path_must_be_an_existing_writable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            output_file = Path(directory) / "not-a-directory"
            output_file.write_text("x", encoding="utf-8")
            config["business_and_data"]["authorized_dataset"][
                "redaction_output_directory"
            ] = str(output_file)
            report = stage4.build_report(
                config, ready_environment(config), ready_runtime()
            )
        errors = report["domains"]["business_and_data"]["validation_errors"]
        self.assertIn("redaction_output_directory_not_writable", errors)
        self.assertEqual(1, stage4.exit_code_for_report(report))

    def test_exit_code_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ready_config(Path(directory))
            ready = stage4.build_report(config, ready_environment(config), ready_runtime())
            missing = stage4.build_report(config, {}, ready_runtime())
            bad_environment = ready_environment(config)
            bad_environment["AGENTGUARD_BUSINESS_API_BASE_URL"] = "http://unsafe.invalid"
            invalid = stage4.build_report(config, bad_environment, ready_runtime())
        self.assertEqual(0, stage4.exit_code_for_report(ready))
        self.assertEqual(2, stage4.exit_code_for_report(missing))
        self.assertEqual(1, stage4.exit_code_for_report(invalid))

    def test_malformed_config_returns_exit_code_one_without_path_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            config_path = temp / "bad-config.json"
            report_path = temp / "report.json"
            markdown_path = temp / "report.md"
            config_path.write_text("{bad", encoding="utf-8")
            code = stage4.main(
                [
                    "--config",
                    str(config_path),
                    "--report",
                    str(report_path),
                    "--markdown",
                    str(markdown_path),
                ]
            )
        self.assertEqual(1, code)


if __name__ == "__main__":
    unittest.main()

"""Read-only Stage 4 preflight for externally controlled production environments.

This command deliberately does not deploy, mutate, authenticate to, or load-test
any external system.  It only inspects local prerequisites, non-secret
configuration, and the *presence* of explicitly authorised credentials.

The report can only use the following honest states:

* blocked_external_environment
* awaiting_authorized_input
* configuration_prepared_not_verified

Even a fully prepared environment is not reported as complete until the
separate, authorised product E2E has been executed and reviewed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "deployment" / "stage4" / "stage4.preflight.example.json"
DEFAULT_REPORT = ROOT / "reports" / "stage4_preflight.json"
DEFAULT_MARKDOWN = ROOT / "reports" / "stage4_preflight.md"

BLOCKED = "blocked_external_environment"
AWAITING = "awaiting_authorized_input"
PREPARED = "configuration_prepared_not_verified"
ALLOWED_STATUSES = {BLOCKED, AWAITING, PREPARED}

SECRET_ENV_VARS = {
    "openbao": ("AGENTGUARD_STAGE4_OPENBAO_TOKEN",),
    "kubernetes": ("AGENTGUARD_STAGE4_KUBECONFIG",),
    "keycloak": (
        "AGENTGUARD_STAGE4_KEYCLOAK_ADMIN_TOKEN",
        "AGENTGUARD_STAGE4_LDAP_BIND_SECRET",
        "AGENTGUARD_STAGE4_MFA_TEST_CREDENTIAL",
    ),
    "business_and_data": (
        "AGENTGUARD_BUSINESS_API_TOKEN",
        "AGENTGUARD_REDACTION_SALT_HEX",
    ),
}


def _present(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _all_present(environment: Mapping[str, str], names: tuple[str, ...]) -> bool:
    return all(_present(environment.get(name, "")) for name in names)


def _https(value: object) -> bool:
    if not _present(value):
        return False
    parsed = urlparse(str(value).strip())
    return parsed.scheme.lower() == "https" and bool(parsed.hostname)


def _readable_file(value: object) -> bool:
    if not _present(value):
        return False
    path = Path(str(value)).expanduser()
    return path.is_file() and os.access(path, os.R_OK)


def _readable_directory(value: object) -> bool:
    if not _present(value):
        return False
    path = Path(str(value)).expanduser()
    return path.is_dir() and os.access(path, os.R_OK)


def _writable_directory(value: object) -> bool:
    if not _present(value):
        return False
    path = Path(str(value)).expanduser()
    return path.is_dir() and os.access(path, os.R_OK | os.W_OK)


def _valid_redaction_salt(value: object) -> bool:
    """Match the redaction pipeline's minimum: 32 bytes encoded as hex."""
    if not _present(value):
        return False
    text = str(value).strip()
    if len(text) < 64 or len(text) % 2:
        return False
    try:
        decoded = bytes.fromhex(text)
    except ValueError:
        return False
    return len(decoded) >= 32


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _future_datetime(value: object) -> bool:
    if not _present(value):
        return False
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        return False
    return parsed.astimezone(timezone.utc) > datetime.now(timezone.utc)


def _validate_authorized_dataset(
    dataset_path_value: object,
    manifest_path_value: object,
    *,
    expected_dataset_id: object,
    expected_purpose: object,
    expected_schema_version: object,
) -> tuple[dict[str, bool], list[str]]:
    """Validate the approval manifest and source data without exposing either path."""
    checks = {
        "manifest_json_object": False,
        "manifest_version_supported": False,
        "dataset_id_matches_expected": False,
        "approved_purpose_matches_expected": False,
        "dataset_schema_version_matches_expected": False,
        "owner_approval_reference_present": False,
        "authorization_not_expired": False,
        "allowed_fields_nonempty_unique": False,
        "prohibited_fields_valid_unique": False,
        "prohibited_fields_disjoint": False,
        "side_effects_explicitly_forbidden": False,
        "retention_and_deletion_reference_present": False,
        "source_sha256_matches_data": False,
        "record_count_matches_data": False,
        "jsonl_records_are_objects": False,
        "records_use_only_allowed_fields": False,
        "records_exclude_prohibited_fields": False,
    }
    errors: list[str] = []
    if not _readable_file(dataset_path_value) or not _readable_file(manifest_path_value):
        return checks, errors
    dataset_path = Path(str(dataset_path_value)).expanduser()
    manifest_path = Path(str(manifest_path_value)).expanduser()
    try:
        if manifest_path.stat().st_size > 1024 * 1024:
            errors.append("authorized_manifest_too_large")
            return checks, errors
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors.append("authorized_manifest_invalid_json")
        return checks, errors
    checks["manifest_json_object"] = isinstance(manifest, dict)
    if not isinstance(manifest, dict):
        errors.append("authorized_manifest_root_not_object")
        return checks, errors

    allowed_manifest_keys = {
        "manifest_version",
        "dataset_id",
        "dataset_schema_version",
        "owner_approval_reference",
        "approved_purpose",
        "allowed_fields",
        "prohibited_fields",
        "expires_at",
        "source_hash_sha256",
        "record_count",
        "retention_and_deletion_reference",
        "side_effects_allowed",
    }
    if set(manifest) - allowed_manifest_keys:
        errors.append("authorized_manifest_unknown_properties")

    checks["manifest_version_supported"] = (
        type(manifest.get("manifest_version")) is int
        and manifest.get("manifest_version") == 1
    )
    checks["dataset_id_matches_expected"] = (
        _present(expected_dataset_id)
        and manifest.get("dataset_id") == str(expected_dataset_id).strip()
    )
    checks["approved_purpose_matches_expected"] = (
        _present(expected_purpose)
        and manifest.get("approved_purpose") == str(expected_purpose).strip()
    )
    checks["dataset_schema_version_matches_expected"] = (
        _present(expected_schema_version)
        and manifest.get("dataset_schema_version")
        == str(expected_schema_version).strip()
    )
    checks["owner_approval_reference_present"] = _present(
        manifest.get("owner_approval_reference")
    )
    checks["authorization_not_expired"] = _future_datetime(manifest.get("expires_at"))
    allowed_fields_value = manifest.get("allowed_fields")
    allowed_fields = (
        [str(item).strip() for item in allowed_fields_value]
        if isinstance(allowed_fields_value, list)
        and all(isinstance(item, str) and item.strip() for item in allowed_fields_value)
        else []
    )
    checks["allowed_fields_nonempty_unique"] = bool(allowed_fields) and len(
        set(allowed_fields)
    ) == len(allowed_fields)
    prohibited_value = manifest.get("prohibited_fields", [])
    prohibited_fields = (
        [str(item).strip() for item in prohibited_value]
        if isinstance(prohibited_value, list)
        and all(isinstance(item, str) and item.strip() for item in prohibited_value)
        else []
    )
    checks["prohibited_fields_valid_unique"] = (
        isinstance(prohibited_value, list)
        and len(set(prohibited_fields)) == len(prohibited_fields)
        and len(prohibited_fields) == len(prohibited_value)
    )
    checks["prohibited_fields_disjoint"] = not (
        set(allowed_fields) & set(prohibited_fields)
    )
    checks["side_effects_explicitly_forbidden"] = (
        manifest.get("side_effects_allowed") is False
    )
    checks["retention_and_deletion_reference_present"] = _present(
        manifest.get("retention_and_deletion_reference")
    )

    expected_hash = manifest.get("source_hash_sha256")
    hash_format_valid = (
        isinstance(expected_hash, str)
        and len(expected_hash) == 64
        and all(character in "0123456789abcdefABCDEF" for character in expected_hash)
    )
    try:
        checks["source_sha256_matches_data"] = hash_format_valid and (
            _sha256_file(dataset_path).lower() == expected_hash.lower()
        )
    except OSError:
        errors.append("authorized_dataset_hash_read_failed")

    records = 0
    objects_only = True
    allowed_only = True
    prohibited_absent = True
    try:
        with dataset_path.open("r", encoding="utf-8-sig") as source:
            for line in source:
                if not line.strip():
                    continue
                records += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    objects_only = False
                    continue
                if not isinstance(record, dict):
                    objects_only = False
                    continue
                record_fields = set(record)
                if not set(allowed_fields).issuperset(record_fields):
                    allowed_only = False
                if set(prohibited_fields) & record_fields:
                    prohibited_absent = False
    except (OSError, UnicodeError):
        errors.append("authorized_dataset_jsonl_read_failed")
        objects_only = False
    checks["jsonl_records_are_objects"] = objects_only and records > 0
    checks["records_use_only_allowed_fields"] = allowed_only and records > 0
    checks["records_exclude_prohibited_fields"] = prohibited_absent and records > 0
    record_count = manifest.get("record_count")
    checks["record_count_matches_data"] = (
        isinstance(record_count, int)
        and not isinstance(record_count, bool)
        and record_count >= 1
        and record_count == records
    )

    for name, passed in checks.items():
        if not passed:
            errors.append(f"authorized_data_{name}_failed")
    return checks, sorted(set(errors))


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _runtime_facts() -> dict[str, Any]:
    kvm = Path("/dev/kvm")
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "dev_kvm_present": kvm.exists(),
        "dev_kvm_read_write": kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
        "binaries": {
            name: bool(shutil.which(name))
            for name in (
                "kata-runtime",
                "firecracker",
                "jailer",
                "bao",
                "kubectl",
            )
        },
    }


def _result(
    name: str,
    status: str,
    checks: Mapping[str, bool],
    blockers: list[str],
    authorized_inputs_missing: list[str],
    next_steps: list[str],
    validation_errors: list[str] | None = None,
) -> dict[str, Any]:
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"unsupported Stage 4 status: {status}")
    return {
        "name": name,
        "status": status,
        "ready_for_authorized_e2e": status == PREPARED,
        "product_validation_completed": False,
        "checks": dict(checks),
        "blockers": blockers,
        "authorized_inputs_missing": authorized_inputs_missing,
        "validation_errors": validation_errors or [],
        "next_steps": next_steps,
    }


def _assess_kvm(config: Mapping[str, Any], runtime: Mapping[str, Any]) -> dict[str, Any]:
    binaries = _mapping(runtime.get("binaries"))
    required = _list(config.get("required_runtimes")) or [
        "kata-runtime",
        "firecracker",
        "jailer",
    ]
    checks = {
        "linux_host": runtime.get("system") == "Linux",
        "supported_architecture": runtime.get("machine") in {"x86_64", "aarch64"},
        "dev_kvm_present": runtime.get("dev_kvm_present") is True,
        "dev_kvm_read_write": runtime.get("dev_kvm_read_write") is True,
        "kata_runtime_available": binaries.get("kata-runtime") is True,
        "firecracker_available": binaries.get("firecracker") is True,
        "firecracker_jailer_available": binaries.get("jailer") is True,
        "kernel_image_reference_supplied": _present(config.get("kernel_image_reference")),
        "rootfs_image_reference_supplied": _present(config.get("rootfs_image_reference")),
        "test_workload_reference_supplied": _present(config.get("test_workload_reference")),
        "all_declared_runtimes_known": all(name in binaries for name in required),
    }
    blockers = [label for label, passed in checks.items() if not passed]
    status = PREPARED if not blockers else BLOCKED
    return _result(
        "Kata/Firecracker KVM product E2E",
        status,
        checks,
        blockers,
        [],
        [
            "Run on an authorised Linux x86_64/aarch64 host with read/write /dev/kvm.",
            "After preflight passes, run separate Kata and Firecracker isolation, escape, resource-limit and performance E2E.",
        ],
    )


def _assess_openbao(
    config: Mapping[str, Any],
    environment: Mapping[str, str],
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    nodes = [_mapping(node) for node in _list(config.get("nodes"))]
    failure_domains = {
        str(node.get("failure_domain", "")).strip()
        for node in nodes
        if _present(node.get("failure_domain"))
    }
    endpoints = [node.get("api_url") for node in nodes]
    node_ids = {
        str(node.get("id", "")).strip() for node in nodes if _present(node.get("id"))
    }
    auto_unseal = _mapping(config.get("auto_unseal"))
    snapshot = _mapping(config.get("snapshot"))
    binaries = _mapping(runtime.get("binaries"))
    checks = {
        "bao_cli_available": binaries.get("bao") is True,
        "at_least_three_nodes_declared": len(nodes) >= 3,
        "unique_node_ids": len(node_ids) == len(nodes) and len(nodes) >= 3,
        "at_least_three_failure_domains": len(failure_domains) >= 3,
        "all_api_endpoints_https": bool(endpoints) and all(_https(url) for url in endpoints),
        "tls_ca_readable": _readable_file(config.get("ca_cert_file")),
        "auto_unseal_provider_declared": _present(auto_unseal.get("provider")),
        "auto_unseal_key_reference_declared": _present(auto_unseal.get("key_reference")),
        "snapshot_target_declared": _present(snapshot.get("target_reference")),
        "snapshot_restore_environment_declared": _present(
            snapshot.get("restore_test_environment")
        ),
        "network_partition_environment_declared": _present(
            config.get("network_partition_test_environment")
        ),
        "capacity_environment_declared": _present(config.get("capacity_test_environment")),
    }
    validation_errors: list[str] = []
    if nodes and any(not isinstance(node, Mapping) for node in _list(config.get("nodes"))):
        validation_errors.append("openbao_node_entry_not_object")
    supplied_ids = [
        str(node.get("id", "")).strip() for node in nodes if _present(node.get("id"))
    ]
    if supplied_ids and len(set(supplied_ids)) != len(supplied_ids):
        validation_errors.append("openbao_duplicate_node_id")
    supplied_domains = [
        str(node.get("failure_domain", "")).strip()
        for node in nodes
        if _present(node.get("failure_domain"))
    ]
    if len(supplied_domains) >= 3 and len(set(supplied_domains)) < 3:
        validation_errors.append("openbao_failure_domains_not_independent")
    if any(_present(url) and not _https(url) for url in endpoints):
        validation_errors.append("openbao_api_url_not_https")
    if _present(config.get("ca_cert_file")) and not checks["tls_ca_readable"]:
        validation_errors.append("openbao_ca_file_not_readable")
    blockers = [label for label, passed in checks.items() if not passed]
    missing = [
        name
        for name in SECRET_ENV_VARS["openbao"]
        if not _present(environment.get(name, ""))
    ]
    if blockers:
        status = BLOCKED
    elif missing:
        status = AWAITING
    else:
        status = PREPARED
    return _result(
        "Cross-failure-domain OpenBao",
        status,
        checks,
        blockers,
        missing,
        [
            "Obtain an authorised least-privilege token through the organisation secret manager.",
            "Run TLS/SAN, Raft quorum, auto-unseal, snapshot restore, leader loss, network partition and capacity tests in the declared failure domains.",
        ],
        validation_errors,
    )


def _assess_kubernetes(
    config: Mapping[str, Any],
    environment: Mapping[str, str],
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    binaries = _mapping(runtime.get("binaries"))
    mtls_provider = str(config.get("mtls_provider", "")).strip().lower()
    kubeconfig_path = environment.get("AGENTGUARD_STAGE4_KUBECONFIG", "")
    checks = {
        "kubectl_available": binaries.get("kubectl") is True,
        "cluster_context_declared": _present(config.get("context")),
        "namespace_declared": _present(config.get("namespace")),
        "kubeconfig_readable": _readable_file(kubeconfig_path),
        "networkpolicy_enforcement_evidence_declared": _present(
            config.get("networkpolicy_enforcement_evidence_reference")
        ),
        "mtls_provider_declared": mtls_provider in {"istio", "linkerd", "other"},
        "mtls_enforcement_evidence_declared": _present(
            config.get("mtls_enforcement_evidence_reference")
        ),
        "failure_test_environment_declared": _present(
            config.get("failure_test_environment")
        ),
    }
    # A missing or unreadable kubeconfig is an authorised-input problem once
    # the external cluster/tooling has otherwise been supplied.
    structural_keys = {
        key: value for key, value in checks.items() if key != "kubeconfig_readable"
    }
    blockers = [label for label, passed in structural_keys.items() if not passed]
    missing = [] if checks["kubeconfig_readable"] else ["AGENTGUARD_STAGE4_KUBECONFIG"]
    validation_errors: list[str] = []
    if _present(config.get("mtls_provider")) and not checks["mtls_provider_declared"]:
        validation_errors.append("kubernetes_unsupported_mtls_provider")
    if _present(kubeconfig_path) and not checks["kubeconfig_readable"]:
        validation_errors.append("kubernetes_kubeconfig_not_readable")
    if blockers:
        status = BLOCKED
    elif missing:
        status = AWAITING
    else:
        status = PREPARED
    return _result(
        "Kubernetes NetworkPolicy and mTLS",
        status,
        checks,
        blockers,
        missing,
        [
            "Use a read-only preflight identity first; use a separately approved deployment identity only when applying manifests.",
            "Verify default deny, required service paths, DNS egress, policy enforcement by the CNI, STRICT mTLS and plaintext rejection.",
        ],
        validation_errors,
    )


def _assess_keycloak(
    config: Mapping[str, Any], environment: Mapping[str, str]
) -> dict[str, Any]:
    endpoints = _list(config.get("node_endpoints"))
    directory = _mapping(config.get("directory_federation"))
    real_mfa = _mapping(config.get("real_mfa"))
    checks = {
        "public_url_https": _https(config.get("public_url")),
        "at_least_two_https_nodes": len(endpoints) >= 2
        and all(_https(endpoint) for endpoint in endpoints),
        "tls_ca_readable": _readable_file(config.get("ca_cert_file")),
        "production_database_ha_declared": config.get("database_ha_confirmed") is True,
        "cache_or_session_ha_declared": config.get("cache_ha_confirmed") is True,
        "load_balancer_health_reference_declared": _present(
            config.get("load_balancer_health_reference")
        ),
        "directory_provider_declared": str(directory.get("type", "")).lower()
        in {"ldap", "active_directory", "custom"},
        "directory_connection_reference_declared": _present(
            directory.get("connection_reference")
        ),
        "real_mfa_flow_declared": str(real_mfa.get("method", "")).lower()
        in {"totp", "hotp", "webauthn", "passkey"},
        "authorized_mfa_account_reference_declared": _present(
            real_mfa.get("authorized_test_account_reference")
        ),
    }
    blockers = [label for label, passed in checks.items() if not passed]
    validation_errors: list[str] = []
    if _present(config.get("public_url")) and not checks["public_url_https"]:
        validation_errors.append("keycloak_public_url_not_https")
    if endpoints and not checks["at_least_two_https_nodes"]:
        validation_errors.append("keycloak_node_endpoints_invalid")
    if _present(config.get("ca_cert_file")) and not checks["tls_ca_readable"]:
        validation_errors.append("keycloak_ca_file_not_readable")
    missing = [
        name
        for name in SECRET_ENV_VARS["keycloak"]
        if not _present(environment.get(name, ""))
    ]
    if blockers:
        status = BLOCKED
    elif missing:
        status = AWAITING
    else:
        status = PREPARED
    return _result(
        "Keycloak HTTPS/HA/federation/real MFA",
        status,
        checks,
        blockers,
        missing,
        [
            "Use authorised non-production test identities and least-privilege administration credentials.",
            "Verify issuer/SAN, node and site failover, directory sync/disable, real step-up MFA, replay rejection and audit evidence.",
        ],
        validation_errors,
    )


def _assess_business_and_data(
    config: Mapping[str, Any], environment: Mapping[str, str]
) -> dict[str, Any]:
    api = _mapping(config.get("api"))
    dataset = _mapping(config.get("authorized_dataset"))
    base_url = environment.get("AGENTGUARD_BUSINESS_API_BASE_URL", "").strip()
    allowed_hosts = [
        item.strip().lower()
        for item in environment.get("AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    ]
    parsed_base_url = urlparse(base_url) if base_url else None
    base_hostname = (
        parsed_base_url.hostname.lower()
        if parsed_base_url is not None and parsed_base_url.hostname
        else ""
    )
    ca_bundle = environment.get("AGENTGUARD_BUSINESS_API_CA_BUNDLE", "").strip()
    timeout_value = environment.get("AGENTGUARD_BUSINESS_API_TIMEOUT_SECONDS", "5").strip()
    environment_name = environment.get("AGENTGUARD_BUSINESS_ENVIRONMENT", "").strip().lower()
    side_effect_confirmation = environment.get(
        "AGENTGUARD_ALLOW_PRODUCTION_SIDE_EFFECTS", ""
    ).strip()
    side_effects_enabled = (
        environment_name == "preproduction"
        and side_effect_confirmation
        == "I_UNDERSTAND_AND_AUTHORIZE_PREPRODUCTION_WRITES"
    )
    max_write_value = environment.get("AGENTGUARD_BUSINESS_MAX_WRITE_AMOUNT", "0").strip()
    dataset_path_value = environment.get("AGENTGUARD_AUTHORIZED_DATA_JSONL", "").strip()
    manifest_path_value = environment.get(
        "AGENTGUARD_AUTHORIZED_DATA_MANIFEST", ""
    ).strip()
    redaction_salt_valid = _valid_redaction_salt(
        environment.get("AGENTGUARD_REDACTION_SALT_HEX", "")
    )
    try:
        timeout_seconds = float(timeout_value)
        timeout_valid = 0 < timeout_seconds <= 60
    except ValueError:
        timeout_valid = False
    try:
        max_write_amount = float(max_write_value)
        max_write_amount_valid = max_write_amount >= 0
    except ValueError:
        max_write_amount_valid = False
    oidc_issuer = environment.get("AGENTGUARD_REQUESTER_OIDC_ISSUER", "").strip()
    approver_issuer = environment.get("AGENTGUARD_APPROVER_OIDC_ISSUER", "").strip()
    data_checks, data_validation_errors = _validate_authorized_dataset(
        dataset_path_value,
        manifest_path_value,
        expected_dataset_id=dataset.get("expected_dataset_id"),
        expected_purpose=dataset.get("expected_purpose"),
        expected_schema_version=dataset.get("expected_schema_version"),
    )
    checks = {
        "business_api_https": _https(base_url),
        "business_api_url_shape_valid": bool(parsed_base_url)
        and not parsed_base_url.username
        and not parsed_base_url.password
        and not parsed_base_url.query
        and not parsed_base_url.fragment,
        "business_api_allowlist_declared": bool(allowed_hosts),
        "business_api_hostname_in_allowlist": bool(base_hostname)
        and base_hostname in allowed_hosts,
        "business_api_token_present": _present(
            environment.get("AGENTGUARD_BUSINESS_API_TOKEN", "")
        ),
        "business_api_ca_readable_when_configured": not ca_bundle
        or _readable_file(ca_bundle),
        "business_api_timeout_valid": timeout_valid,
        "requester_oidc_issuer_https": _https(oidc_issuer),
        "requester_oidc_audience_present": _present(
            environment.get("AGENTGUARD_REQUESTER_OIDC_AUDIENCE", "")
        ),
        "query_requester_token_present": _present(
            environment.get("AGENTGUARD_QUERY_REQUESTER_ACCESS_TOKEN", "")
        ),
        "side_effect_test_scope_declared": _present(api.get("side_effect_test_scope")),
        "rollback_or_compensation_declared": _present(
            api.get("rollback_or_compensation_reference")
        ),
        "authorized_dataset_readable": _readable_file(dataset_path_value),
        "data_authorization_manifest_readable": _readable_file(manifest_path_value),
        "expected_dataset_id_declared": _present(dataset.get("expected_dataset_id")),
        "expected_purpose_declared": _present(dataset.get("expected_purpose")),
        "expected_schema_version_declared": _present(
            dataset.get("expected_schema_version")
        ),
        "redaction_output_directory_writable": _writable_directory(
            dataset.get("redaction_output_directory")
        ),
        "redaction_salt_is_at_least_32_bytes_hex": redaction_salt_valid,
        "business_max_write_amount_valid": max_write_amount_valid,
    }
    checks.update(data_checks)
    if side_effects_enabled:
        checks.update(
            {
                "business_environment_is_preproduction": environment_name
                == "preproduction",
                "write_requester_token_present": _present(
                    environment.get("AGENTGUARD_WRITE_REQUESTER_ACCESS_TOKEN", "")
                ),
                "approver_oidc_issuer_https": _https(approver_issuer),
                "approver_oidc_audience_present": _present(
                    environment.get("AGENTGUARD_APPROVER_OIDC_AUDIENCE", "")
                ),
                "approver_token_present": _present(
                    environment.get("AGENTGUARD_APPROVER_ACCESS_TOKEN", "")
                ),
                "positive_write_limit_configured": max_write_amount_valid
                and max_write_amount > 0,
            }
        )
    missing = []
    required_inputs = {
        "AGENTGUARD_BUSINESS_API_BASE_URL": base_url,
        "AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS": environment.get(
            "AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS", ""
        ),
        "AGENTGUARD_BUSINESS_API_TOKEN": environment.get(
            "AGENTGUARD_BUSINESS_API_TOKEN", ""
        ),
        "AGENTGUARD_REQUESTER_OIDC_ISSUER": oidc_issuer,
        "AGENTGUARD_REQUESTER_OIDC_AUDIENCE": environment.get(
            "AGENTGUARD_REQUESTER_OIDC_AUDIENCE", ""
        ),
        "AGENTGUARD_QUERY_REQUESTER_ACCESS_TOKEN": environment.get(
            "AGENTGUARD_QUERY_REQUESTER_ACCESS_TOKEN", ""
        ),
        "AGENTGUARD_AUTHORIZED_DATA_JSONL": dataset_path_value,
        "AGENTGUARD_AUTHORIZED_DATA_MANIFEST": manifest_path_value,
        "AGENTGUARD_REDACTION_SALT_HEX": environment.get(
            "AGENTGUARD_REDACTION_SALT_HEX", ""
        ),
    }
    if side_effects_enabled:
        required_inputs.update(
            {
                "AGENTGUARD_WRITE_REQUESTER_ACCESS_TOKEN": environment.get(
                    "AGENTGUARD_WRITE_REQUESTER_ACCESS_TOKEN", ""
                ),
                "AGENTGUARD_APPROVER_OIDC_ISSUER": approver_issuer,
                "AGENTGUARD_APPROVER_OIDC_AUDIENCE": environment.get(
                    "AGENTGUARD_APPROVER_OIDC_AUDIENCE", ""
                ),
                "AGENTGUARD_APPROVER_ACCESS_TOKEN": environment.get(
                    "AGENTGUARD_APPROVER_ACCESS_TOKEN", ""
                ),
            }
        )
    missing.extend(name for name, value in required_inputs.items() if not _present(value))
    config_gaps = [
        name
        for name in (
            "side_effect_test_scope_declared",
            "rollback_or_compensation_declared",
            "expected_dataset_id_declared",
            "expected_purpose_declared",
            "expected_schema_version_declared",
            "redaction_output_directory_writable",
        )
        if not checks[name]
    ]
    missing.extend(config_gaps)
    validation_errors = list(data_validation_errors)
    if base_url and not checks["business_api_https"]:
        validation_errors.append("business_api_base_url_not_https")
    if base_url and not checks["business_api_url_shape_valid"]:
        validation_errors.append("business_api_base_url_has_forbidden_components")
    if base_url and allowed_hosts and not checks["business_api_hostname_in_allowlist"]:
        validation_errors.append("business_api_hostname_not_allowlisted")
    if ca_bundle and not checks["business_api_ca_readable_when_configured"]:
        validation_errors.append("business_api_ca_bundle_not_readable")
    if not timeout_valid:
        validation_errors.append("business_api_timeout_invalid")
    if oidc_issuer and not checks["requester_oidc_issuer_https"]:
        validation_errors.append("requester_oidc_issuer_not_https")
    if side_effect_confirmation and side_effect_confirmation not in {
        "false",
        "leave-empty-for-read-only",
        "I_UNDERSTAND_AND_AUTHORIZE_PREPRODUCTION_WRITES",
    }:
        validation_errors.append("business_side_effect_confirmation_invalid")
    if (
        side_effect_confirmation
        == "I_UNDERSTAND_AND_AUTHORIZE_PREPRODUCTION_WRITES"
        and environment_name != "preproduction"
    ):
        validation_errors.append("business_write_enabled_outside_preproduction")
    if not max_write_amount_valid:
        validation_errors.append("business_max_write_amount_invalid")
    if side_effects_enabled:
        if not _present(environment.get("AGENTGUARD_BUSINESS_MAX_WRITE_AMOUNT", "")):
            missing.append("AGENTGUARD_BUSINESS_MAX_WRITE_AMOUNT")
        elif max_write_amount_valid and max_write_amount <= 0:
            validation_errors.append("business_max_write_amount_not_positive")
    if _present(environment.get("AGENTGUARD_REDACTION_SALT_HEX", "")) and not redaction_salt_valid:
        validation_errors.append("redaction_salt_invalid")
    if dataset_path_value and not checks["authorized_dataset_readable"]:
        validation_errors.append("authorized_dataset_not_readable")
    if manifest_path_value and not checks["data_authorization_manifest_readable"]:
        validation_errors.append("authorized_manifest_not_readable")
    if _present(dataset.get("redaction_output_directory")) and not checks[
        "redaction_output_directory_writable"
    ]:
        validation_errors.append("redaction_output_directory_not_writable")
    if side_effects_enabled and approver_issuer and not checks[
        "approver_oidc_issuer_https"
    ]:
        validation_errors.append("approver_oidc_issuer_not_https")
    # Business endpoints, credentials and production data are organisation-owned
    # inputs.  Their absence is not represented as an implementation failure.
    status = AWAITING if missing or validation_errors else PREPARED
    return _result(
        "Authorised business API and production data",
        status,
        checks,
        [],
        sorted(set(missing)),
        [
            "Obtain written data-owner/API-owner authorisation, scoped credentials and an approved rollback window.",
            "Validate schema and provenance, redact into an isolated output directory, then run read-only calls before approved side-effect tests.",
        ],
        sorted(set(validation_errors)),
    )


def build_report(
    config: Mapping[str, Any],
    environment: Mapping[str, str] | None = None,
    runtime: Mapping[str, Any] | None = None,
    *,
    config_name: str = "stage4.preflight.example.json",
) -> dict[str, Any]:
    environment = environment or {}
    runtime = runtime or _runtime_facts()
    configuration_errors: list[str] = []
    allowed_top_level = {
        "schema_version",
        "kata_firecracker",
        "openbao",
        "kubernetes",
        "keycloak",
        "business_and_data",
    }
    if config.get("schema_version") != 1:
        configuration_errors.append("stage4_schema_version_unsupported")
    if set(config) - allowed_top_level:
        configuration_errors.append("stage4_config_unknown_top_level_properties")
    domains = {
        "kata_firecracker": _assess_kvm(_mapping(config.get("kata_firecracker")), runtime),
        "openbao": _assess_openbao(
            _mapping(config.get("openbao")), environment, runtime
        ),
        "kubernetes": _assess_kubernetes(
            _mapping(config.get("kubernetes")), environment, runtime
        ),
        "keycloak": _assess_keycloak(
            _mapping(config.get("keycloak")), environment
        ),
        "business_and_data": _assess_business_and_data(
            _mapping(config.get("business_and_data")), environment
        ),
    }
    statuses = [domain["status"] for domain in domains.values()]
    for domain_name, domain in domains.items():
        configuration_errors.extend(
            f"{domain_name}:{error}" for error in domain["validation_errors"]
        )
    if BLOCKED in statuses:
        overall = BLOCKED
    elif AWAITING in statuses:
        overall = AWAITING
    else:
        overall = PREPARED
    report = {
        "schema_version": 1,
        "generated_at": datetime.now().astimezone().isoformat(),
        "run_id": environment.get("AGENTGUARD_RUN_ID", "standalone"),
        "status": overall,
        "production_ready": False,
        "product_validation_completed": False,
        "preflight_valid": not configuration_errors,
        "result_class": (
            "invalid_configuration" if configuration_errors else overall
        ),
        "preflight_mode": "read_only",
        "network_requests_performed": False,
        "mutating_commands_performed": False,
        "secret_values_recorded": False,
        "config_source_filename": Path(config_name).name,
        "host": {
            "system": runtime.get("system"),
            "release": runtime.get("release"),
            "machine": runtime.get("machine"),
        },
        "status_contract": sorted(ALLOWED_STATUSES),
        "domains": domains,
        "summary": {
            "prepared_not_verified": statuses.count(PREPARED),
            "awaiting_authorized_input": statuses.count(AWAITING),
            "blocked_external_environment": statuses.count(BLOCKED),
            "total": len(statuses),
            "validation_errors": len(configuration_errors),
        },
        "validation_errors": sorted(set(configuration_errors)),
        "boundary": (
            "This preflight proves only that local prerequisites and authorised-input "
            "presence are prepared. It does not prove product E2E, production safety, "
            "high availability, isolation strength, or performance."
        ),
    }
    report["expected_exit_code"] = exit_code_for_report(report)
    return report


def exit_code_for_report(report: Mapping[str, Any]) -> int:
    if report.get("preflight_valid") is not True:
        return 1
    return 0 if report.get("status") == PREPARED else 2


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Stage 4 external-environment preflight",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Overall status: `{report['status']}`",
        f"- Result class: `{report['result_class']}`",
        f"- Configuration valid: {'yes' if report['preflight_valid'] else 'no'}",
        "- Mode: read-only; no deployment, mutation, login or load test performed",
        "- Production ready: no",
        "",
        "| Domain | Status | Prepared for authorised E2E |",
        "|---|---|---:|",
    ]
    for domain in report["domains"].values():
        lines.append(
            f"| {domain['name']} | `{domain['status']}` | "
            f"{'yes' if domain['ready_for_authorized_e2e'] else 'no'} |"
        )
    lines.extend(["", "## Blockers and missing authorised inputs", ""])
    for domain in report["domains"].values():
        gaps = domain["blockers"] + domain["authorized_inputs_missing"]
        lines.append(f"### {domain['name']}")
        lines.append("")
        if gaps:
            lines.extend(f"- {gap}" for gap in gaps)
        else:
            lines.append("- Preflight inputs are present; product validation has not been run.")
        lines.append("")
    if report["validation_errors"]:
        lines.extend(["## Configuration and validation errors", ""])
        lines.extend(f"- `{error}`" for error in report["validation_errors"])
        lines.append("")
    lines.extend(
        [
            "## Evidence boundary",
            "",
            str(report["boundary"]),
            "",
        ]
    )
    return "\n".join(lines)


def _load_config(path: Path) -> Mapping[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read Stage 4 config {path.name}") from exc
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Stage 4 config {path.name} is invalid JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    if not isinstance(loaded, dict):
        raise ValueError("Stage 4 config root must be a JSON object")
    return loaded


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("AGENTGUARD_STAGE4_CONFIG", DEFAULT_CONFIG)),
        help="Non-secret Stage 4 JSON config; defaults to the safe example.",
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config = _load_config(args.config)
        report = build_report(
            config,
            os.environ,
            config_name=args.config.name,
        )
    except ValueError as exc:
        error_text = str(exc)
        invalid_report = {
            "schema_version": 1,
            "generated_at": datetime.now().astimezone().isoformat(),
            "status": BLOCKED,
            "result_class": "invalid_configuration",
            "preflight_valid": False,
            "production_ready": False,
            "product_validation_completed": False,
            "preflight_mode": "read_only",
            "network_requests_performed": False,
            "mutating_commands_performed": False,
            "secret_values_recorded": False,
            "config_source_filename": args.config.name,
            "validation_errors": ["stage4_config_parse_failed"],
            "expected_exit_code": 1,
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(invalid_report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        args.markdown.write_text(
            "# Stage 4 external-environment preflight\n\n"
            "- Result class: `invalid_configuration`\n"
            "- Production ready: no\n"
            "- Validation error: `stage4_config_parse_failed`\n",
            encoding="utf-8",
        )
        print(f"stage4_config_invalid: {error_text}", file=sys.stderr)
        return 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    args.markdown.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return exit_code_for_report(report)


if __name__ == "__main__":
    raise SystemExit(main())

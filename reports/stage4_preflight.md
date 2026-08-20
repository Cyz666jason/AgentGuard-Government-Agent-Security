# Stage 4 external-environment preflight

- Generated: 2026-08-20T17:03:12.609135+08:00
- Overall status: `blocked_external_environment`
- Result class: `blocked_external_environment`
- Configuration valid: yes
- Mode: read-only; no deployment, mutation, login or load test performed
- Production ready: no

| Domain | Status | Prepared for authorised E2E |
|---|---|---:|
| Kata/Firecracker KVM product E2E | `blocked_external_environment` | no |
| Cross-failure-domain OpenBao | `blocked_external_environment` | no |
| Kubernetes NetworkPolicy and mTLS | `blocked_external_environment` | no |
| Keycloak HTTPS/HA/federation/real MFA | `blocked_external_environment` | no |
| Authorised business API and production data | `awaiting_authorized_input` | no |

## Blockers and missing authorised inputs

### Kata/Firecracker KVM product E2E

- linux_host
- supported_architecture
- dev_kvm_present
- dev_kvm_read_write
- kata_runtime_available
- firecracker_available
- firecracker_jailer_available
- kernel_image_reference_supplied
- rootfs_image_reference_supplied
- test_workload_reference_supplied

### Cross-failure-domain OpenBao

- unique_node_ids
- at_least_three_failure_domains
- all_api_endpoints_https
- tls_ca_readable
- auto_unseal_provider_declared
- auto_unseal_key_reference_declared
- snapshot_target_declared
- snapshot_restore_environment_declared
- network_partition_environment_declared
- capacity_environment_declared
- AGENTGUARD_STAGE4_OPENBAO_TOKEN

### Kubernetes NetworkPolicy and mTLS

- kubectl_available
- cluster_context_declared
- networkpolicy_enforcement_evidence_declared
- mtls_provider_declared
- mtls_enforcement_evidence_declared
- failure_test_environment_declared
- AGENTGUARD_STAGE4_KUBECONFIG

### Keycloak HTTPS/HA/federation/real MFA

- public_url_https
- at_least_two_https_nodes
- tls_ca_readable
- production_database_ha_declared
- cache_or_session_ha_declared
- load_balancer_health_reference_declared
- directory_provider_declared
- directory_connection_reference_declared
- real_mfa_flow_declared
- authorized_mfa_account_reference_declared
- AGENTGUARD_STAGE4_KEYCLOAK_ADMIN_TOKEN
- AGENTGUARD_STAGE4_LDAP_BIND_SECRET
- AGENTGUARD_STAGE4_MFA_TEST_CREDENTIAL

### Authorised business API and production data

- AGENTGUARD_AUTHORIZED_DATA_JSONL
- AGENTGUARD_AUTHORIZED_DATA_MANIFEST
- AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS
- AGENTGUARD_BUSINESS_API_BASE_URL
- AGENTGUARD_BUSINESS_API_TOKEN
- AGENTGUARD_QUERY_REQUESTER_ACCESS_TOKEN
- AGENTGUARD_REDACTION_SALT_HEX
- AGENTGUARD_REQUESTER_OIDC_AUDIENCE
- AGENTGUARD_REQUESTER_OIDC_ISSUER
- expected_dataset_id_declared
- expected_purpose_declared
- expected_schema_version_declared
- redaction_output_directory_writable
- rollback_or_compensation_declared
- side_effect_test_scope_declared

## Evidence boundary

This preflight proves only that local prerequisites and authorised-input presence are prepared. It does not prove product E2E, production safety, high availability, isolation strength, or performance.

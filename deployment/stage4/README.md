# Stage 4 external-environment preparation

This directory contains non-secret templates for work that cannot honestly be
completed on the local Windows test machine or without organisation-owned
systems, identities and data.

The preflight is deliberately read-only. It does **not** deploy manifests,
authenticate to services, trigger failover, partition networks, restore
snapshots, write business records or read production dataset contents.

## Run

1. Copy `stage4.preflight.example.json` to a local file outside Git and fill
   only non-secret references.
2. Put secrets in the approved secret manager and expose them as the variables
   listed in `stage4.env.example` for the duration of the test.
3. Run:

   ```text
   python scripts/run_stage4_preflight.py --config <local-config.json>
   ```

The command writes:

- `reports/stage4_preflight.json`
- `reports/stage4_preflight.md`

Exit code `2` means an external environment or authorised input is still
missing. That is an expected, truthful preflight result, not a product failure.
Exit code `0` means configuration is prepared for a separately authorised E2E;
it still does not mean the product test passed.
Exit code `1` means the configuration, manifest, hash, field scope or another
fail-closed validation is invalid and must be corrected before execution.

Allowed statuses are limited to:

- `blocked_external_environment`
- `awaiting_authorized_input`
- `configuration_prepared_not_verified`

## Safety boundary

- Never put bearer tokens, passwords, private keys, MFA seeds, LDAP bind
  passwords or redaction salts into the JSON file.
- Do not apply the Kubernetes manifests before selectors, namespaces, DNS,
  certificate authorities and emergency access paths are reviewed.
- Do not use production side effects merely because preflight succeeds.
- Product completion requires the signed acceptance checklist in
  `docs/stage4_external_environment_plan.md` and evidence from the real target
  environment.

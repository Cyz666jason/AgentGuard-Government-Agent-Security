# Kubernetes template boundary

These manifests are reviewable starting points, not a deployment result.

Before applying them, prove that the target CNI enforces NetworkPolicy. Merely
creating a NetworkPolicy object is not sufficient. Confirm the actual workload
labels, ports, DNS implementation, mesh identity, certificate rotation and
emergency access path.

Acceptance requires negative tests from an unauthorised namespace, a pod with
forged labels, a plaintext client, and direct access to protected backends.
Traffic needed by identity, policy, ticket state and approved business adapters
must be added explicitly. Do not add an unrestricted `0.0.0.0/0` egress rule.

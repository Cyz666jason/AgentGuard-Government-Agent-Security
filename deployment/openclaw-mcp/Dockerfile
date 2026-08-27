# syntax=docker/dockerfile:1.7
#
# AgentGuard remote MCP adapter image.
#
# The image contains the protocol/authentication adapter and the existing
# AgentGuard enforcement code.  It deliberately does not contain OpenClaw,
# development identities, or any credential.  Build and publish it with a
# digest-pinned tag in the release pipeline.

FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install only the repository's hash-locked runtime dependencies.  The lock
# file itself is reviewed in Git; no secret or private package index belongs in
# this image build.  ``--require-hashes`` prevents an unreviewed transitive
# upgrade from silently entering a published image.
COPY requirements-full.txt requirements-approval.txt requirements-lock.txt ./
RUN python -m pip install --no-cache-dir --require-hashes --requirement requirements-lock.txt

COPY approval ./approval
COPY config ./config
COPY data ./data
COPY enforcement ./enforcement
COPY identity ./identity
COPY integrations ./integrations
COPY policy ./policy
COPY schemas ./schemas
COPY security_kernel ./security_kernel
COPY service ./service

# A non-root, read-only runtime user.  The state directory is mounted by the
# orchestrator (or backed by an approved external ledger); it is never baked
# into the image.
RUN groupadd --gid 10001 agentguard \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin agentguard \
    && mkdir -p /var/lib/agentguard \
    && chown 10001:10001 /var/lib/agentguard

USER 10001:10001

EXPOSE 8000

# The remote entrypoint is implemented by integrations.openclaw_mcp.  It
# verifies OIDC before creating a request-scoped principal and then hands the
# request to AgentGuard.  TLS termination belongs at the approved ingress;
# this container must never be published as plaintext on the public network.
ENTRYPOINT ["python", "-m", "integrations.openclaw_mcp", "--transport", "streamable-http"]

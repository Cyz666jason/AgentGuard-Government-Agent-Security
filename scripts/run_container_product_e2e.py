"""Run OPA-Envoy and ToolHive product checks when a container runtime exists."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "container_product_e2e_attempt.json"
COMPOSE = ROOT / "deployment" / "product-e2e" / "docker-compose.yml"
REQUEST_BODY = b"{}"
CONTAINERS = (
    "agentguard-product-backend",
    "agentguard-product-opa-envoy",
    "agentguard-product-envoy",
)


def run(command: list[str], *, check: bool = True, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
        env=env,
    )


def issue_ticket(secret: bytes, task_id: str, action_digest: str) -> str:
    now = time.time()
    payload = {
        "jti": uuid.uuid4().hex,
        "task_id": task_id,
        "action_digest": action_digest,
        "iat": round(now, 6),
        "exp": round(now + 30, 6),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    digest = base64.urlsafe_b64encode(
        hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    return f"{encoded}.local-v1:{digest}"


def request_action_digest(method: str, path: str, body: bytes) -> str:
    canonical = json.dumps(
        {
            "method": method,
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def request(
    ticket: str | None = None,
    task_id: str = "container-task",
    path: str = "/internal/tool-adapter/echo",
) -> tuple[int, str]:
    headers = {"Content-Type": "application/json"}
    if ticket:
        headers["X-AgentGuard-Ticket"] = ticket
        headers["X-AgentGuard-Task-ID"] = task_id
    req = urllib.request.Request(
        f"http://127.0.0.1:18081{path}",
        data=REQUEST_BODY,
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def wait_for_envoy() -> None:
    for _ in range(60):
        try:
            request()
            return
        except (OSError, TimeoutError):
            time.sleep(1)
    raise RuntimeError("Envoy did not become reachable")


def raw_docker_up(runtime: str, run_id: str, environment: dict[str, str]) -> str:
    network = f"agentguard-internal-{run_id}"
    edge_network = f"agentguard-edge-{run_id}"
    backend_image = f"agentguard-product-backend:{run_id}"
    run([runtime, "network", "create", "--internal", network], env=environment)
    run([runtime, "network", "create", edge_network], env=environment)
    run(
        [
            runtime,
            "build",
            "-t",
            backend_image,
            str(ROOT / "deployment" / "product-e2e" / "backend"),
        ],
        env=environment,
    )
    common = [
        "--network",
        network,
        "--read-only",
        "--tmpfs",
        "/tmp:noexec,nosuid,size=8m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
    ]
    run(
        [
            runtime,
            "run",
            "-d",
            "--name",
            CONTAINERS[0],
            "--network-alias",
            "backend",
            *common,
            "-e",
            f"AGENTGUARD_CONTAINER_TICKET_SECRET={environment['AGENTGUARD_CONTAINER_TICKET_SECRET']}",
            backend_image,
        ],
        env=environment,
    )
    run(
        [
            runtime,
            "run",
            "-d",
            "--name",
            CONTAINERS[1],
            "--network-alias",
            "opa-envoy",
            *common,
            "-v",
            f"{ROOT / 'deployment' / 'opa-envoy' / 'opa-envoy-config.yaml'}:/config/opa-envoy-config.yaml:ro",
            "-v",
            f"{ROOT / 'deployment' / 'opa-envoy' / 'envoy_guard.rego'}:/policy/envoy_guard.rego:ro",
            "openpolicyagent/opa:1.16.2-envoy@sha256:f854ba5a366b7ff25a6b4598b8e408606cf47a3e39b8c560e9f02b062dd580db",
            "run",
            "--server",
            "--addr=0.0.0.0:8181",
            "--config-file=/config/opa-envoy-config.yaml",
            "/policy/envoy_guard.rego",
        ],
        env=environment,
    )
    run(
        [
            runtime,
            "run",
            "-d",
            "--name",
            CONTAINERS[2],
            *common,
            "-p",
            "127.0.0.1:18081:8081",
            "-v",
            f"{ROOT / 'deployment' / 'product-e2e' / 'envoy.yaml'}:/etc/envoy/envoy.yaml:ro",
            "--entrypoint",
            "/usr/local/bin/envoy",
            "envoyproxy/envoy:v1.38.0@sha256:8146b97ee61a42cd216514709e4e3198af75f014974e3d9f310aef9c901fcbdf",
            "-c",
            "/etc/envoy/envoy.yaml",
        ],
        env=environment,
    )
    # Give only Envoy a route to the host-facing published port.  OPA and the
    # protected backend stay exclusively on the internal network.
    run([runtime, "network", "connect", edge_network, CONTAINERS[2]], env=environment)
    return backend_image


def raw_docker_down(runtime: str, networks: list[str], backend_image: str, environment) -> None:
    for container in reversed(CONTAINERS):
        run([runtime, "rm", "-f", container], check=False, env=environment)
    for network in networks:
        run([runtime, "network", "rm", network], check=False, env=environment)
    if backend_image:
        run([runtime, "image", "rm", backend_image], check=False, env=environment)


def main() -> int:
    run_id = os.environ.get("AGENTGUARD_RUN_ID") or uuid.uuid4().hex[:12]
    runtime = next(
        (name for name in ("docker", "podman") if shutil.which(name)), None
    )
    base = {
        "run_id": run_id,
        "generated_at": datetime.now().astimezone().isoformat(),
        "runtime": runtime,
    }
    if runtime is None or run([runtime, "info"], check=False).returncode != 0:
        report = {
            **base,
            "status": "blocked_external_environment",
            "opa_envoy_container_e2e": False,
            "toolhive_container_e2e": False,
            "reason": "Docker/Podman daemon is unavailable",
        }
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": report["status"], "run_id": run_id}))
        return 2

    compose_available = (
        run([runtime, "compose", "version"], check=False).returncode == 0
    )
    compose = [runtime, "compose", "-f", str(COMPOSE)] if compose_available else []
    checks: dict[str, bool] = {}
    image_digests: dict[str, list[str]] = {}
    image_ids: dict[str, str] = {}
    toolhive_detail = "not_run"
    ticket_secret = secrets.token_bytes(32)
    environment = os.environ.copy()
    environment["AGENTGUARD_CONTAINER_TICKET_SECRET"] = ticket_secret.hex()
    raw_networks: list[str] = []
    raw_backend_image = ""
    failure: dict[str, object] | None = None
    container_diagnostics: dict[str, dict[str, object]] = {}
    try:
        if compose_available:
            run([*compose, "up", "-d", "--build"], env=environment)
        else:
            raw_networks = [
                f"agentguard-internal-{run_id}",
                f"agentguard-edge-{run_id}",
            ]
            raw_backend_image = raw_docker_up(runtime, run_id, environment)
        wait_for_envoy()
        denied_status, _ = request()
        forged_status, _ = request("container-e2e-forged-ticket")
        task_id = f"container-task-{run_id}"
        action_digest = request_action_digest(
            "POST", "/internal/tool-adapter/echo", REQUEST_BODY
        )
        ticket = issue_ticket(ticket_secret, task_id, action_digest)
        allowed_status, allowed_body = request(ticket, task_id)
        replay_status, _ = request(ticket, task_id)
        binding_ticket = issue_ticket(ticket_secret, task_id, action_digest)
        binding_status, _ = request(
            binding_ticket, task_id, "/internal/tool-adapter/different-action"
        )
        checks["request_without_ticket_denied"] = denied_status in {401, 403}
        checks["forged_nonempty_ticket_denied_by_backend"] = forged_status == 403
        checks["signed_bound_ticket_reaches_backend"] = (
            allowed_status == 200 and "backend_reached_through_envoy" in allowed_body
        )
        checks["ticket_replay_denied_by_backend"] = replay_status == 409
        checks["ticket_cannot_authorize_different_action"] = binding_status == 403
        ports = run(
            [runtime, "inspect", "agentguard-product-backend", "--format", "{{json .HostConfig.PortBindings}}"]
        ).stdout.strip()
        checks["backend_has_no_host_port"] = ports in {"null", "{}", ""}
        if compose_available:
            run([*compose, "stop", "opa-envoy"], env=environment)
        else:
            run([runtime, "stop", CONTAINERS[1]], env=environment)
        outage_task_id = f"container-outage-{run_id}"
        outage_digest = request_action_digest(
            "POST", "/internal/tool-adapter/echo", REQUEST_BODY
        )
        outage_ticket = issue_ticket(ticket_secret, outage_task_id, outage_digest)
        outage_status, _ = request(outage_ticket, outage_task_id)
        checks["opa_outage_fails_closed"] = outage_status in {401, 403, 500, 503}
        if compose_available:
            run([*compose, "start", "opa-envoy"], env=environment)
        else:
            run([runtime, "start", CONTAINERS[1]], env=environment)
        for container in CONTAINERS:
            image_id = run(
                [runtime, "inspect", container, "--format", "{{.Image}}"]
            ).stdout.strip()
            image_ids[container] = image_id
            raw = run(
                [runtime, "image", "inspect", image_id, "--format", "{{json .RepoDigests}}"],
                check=False,
            ).stdout.strip()
            image_digests[container] = (
                json.loads(raw) if raw not in {"", "null"} else []
            )
        checks["resolved_external_image_digests_recorded"] = all(
            image_digests.get(container)
            for container in (
                "agentguard-product-opa-envoy",
                "agentguard-product-envoy",
            )
        )
        checks["backend_base_image_pinned_in_dockerfile"] = "@sha256:" in (
            ROOT / "deployment" / "product-e2e" / "backend" / "Dockerfile"
        ).read_text(encoding="utf-8")

        thv = os.environ.get("AGENTGUARD_THV_PATH") or shutil.which("thv")
        if not thv:
            local = ROOT / "third_party" / "runtime" / "toolhive" / "thv.exe"
            thv = str(local) if local.exists() else ""
        if thv:
            workload = f"agentguard-fetch-{run_id}"
            doctor = run([thv, "doctor"], check=False, env=environment)
            started = run(
                [
                    thv,
                    "run",
                    "fetch",
                    "--name",
                    workload,
                    "--isolate-network",
                    "--tools",
                    "fetch",
                    "--enable-audit",
                ],
                check=False,
                env=environment,
            )
            time.sleep(5)
            containers = run([runtime, "ps", "--format", "{{.Names}}"], check=False).stdout
            checks["toolhive_runtime_doctor_passed"] = doctor.returncode == 0
            checks["toolhive_mcp_container_running"] = (
                started.returncode == 0 and workload in containers
            )
            toolhive_detail = f"doctor={doctor.returncode};run={started.returncode};name={workload}"
            run([thv, "stop", workload], check=False, env=environment)
            run([thv, "rm", workload], check=False, env=environment)
        else:
            checks["toolhive_runtime_doctor_passed"] = False
            checks["toolhive_mcp_container_running"] = False
            toolhive_detail = "ToolHive CLI unavailable"
    except Exception as exc:
        failure = {"type": type(exc).__name__, "message": str(exc)}
        for container in CONTAINERS:
            state = run(
                [runtime, "ps", "-a", "--filter", f"name=^{container}$", "--format", "{{.Status}}"],
                check=False,
                env=environment,
            )
            logs = run(
                [runtime, "logs", "--tail", "120", container],
                check=False,
                env=environment,
            )
            container_diagnostics[container] = {
                "status": state.stdout.strip(),
                "logs_tail": (logs.stdout + logs.stderr)[-8000:],
            }
    finally:
        if compose_available:
            run(
                [*compose, "down", "--volumes", "--remove-orphans"],
                check=False,
                env=environment,
            )
        else:
            raw_docker_down(
                runtime, raw_networks, raw_backend_image, environment
            )

    report = {
        **base,
        "status": "passed" if failure is None and all(checks.values()) else "failed",
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "opa_envoy_container_e2e": all(
            checks.get(name, False)
            for name in (
                "request_without_ticket_denied",
                "forged_nonempty_ticket_denied_by_backend",
                "signed_bound_ticket_reaches_backend",
                "ticket_replay_denied_by_backend",
                "ticket_cannot_authorize_different_action",
                "backend_has_no_host_port",
                "opa_outage_fails_closed",
            )
        ),
        "toolhive_container_e2e": checks.get("toolhive_mcp_container_running", False),
        "image_content_ids": image_ids,
        "image_repo_digests": image_digests,
        "toolhive_detail": toolhive_detail,
        "orchestration": "docker_compose" if compose_available else "raw_docker_cli",
        "failure": failure,
        "container_diagnostics": container_diagnostics,
        "boundary": "OPA-Envoy performs fail-closed network authorization; the protected backend independently validates the signed, time-limited, action-bound, one-time ticket.",
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "passed": report["passed"], "total": report["total"], "run_id": run_id}))
    return 0 if failure is None and all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

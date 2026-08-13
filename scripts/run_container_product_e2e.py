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

    compose = [runtime, "compose", "-f", str(COMPOSE)]
    checks: dict[str, bool] = {}
    image_digests: dict[str, list[str]] = {}
    toolhive_detail = "not_run"
    ticket_secret = secrets.token_bytes(32)
    environment = os.environ.copy()
    environment["AGENTGUARD_CONTAINER_TICKET_SECRET"] = ticket_secret.hex()
    try:
        run([*compose, "up", "-d", "--build"], env=environment)
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
        run([*compose, "stop", "opa-envoy"], env=environment)
        outage_task_id = f"container-outage-{run_id}"
        outage_digest = request_action_digest(
            "POST", "/internal/tool-adapter/echo", REQUEST_BODY
        )
        outage_ticket = issue_ticket(ticket_secret, outage_task_id, outage_digest)
        outage_status, _ = request(outage_ticket, outage_task_id)
        checks["opa_outage_fails_closed"] = outage_status in {401, 403, 500, 503}
        run([*compose, "start", "opa-envoy"], env=environment)
        for container in (
            "agentguard-product-backend",
            "agentguard-product-opa-envoy",
            "agentguard-product-envoy",
        ):
            raw = run(
                [runtime, "inspect", container, "--format", "{{json .RepoDigests}}"]
            ).stdout.strip()
            image_digests[container] = json.loads(raw) if raw not in {"", "null"} else []
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
    finally:
        run(
            [*compose, "down", "--volumes", "--remove-orphans"],
            check=False,
            env=environment,
        )

    report = {
        **base,
        "status": "passed" if all(checks.values()) else "failed",
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
        "image_repo_digests": image_digests,
        "toolhive_detail": toolhive_detail,
        "boundary": "OPA-Envoy performs fail-closed network authorization; the protected backend independently validates the signed, time-limited, action-bound, one-time ticket.",
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "passed": report["passed"], "total": report["total"], "run_id": run_id}))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

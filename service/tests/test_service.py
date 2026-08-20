"""服务入口测试：启动、关闭、超时、连接失败、依赖恢复与 fail-closed。"""

from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

from enforcement.tickets import compute_action_digest
from service.app import AgentGuardService
from service.config import ConfigError, load_config
from service.opa_runtime import OpaRuntimeError, ResidentOpaProcess, resolve_opa_binary

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SECRET_HEX = "cd" * 32


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def get_json(url: str, timeout: float = 10.0) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def post_json(
    url: str, payload: dict[str, Any], timeout: float = 20.0
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


class FakeOpaServer:
    """可控的假 OPA：能被关停、能变慢、能返回坏响应，用于探针与恢复测试。"""

    def __init__(self) -> None:
        self.healthy = True
        self.delay_seconds = 0.0
        self.effect = "allow"
        self.malformed = False
        self.decision_calls = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, status: int, payload: Any) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                if outer.delay_seconds:
                    time.sleep(outer.delay_seconds)
                if self.path.startswith("/health"):
                    self._send(200 if outer.healthy else 500, {})
                    return
                self._send(404, {})

            def do_POST(self) -> None:  # noqa: N802
                outer.decision_calls += 1
                if outer.delay_seconds:
                    time.sleep(outer.delay_seconds)
                if not outer.healthy:
                    self._send(500, {"error": "unavailable"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length)) if length else {}
                request = payload.get("input", {})
                if outer.malformed:
                    self._send(200, {"unexpected": True})
                    return
                self._send(
                    200,
                    {
                        "result": {
                            "effect": outer.effect,
                            "allow": outer.effect == "allow",
                            "approval_required": outer.effect == "require_approval",
                            "risk_score": 5,
                            "reason_codes": [],
                            "reasons": [],
                            "required_controls": [],
                            "action_digest": compute_action_digest(request),
                            "policy_version": "fake-0",
                            "audit": {},
                        }
                    },
                )

            def log_message(self, *_: Any) -> None:
                return

        class Server(ThreadingHTTPServer):
            def handle_error(self, request: Any, client_address: Any) -> None:
                # 超时测试里客户端会主动断开，属于预期行为，不打印堆栈。
                return

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> "FakeOpaServer":
        self._thread.start()
        return self

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=3)

    def __enter__(self) -> "FakeOpaServer":
        return self.start()

    def __exit__(self, *_: Any) -> None:
        self.close()


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = TemporaryDirectory()
        self.state_dir = Path(self._temp.name) / "state"
        # 机密只从环境读取，配置与运行期必须看到同一个环境映射。
        patcher = mock.patch.dict(
            os.environ, {"AGENTGUARD_TICKET_SECRET_HEX": SECRET_HEX}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def make_config(self, **overrides: Any):
        base = {
            "port": 0,
            "state_dir": str(self.state_dir),
            "readiness_timeout_seconds": 1.0,
            "shutdown_timeout_seconds": 2.0,
        }
        base.update(overrides)
        return load_config(overrides=base)


class StartupAndShutdownTests(ServiceTestBase):
    def test_service_starts_and_serves_all_endpoints(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                for path in ("/healthz", "/readyz", "/version"):
                    status, payload = get_json(f"{service.base_url}{path}")
                    self.assertEqual(status, 200, f"{path} -> {payload}")
            finally:
                service.close()

    def test_shutdown_stops_accepting_connections(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            url = f"{service.base_url}/healthz"
            self.assertEqual(get_json(url)[0], 200)
            service.close()
            with self.assertRaises(urllib.error.URLError):
                get_json(url, timeout=3)

    def test_close_is_idempotent(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            service.close()
            service.close()  # 不应抛异常

    def test_context_manager_closes_service(self) -> None:
        with FakeOpaServer() as opa:
            config = self.make_config(opa_base_url=opa.base_url)
            with AgentGuardService(config, PROJECT_ROOT) as service:
                url = f"{service.base_url}/healthz"
                self.assertEqual(get_json(url)[0], 200)
            with self.assertRaises(urllib.error.URLError):
                get_json(url, timeout=3)

    def test_state_directory_is_created_on_startup(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            )
            try:
                self.assertTrue(self.state_dir.is_dir())
            finally:
                service.close()


class LivenessVersusReadinessTests(ServiceTestBase):
    def test_healthz_stays_200_while_opa_is_down(self) -> None:
        """存活与就绪必须分离：OPA 挂掉不应让编排系统重启进程。"""

        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                opa.healthy = False
                live_status, live = get_json(f"{service.base_url}/healthz")
                ready_status, ready = get_json(f"{service.base_url}/readyz")
                self.assertEqual(live_status, 200)
                self.assertTrue(live["alive"])
                self.assertEqual(ready_status, 503)
                self.assertFalse(ready["ready"])
                self.assertIn("opa", ready["blocking_dependencies"])
            finally:
                service.close()

    def test_readyz_reports_each_dependency_separately(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                status, ready = get_json(f"{service.base_url}/readyz")
                self.assertEqual(status, 200)
                self.assertEqual(
                    set(ready["dependencies"]),
                    {"opa", "signer", "ticket_state", "identity"},
                )
                for name in ("opa", "signer", "ticket_state"):
                    self.assertTrue(
                        ready["dependencies"][name]["healthy"],
                        ready["dependencies"][name],
                    )
                    self.assertTrue(ready["dependencies"][name]["required"])
                # 未启用 OIDC 时身份不是必需依赖，不应阻塞就绪。
                self.assertFalse(ready["dependencies"]["identity"]["required"])
                self.assertTrue(ready["fail_closed"])
            finally:
                service.close()

    def test_signer_and_ticket_state_are_probed_independently_of_opa(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                opa.healthy = False
                _, ready = get_json(f"{service.base_url}/readyz")
                self.assertFalse(ready["dependencies"]["opa"]["healthy"])
                self.assertTrue(ready["dependencies"]["signer"]["healthy"])
                self.assertTrue(ready["dependencies"]["ticket_state"]["healthy"])
            finally:
                service.close()


class DependencyFailureTests(ServiceTestBase):
    def test_connection_refused_is_reported_as_unavailable(self) -> None:
        closed_port = free_port()
        service = AgentGuardService(
            self.make_config(opa_base_url=f"http://127.0.0.1:{closed_port}"),
            PROJECT_ROOT,
        ).start()
        try:
            status, ready = get_json(f"{service.base_url}/readyz")
            self.assertEqual(status, 503)
            self.assertIn("S001_OPA_UNAVAILABLE", ready["reason_codes"])
        finally:
            service.close()

    def test_slow_dependency_times_out_and_is_not_ready(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(
                    opa_base_url=opa.base_url, readiness_timeout_seconds=0.3
                ),
                PROJECT_ROOT,
            ).start()
            try:
                opa.delay_seconds = 1.5
                status, ready = get_json(f"{service.base_url}/readyz", timeout=20)
                self.assertEqual(status, 503)
                self.assertFalse(ready["dependencies"]["opa"]["healthy"])
            finally:
                opa.delay_seconds = 0.0
                service.close()

    def test_malformed_opa_response_is_not_ready(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                opa.malformed = True
                status, ready = get_json(f"{service.base_url}/readyz")
                self.assertEqual(status, 503)
                self.assertFalse(ready["dependencies"]["opa"]["healthy"])
            finally:
                service.close()

    def test_dependency_recovery_flips_readiness_back(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                self.assertEqual(get_json(f"{service.base_url}/readyz")[0], 200)
                opa.healthy = False
                self.assertEqual(get_json(f"{service.base_url}/readyz")[0], 503)
                opa.healthy = True
                self.assertEqual(get_json(f"{service.base_url}/readyz")[0], 200)
            finally:
                service.close()

    def test_invoke_fails_closed_when_opa_is_unavailable(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                opa.healthy = False
                sample = json.loads(
                    (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(
                        encoding="utf-8"
                    )
                )
                status, result = post_json(f"{service.base_url}/invoke", sample)
                self.assertEqual(status, 503)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(
                    result["reason_code"], "G001_OPA_UNAVAILABLE_FAIL_CLOSED"
                )
                self.assertIsNone(result["receipt"])
            finally:
                service.close()

    def test_identity_unavailable_blocks_invoke_when_oidc_required(self) -> None:
        """启用 OIDC 但 discovery 失败时，/invoke 必须拒绝而不是放行。"""

        with FakeOpaServer() as opa:
            config = self.make_config(
                opa_base_url=opa.base_url,
                oidc_enabled=True,
                oidc_issuer=f"http://127.0.0.1:{free_port()}/realms/absent",
            )
            service = AgentGuardService(config, PROJECT_ROOT).start()
            try:
                self.assertIsNone(service.verifier)
                sample = json.loads(
                    (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(
                        encoding="utf-8"
                    )
                )
                status, result = post_json(f"{service.base_url}/invoke", sample)
                self.assertEqual(status, 503)
                self.assertEqual(result["reason_code"], "S004_IDENTITY_UNAVAILABLE")
            finally:
                service.close()

    def test_identity_is_blocking_when_declared_required(self) -> None:
        with FakeOpaServer() as opa:
            config = self.make_config(
                opa_base_url=opa.base_url,
                oidc_enabled=True,
                oidc_issuer=f"http://127.0.0.1:{free_port()}/realms/absent",
                required_dependencies=("opa", "signer", "ticket_state", "identity"),
            )
            service = AgentGuardService(config, PROJECT_ROOT).start()
            try:
                status, ready = get_json(f"{service.base_url}/readyz")
                self.assertEqual(status, 503)
                self.assertIn("identity", ready["blocking_dependencies"])
                self.assertIn("S004_IDENTITY_UNAVAILABLE", ready["reason_codes"])
            finally:
                service.close()


class InvokeContractTests(ServiceTestBase):
    def test_allow_path_executes_through_gateway(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                sample = json.loads(
                    (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(
                        encoding="utf-8"
                    )
                )
                status, result = post_json(f"{service.base_url}/invoke", sample)
                self.assertEqual(status, 200, result)
                self.assertEqual(result["status"], "executed_isolated")
                self.assertIn("sandbox", result["receipt"])
            finally:
                service.close()

    def test_require_approval_returns_pending_not_execution(self) -> None:
        with FakeOpaServer() as opa:
            opa.effect = "require_approval"
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                sample = json.loads(
                    (PROJECT_ROOT / "samples" / "require_approval.json").read_text(
                        encoding="utf-8"
                    )
                )
                status, result = post_json(f"{service.base_url}/invoke", sample)
                self.assertEqual(status, 202)
                self.assertEqual(result["status"], "pending_approval")
                self.assertIsNone(result["receipt"])
            finally:
                service.close()

    def test_deny_effect_is_blocked(self) -> None:
        with FakeOpaServer() as opa:
            opa.effect = "deny"
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                sample = json.loads(
                    (PROJECT_ROOT / "samples" / "deny_dangerous_command.json").read_text(
                        encoding="utf-8"
                    )
                )
                status, result = post_json(f"{service.base_url}/invoke", sample)
                self.assertEqual(status, 403)
                self.assertEqual(result["reason_code"], "G002_POLICY_DENY")
            finally:
                service.close()

    def test_invalid_json_body_is_rejected(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                request = urllib.request.Request(
                    f"{service.base_url}/invoke",
                    data=b"{not json",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(request, timeout=10)
                self.assertEqual(caught.exception.code, 400)
                self.assertEqual(
                    json.load(caught.exception)["reason_code"], "S022_INVALID_JSON"
                )
            finally:
                service.close()

    def test_oversized_body_is_rejected_before_policy_evaluation(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                before = opa.decision_calls
                connection = http.client.HTTPConnection(
                    "127.0.0.1", service.port, timeout=10
                )
                try:
                    connection.putrequest("POST", "/invoke")
                    connection.putheader("Content-Type", "application/json")
                    connection.putheader("Content-Length", str(1024 * 1024 + 10))
                    connection.endheaders()
                    response = connection.getresponse()
                    self.assertEqual(response.status, 413)
                    self.assertEqual(
                        json.load(response)["reason_code"],
                        "S021_REQUEST_SIZE_REJECTED",
                    )
                finally:
                    connection.close()
                self.assertEqual(opa.decision_calls, before)
            finally:
                service.close()

    def test_unknown_path_returns_404(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                self.assertEqual(get_json(f"{service.base_url}/nope")[0], 404)
                self.assertEqual(
                    post_json(f"{service.base_url}/nope", {"a": 1})[0], 404
                )
            finally:
                service.close()


class VersionEndpointTests(ServiceTestBase):
    def test_version_exposes_mode_without_secrets(self) -> None:
        with FakeOpaServer() as opa:
            service = AgentGuardService(
                self.make_config(opa_base_url=opa.base_url), PROJECT_ROOT
            ).start()
            try:
                status, payload = get_json(f"{service.base_url}/version")
                self.assertEqual(status, 200)
                self.assertEqual(payload["opa_mode"], "rest")
                self.assertEqual(payload["policy_version"], "0.1.0")
                self.assertTrue(payload["performance_representative"])
                self.assertEqual(
                    payload["ticket_secret_source"], "environment_variable"
                )
                self.assertFalse(payload["secret_values_recorded"])
                self.assertNotIn(SECRET_HEX, json.dumps(payload))
            finally:
                service.close()

    def test_cli_mode_version_marks_result_not_performance_representative(self) -> None:
        service = AgentGuardService(self.make_config(opa_mode="cli"), PROJECT_ROOT).start()
        try:
            _, payload = get_json(f"{service.base_url}/version")
            self.assertEqual(payload["opa_mode"], "cli")
            self.assertFalse(payload["performance_representative"])
            self.assertIn("不是生产性能结果", payload["performance_note"])
        finally:
            service.close()


class ResidentOpaProcessTests(ServiceTestBase):
    """真实拉起 tools/opa 常驻进程，验证启动与关闭。"""

    def setUp(self) -> None:
        super().setUp()
        candidates = [PROJECT_ROOT / "tools" / name for name in ("opa.exe", "opa")]
        if not any(path.is_file() for path in candidates):
            self.skipTest("未找到 tools/opa(.exe)，跳过常驻 OPA 进程测试")

    def test_service_manages_resident_opa_lifecycle(self) -> None:
        port = free_port()
        config = self.make_config(
            opa_base_url=f"http://127.0.0.1:{port}",
            manage_opa_process=True,
            opa_startup_timeout_seconds=40.0,
        )
        service = AgentGuardService(config, PROJECT_ROOT).start()
        try:
            status, ready = get_json(f"{service.base_url}/readyz", timeout=20)
            self.assertEqual(status, 200, ready)
            self.assertTrue(ready["dependencies"]["opa"]["healthy"])
            _, version = get_json(f"{service.base_url}/version")
            self.assertTrue(version["opa_managed_by_service"])
        finally:
            service.close()
        # 关闭后常驻 OPA 端口必须不再监听。
        with socket.socket() as probe:
            probe.settimeout(2)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)

    def test_real_opa_returns_three_state_decision_through_invoke(self) -> None:
        port = free_port()
        config = self.make_config(
            opa_base_url=f"http://127.0.0.1:{port}",
            manage_opa_process=True,
            opa_startup_timeout_seconds=40.0,
        )
        service = AgentGuardService(config, PROJECT_ROOT).start()
        try:
            allow_sample = json.loads(
                (PROJECT_ROOT / "samples" / "allow_low_risk.json").read_text(
                    encoding="utf-8"
                )
            )
            status, result = post_json(f"{service.base_url}/invoke", allow_sample)
            self.assertEqual(status, 200, result)
            self.assertEqual(result["status"], "executed_isolated")

            deny_sample = json.loads(
                (PROJECT_ROOT / "samples" / "deny_dangerous_command.json").read_text(
                    encoding="utf-8"
                )
            )
            status, result = post_json(f"{service.base_url}/invoke", deny_sample)
            self.assertEqual(status, 403)
            self.assertEqual(result["reason_code"], "G002_POLICY_DENY")
        finally:
            service.close()

    def test_unbindable_address_reports_startup_failure(self) -> None:
        """OPA 无法绑定时必须报错，不能静默当成已就绪。"""

        resident = ResidentOpaProcess(
            PROJECT_ROOT,
            address="300.300.300.300:8181",  # 非法 IPv4，OPA 会启动失败退出
            startup_timeout_seconds=8.0,
        )
        try:
            with self.assertRaises(OpaRuntimeError) as caught:
                resident.start()
            self.assertIn(
                caught.exception.code,
                {"S011_OPA_PROCESS_EXITED", "S012_OPA_STARTUP_TIMEOUT"},
            )
        finally:
            resident.stop()

    def test_missing_binary_is_reported(self) -> None:
        with self.assertRaises(OpaRuntimeError) as caught:
            resolve_opa_binary(PROJECT_ROOT, configured=str(self.state_dir / "absent-opa"))
        self.assertEqual(caught.exception.code, "S010_OPA_BINARY_MISSING")

    def test_stop_before_start_is_safe(self) -> None:
        resident = ResidentOpaProcess(PROJECT_ROOT, address="127.0.0.1:8181")
        resident.stop()  # 不应抛异常
        self.assertIsNone(resident.process)


if __name__ == "__main__":
    unittest.main()

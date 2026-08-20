"""AgentGuard 网关服务：稳定、可配置的应用启动入口。

对外暴露：

* ``GET  /healthz``  存活探针——只回答进程是否在跑、配置是否已加载；
* ``GET  /readyz``   就绪探针——真实往返 OPA、签名服务、票据状态服务；
* ``GET  /version``  版本与运行模式（不含任何机密）；
* ``POST /invoke``   工具调用强制执行点，复用现有 ``EnforcementGateway``。

本模块**不重写**任何安全逻辑：决策、签票、核销、沙箱与审计仍由
``enforcement.EnforcementGateway`` 完成，这里只补上进程生命周期、配置与探针。
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from approval.credentials import ApprovalCredentialService, SQLiteApprovalLedger
from enforcement import build_gateway
from enforcement.ledgers import OpenBaoKvTicketLedger
from enforcement.signers import HmacKeyringSigner, OpenBaoTransitSigner
from identity import OidcIdentityError, OidcVerifier

from .config import (
    PROJECT_ROOT,
    ConfigError,
    ServiceConfig,
    load_config,
    resolve_openbao_token,
    resolve_ticket_secret,
)
from .health import DependencyProbes, liveness
from .opa_runtime import ResidentOpaProcess, build_opa_client

MAX_REQUEST_BYTES = 1024 * 1024


class _GatewayHttpServer(ThreadingHTTPServer):
    """客户端中途断开不是服务故障，不应打印堆栈或影响其他请求。

    探针超时、编排系统取消请求、负载均衡器回收连接都会产生
    ``ConnectionAbortedError``/``ConnectionResetError``。这些必须被安静吞掉；
    其他异常仍交给标准实现记录，避免掩盖真实错误。
    """

    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def _policy_version(project_root: Path, relative: str) -> str:
    path = project_root / relative
    if not path.is_file():
        return "unknown"
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("policy_version"):
            _, _, value = stripped.partition(":=")
            return value.strip().strip('"') or "unknown"
    return "unknown"


def _git_commit(project_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except (OSError, ValueError):
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    return (completed.stdout or "").strip() or "unknown"


class AgentGuardService:
    """网关服务的生命周期容器：装配依赖、启动/停止 HTTP 服务、暴露探针。"""

    def __init__(
        self,
        config: ServiceConfig | None = None,
        project_root: Path | str = PROJECT_ROOT,
        opa_client: Any | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        # 机密来源与配置来源必须是同一个环境映射，否则会出现"配置说有密钥、
        # 运行期又读不到"的不一致。默认使用真实进程环境。
        self.environ: Mapping[str, str] = os.environ if environ is None else environ
        self.config = config or load_config(self.environ)
        self.project_root = Path(project_root)
        self.started_at = time.monotonic()
        self.started_at_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._resident_opa: ResidentOpaProcess | None = None
        self._closed = False

        state_dir = self.config.state_path
        state_dir.mkdir(parents=True, exist_ok=True)

        # 常驻 OPA：可选由服务自己拉起，便于单机部署与演示。
        if self.config.manage_opa_process and self.config.opa_mode == "rest":
            address = self.config.opa_base_url.split("://", 1)[-1]
            self._resident_opa = ResidentOpaProcess(
                self.project_root,
                address,
                binary=self.config.opa_binary,
                startup_timeout_seconds=self.config.opa_startup_timeout_seconds,
            ).start()

        if opa_client is not None:
            self.opa_client = opa_client
            self.performance_note = "由调用方注入的 OPA 客户端"
        else:
            self.opa_client, self.performance_note = build_opa_client(
                self.config, self.project_root
            )

        self.signer, self.ledger, self.approval_service = self._build_crypto(state_dir)
        self.verifier = self._build_verifier()
        self.gateway = build_gateway(
            state_dir,
            project_root=self.project_root,
            opa_client=self.opa_client,
            enable_local_adapters=self.config.enable_local_adapters,
            signer=self.signer,
            ledger=self.ledger,
            approval_service=self.approval_service,
        )
        self.probes = DependencyProbes(
            self.config,
            opa_client=self.opa_client,
            signer=self.signer,
            ticket_store=self.gateway.tickets,
            verifier=self.verifier,
        )

    # ----------------------------------------------------------- assembly

    def _build_crypto(
        self, state_dir: Path
    ) -> tuple[Any, Any | None, ApprovalCredentialService | None]:
        if self.config.signer_mode == "openbao_transit":
            token = resolve_openbao_token(self.environ)
            signer = OpenBaoTransitSigner(
                self.config.openbao_address,
                token,
                key_name=self.config.openbao_key_name,
                mount=self.config.openbao_mount,
                namespace=self.config.openbao_namespace or None,
                timeout_seconds=self.config.openbao_timeout_seconds,
            )
            ledger = OpenBaoKvTicketLedger(
                self.config.openbao_address,
                token,
                namespace=self.config.openbao_namespace or None,
                timeout_seconds=self.config.openbao_timeout_seconds,
            )
            return signer, ledger, None

        secret, _ = resolve_ticket_secret(self.environ)
        if secret is None:  # load_config 已经拦截；这里是纵深防御
            raise ConfigError(
                "C008_TICKET_SECRET_REQUIRED", "缺少票据签名机密，服务拒绝启动"
            )
        signer = HmacKeyringSigner.single_key(secret)
        approval_secret = hashlib.sha256(b"agentguard-approval-v1\0" + secret).digest()
        approval_service = ApprovalCredentialService(
            HmacKeyringSigner.single_key(approval_secret),
            SQLiteApprovalLedger(state_dir / "approval_credentials.sqlite"),
        )
        return signer, None, approval_service

    def _build_verifier(self) -> OidcVerifier | None:
        if not self.config.oidc_enabled:
            return None
        try:
            return OidcVerifier(
                self.config.oidc_issuer,
                self.config.oidc_audience,
                require_mfa=self.config.oidc_require_mfa,
                timeout_seconds=self.config.oidc_timeout_seconds,
            )
        except OidcIdentityError:
            # 身份服务暂时不可用不应让进程崩溃：/readyz 会报告不可用，
            # /invoke 在启用 OIDC 时一律拒绝（fail-closed）。
            return None

    # ------------------------------------------------------------ payload

    def version_payload(self) -> dict[str, Any]:
        return {
            "service": self.config.service_name,
            "version": self.config.service_version,
            "policy_version": _policy_version(
                self.project_root, self.config.policy_version_path
            ),
            "commit": _git_commit(self.project_root),
            "started_at": self.started_at_utc,
            "uptime_seconds": round(time.monotonic() - self.started_at, 3),
            "opa_mode": self.config.opa_mode,
            "opa_managed_by_service": self._resident_opa is not None,
            "signer_mode": self.config.signer_mode,
            "ticket_secret_source": self.config.ticket_secret_source,
            "oidc_enabled": self.config.oidc_enabled,
            "performance_representative": self.config.performance_representative,
            "performance_note": self.performance_note,
            "configuration": self.config.redacted(),
            "secret_values_recorded": False,
        }

    def invoke(
        self, request: Mapping[str, Any], authorization_header: str | None
    ) -> dict[str, Any]:
        """强制执行入口。身份服务不可用时 fail-closed。"""

        if self.config.oidc_enabled:
            if self.verifier is None:
                return {
                    "status": "blocked",
                    "http_status": 503,
                    "reason_code": "S004_IDENTITY_UNAVAILABLE",
                    "message": "身份服务不可用，默认拒绝",
                    "receipt": None,
                }
            return self.gateway.invoke_authenticated(
                request, authorization_header, self.verifier
            )
        return self.gateway.invoke(request)

    # ------------------------------------------------------------ server

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = f"{service.config.service_name}/{service.config.service_version}"
            sys_version = ""

            def _send(self, status: int, payload: Mapping[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
                if self.path in {"/healthz", "/health"}:
                    self._send(200, liveness(service.config, service.started_at))
                    return
                if self.path == "/readyz":
                    readiness = service.probes.readiness()
                    self._send(200 if readiness["ready"] else 503, readiness)
                    return
                if self.path == "/version":
                    self._send(200, service.version_payload())
                    return
                self._send(404, {"status": "not_found", "path": self.path})

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/invoke":
                    self._send(404, {"status": "not_found", "path": self.path})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self._send(
                        400,
                        {
                            "status": "blocked",
                            "reason_code": "S020_BAD_CONTENT_LENGTH",
                            "message": "Content-Length 无效",
                        },
                    )
                    return
                if length <= 0 or length > MAX_REQUEST_BYTES:
                    self._send(
                        413 if length > MAX_REQUEST_BYTES else 400,
                        {
                            "status": "blocked",
                            "reason_code": "S021_REQUEST_SIZE_REJECTED",
                            "message": "请求体为空或超过 1 MiB",
                        },
                    )
                    return
                try:
                    payload = json.loads(self.rfile.read(length))
                except json.JSONDecodeError:
                    self._send(
                        400,
                        {
                            "status": "blocked",
                            "reason_code": "S022_INVALID_JSON",
                            "message": "请求体不是合法 JSON",
                        },
                    )
                    return
                if not isinstance(payload, dict):
                    self._send(
                        400,
                        {
                            "status": "blocked",
                            "reason_code": "S022_INVALID_JSON",
                            "message": "请求体必须是 JSON 对象",
                        },
                    )
                    return
                try:
                    result = service.invoke(payload, self.headers.get("Authorization"))
                except Exception as exc:
                    # 任何未预期异常都必须默认拒绝，不允许落到"放行"。
                    self._send(
                        503,
                        {
                            "status": "blocked",
                            "http_status": 503,
                            "reason_code": "S023_GATEWAY_INTERNAL_FAIL_CLOSED",
                            "message": f"{type(exc).__name__}",
                            "receipt": None,
                        },
                    )
                    return
                self._send(int(result.get("http_status", 500)), result)

            def log_message(self, format: str, *args: Any) -> None:
                return

        return Handler

    def start(self) -> "AgentGuardService":
        if self._server is not None:
            return self
        self._server = _GatewayHttpServer(
            (self.config.host, self.config.port), self._handler_class()
        )
        self._server.timeout = self.config.request_timeout_seconds
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"{self.config.service_name}-http",
            daemon=True,
        )
        self._thread.start()
        return self

    @property
    def port(self) -> int:
        if self._server is None:
            return self.config.port
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://{self.config.host}:{self.port}"

    def serve_forever(self) -> None:
        self.start()
        assert self._thread is not None
        server_thread = self._thread
        try:
            while server_thread.is_alive():
                server_thread.join(timeout=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self) -> None:
        """有序关闭：先停止接受请求，再释放常驻 OPA 进程。"""

        if self._closed:
            return
        self._closed = True
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=self.config.shutdown_timeout_seconds)
            self._thread = None
        if self._resident_opa is not None:
            self._resident_opa.stop()
            self._resident_opa = None

    def __enter__(self) -> "AgentGuardService":
        return self.start()

    def __exit__(self, *_: Any) -> None:
        self.close()

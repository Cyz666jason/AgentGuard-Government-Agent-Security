"""本机网络级强制执行链路：HTTP 网关 -> 受保护工具后端。"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

from identity import OidcIdentityError, OidcVerifier

from .gateway import EnforcementGateway


class OpaRestClient:
    """调用常驻 OPA REST API，避免逐请求启动 CLI。"""

    def __init__(self, base_url: str = "http://127.0.0.1:8181", timeout: float = 3.0) -> None:
        self.url = f"{base_url.rstrip('/')}/v1/data/agent/guard/decision"
        self.timeout = timeout

    def decide(self, request: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps({"input": request}, ensure_ascii=False).encode("utf-8")
        http_request = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(http_request, timeout=self.timeout) as response:
            payload = json.load(response)
        result = payload.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("OPA REST 响应缺少 decision result")
        return result


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0 or length > 1024 * 1024:
        raise ValueError("请求体为空或过大")
    payload = json.loads(handler.rfile.read(length))
    if not isinstance(payload, dict):
        raise ValueError("请求体必须是 JSON 对象")
    return payload


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: Mapping[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class HttpEnforcementStack:
    """在两个独立 loopback 端口启动网关与受票据保护的工具后端。"""

    def __init__(
        self,
        gateway: EnforcementGateway,
        verifier: OidcVerifier | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.gateway = gateway
        self.verifier = verifier
        backend_gateway = gateway

        class BackendHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/internal/dispatch":
                    _write_json(self, 404, {"status": "not_found"})
                    return
                try:
                    request = _read_json(self)
                    result = backend_gateway.dispatch(
                        request, self.headers.get("X-AgentGuard-Ticket")
                    )
                    _write_json(self, int(result.get("http_status", 500)), result)
                except Exception as exc:
                    _write_json(self, 400, {"status": "blocked", "message": str(exc)})

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.backend_server = ThreadingHTTPServer((host, 0), BackendHandler)
        self.backend_url = f"http://{host}:{self.backend_server.server_port}"
        outer = self

        class GatewayHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/invoke":
                    _write_json(self, 404, {"status": "not_found"})
                    return
                try:
                    request = _read_json(self)
                    if outer.verifier is not None:
                        try:
                            request = outer.verifier.authenticate_request(
                                request, self.headers.get("Authorization")
                            )
                        except OidcIdentityError as exc:
                            _write_json(
                                self,
                                401,
                                {
                                    "status": "blocked",
                                    "http_status": 401,
                                    "reason_code": exc.code,
                                    "message": str(exc),
                                    "receipt": None,
                                },
                            )
                            return
                    authorization = outer.gateway.authorize(request)
                    if authorization.get("status") != "authorized":
                        _write_json(
                            self, int(authorization.get("http_status", 500)), authorization
                        )
                        return
                    body = json.dumps(request, ensure_ascii=False).encode("utf-8")
                    backend_request = urllib.request.Request(
                        f"{outer.backend_url}/internal/dispatch",
                        data=body,
                        headers={
                            "Content-Type": "application/json",
                            "X-AgentGuard-Ticket": str(authorization["ticket"]),
                        },
                    )
                    try:
                        with urllib.request.urlopen(backend_request, timeout=5) as response:
                            result = json.load(response)
                    except urllib.error.HTTPError as exc:
                        result = json.load(exc)
                    _write_json(self, int(result.get("http_status", 500)), result)
                except Exception as exc:
                    _write_json(
                        self,
                        500,
                        {
                            "status": "blocked",
                            "http_status": 500,
                            "reason_code": "G010_HTTP_GATEWAY_ERROR",
                            "message": str(exc),
                            "receipt": None,
                        },
                    )

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.gateway_server = ThreadingHTTPServer((host, 0), GatewayHandler)
        self.gateway_url = f"http://{host}:{self.gateway_server.server_port}"
        self._threads: list[threading.Thread] = []

    def start(self) -> "HttpEnforcementStack":
        for server, name in (
            (self.backend_server, "agentguard-backend"),
            (self.gateway_server, "agentguard-gateway"),
        ):
            thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def close(self) -> None:
        for server in (self.gateway_server, self.backend_server):
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=3)

    def __enter__(self) -> "HttpEnforcementStack":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def post_json(url: str, payload: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", **dict(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)

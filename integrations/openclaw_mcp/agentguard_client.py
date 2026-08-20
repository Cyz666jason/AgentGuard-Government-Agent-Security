"""Narrow HTTP client that can call only AgentGuard's enforcement endpoint."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from .config import AdapterConfig, AdapterConfigError


class AgentGuardClientError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise AgentGuardClientError(
            "MCP_G004_REDIRECT_BLOCKED", "AgentGuard 地址返回重定向，已默认拒绝"
        )


class AgentGuardClient:
    """Calls one fixed REST route; it has no direct business-system capability."""

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config
        ssl_context = ssl.create_default_context(cafile=config.ca_bundle or None)
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(context=ssl_context),
            _NoRedirect(),
        )

    @staticmethod
    def _business_hours() -> bool:
        now = datetime.now().astimezone()
        return now.weekday() < 5 and 8 <= now.hour < 18

    def _request_payload(self, limit: int) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        call_id = uuid.uuid4().hex
        return {
            "request_id": f"mcp-req-{call_id}",
            "task_id": f"mcp-task-{call_id}",
            "timestamp": now,
            "subject": self.config.request_subject(),
            "action": {
                "tool": "database.query",
                "operation": "query",
                "resource": "db://public/notices",
                "parameters": {"limit": limit, "item_count": limit},
                "risk_level": "low",
                "data_level": "internal",
            },
            "context": {
                "source": "mcp",
                "server_time": now,
                "destination_zone": "internal",
                "enforcement_point": "gateway",
                "business_hours": self._business_hours(),
                "repeat_count": 0,
                "mcp_adapter": "agentguard-openclaw-readonly",
            },
            "environment": {"sandbox": {"enabled": False, "profile": ""}},
            "approval": {},
        }

    def list_notices(self, limit: int) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise AgentGuardClientError(
                "MCP_G001_ARGUMENT_INVALID", "limit 必须是 1 到 100 的整数"
            )
        try:
            token = self.config.authorization_token()
            payload = self._request_payload(limit)
        except AdapterConfigError as exc:
            raise AgentGuardClientError(exc.code, str(exc)) from exc
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": "AgentGuard-OpenClaw-MCP/0.1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.config.invoke_url,
            data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            ),
            headers=headers,
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read(self.config.max_response_bytes + 1)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            raw = exc.read(self.config.max_response_bytes + 1)
            status = int(exc.code)
        except AgentGuardClientError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AgentGuardClientError(
                "MCP_G002_AGENTGUARD_UNAVAILABLE",
                f"AgentGuard 不可用，调用未执行（{type(exc).__name__}）",
            ) from exc
        if len(raw) > self.config.max_response_bytes:
            raise AgentGuardClientError(
                "MCP_G003_RESPONSE_TOO_LARGE", "AgentGuard 响应超过安全上限"
            )
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentGuardClientError(
                "MCP_G005_INVALID_RESPONSE", "AgentGuard 返回了无效 JSON"
            ) from exc
        if not isinstance(result, dict):
            raise AgentGuardClientError(
                "MCP_G005_INVALID_RESPONSE", "AgentGuard 响应必须是 JSON 对象"
            )
        result["_agentguard_http_status"] = status
        return result

"""Fail-closed HTTP adapter for authorized pre-production business APIs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class ProductionAdapterError(RuntimeError):
    pass


class ProductionOutcomeUnknownError(ProductionAdapterError):
    """The remote write may have committed; reconcile before any retry."""

    outcome_unknown = True

    def __init__(self, idempotency_key: str, endpoint_host: str) -> None:
        super().__init__("业务写操作结果未知，禁止自动重试，必须按幂等键查询对账")
        self.idempotency_key = idempotency_key
        self.endpoint_host = endpoint_host


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirects are blocked so an allowlisted host cannot bounce to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProductionAdapterError("业务API禁止HTTP重定向")


@dataclass(frozen=True)
class ProductionApiConfig:
    base_url: str
    bearer_token: str
    allowed_hosts: tuple[str, ...]
    ca_bundle: str | None = None
    timeout_seconds: float = 5.0
    environment: str = "unconfigured"
    allow_side_effects: bool = False
    max_write_amount: float = 0.0

    @classmethod
    def from_environment(cls) -> "ProductionApiConfig":
        base_url = os.environ.get("AGENTGUARD_BUSINESS_API_BASE_URL", "")
        token = os.environ.get("AGENTGUARD_BUSINESS_API_TOKEN", "")
        allowed_hosts = tuple(
            host.strip().lower()
            for host in os.environ.get("AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        )
        if not base_url or not token or not allowed_hosts:
            raise ProductionAdapterError(
                "真实业务适配器未配置：需要BASE_URL、TOKEN和ALLOWED_HOSTS"
            )
        environment = os.environ.get("AGENTGUARD_BUSINESS_ENVIRONMENT", "").lower()
        write_confirmation = os.environ.get(
            "AGENTGUARD_ALLOW_PRODUCTION_SIDE_EFFECTS", ""
        )
        allow_side_effects = (
            environment == "preproduction"
            and write_confirmation
            == "I_UNDERSTAND_AND_AUTHORIZE_PREPRODUCTION_WRITES"
        )
        return cls(
            base_url=base_url,
            bearer_token=token,
            allowed_hosts=allowed_hosts,
            ca_bundle=os.environ.get("AGENTGUARD_BUSINESS_API_CA_BUNDLE") or None,
            timeout_seconds=float(
                os.environ.get("AGENTGUARD_BUSINESS_API_TIMEOUT_SECONDS", "5")
            ),
            environment=environment or "unconfigured",
            allow_side_effects=allow_side_effects,
            max_write_amount=float(
                os.environ.get("AGENTGUARD_BUSINESS_MAX_WRITE_AMOUNT", "0")
            ),
        )


class ProductionHttpBusinessAdapter:
    """HTTPS-only adapter with host/IP allowlists and idempotency binding."""

    def __init__(self, config: ProductionApiConfig) -> None:
        parsed = urllib.parse.urlparse(config.base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ProductionAdapterError("真实业务API必须使用HTTPS绝对地址")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ProductionAdapterError("base URL不能包含凭据、查询串或片段")
        hostname = parsed.hostname.lower()
        if hostname not in config.allowed_hosts:
            raise ProductionAdapterError("业务API主机不在显式白名单")
        self.config = config
        self.hostname = hostname
        self._validate_resolution(hostname)
        self.ssl_context = ssl.create_default_context(cafile=config.ca_bundle)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ssl_context),
            NoRedirectHandler(),
        )

    @staticmethod
    def _validate_resolution(hostname: str) -> None:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
        except socket.gaierror as exc:
            raise ProductionAdapterError("业务API主机无法解析") from exc
        for raw in addresses:
            address = ipaddress.ip_address(raw)
            if (
                address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
            ):
                raise ProductionAdapterError("业务API解析到禁止的本机或特殊地址")

    @staticmethod
    def _idempotency_key(request: Mapping[str, Any]) -> str:
        task_id = str(request.get("task_id", ""))
        action = request.get("action", {})
        canonical = json.dumps(
            {"task_id": task_id, "action": action},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        action = request.get("action", {})
        key = (str(action.get("tool", "")), str(action.get("operation", "")))
        routes = {
            ("database.query", "query"): ("GET", "/v1/notices/query", False),
            ("payment.transfer", "transfer"): ("POST", "/v1/payments", True),
        }
        if key not in routes:
            raise ProductionAdapterError("真实业务适配器未注册该工具操作")
        method, path, side_effect = routes[key]
        if side_effect and request.get("approval", {}).get("status") != "approved":
            raise ProductionAdapterError("生产写操作必须携带已批准凭证")
        if side_effect and not self.config.allow_side_effects:
            raise ProductionAdapterError(
                "预生产写操作未取得双重显式授权，当前适配器保持只读"
            )
        amount = action.get("parameters", {}).get("amount", 0)
        if side_effect:
            try:
                numeric_amount = float(amount)
            except (TypeError, ValueError) as exc:
                raise ProductionAdapterError("写操作金额格式无效") from exc
            if numeric_amount <= 0 or numeric_amount > self.config.max_write_amount:
                raise ProductionAdapterError("写操作金额超过预先授权上限")
        payload = {
            "task_id": request.get("task_id", ""),
            "resource": action.get("resource", ""),
            "parameters": action.get("parameters", {}),
        }
        url = urllib.parse.urljoin(self.config.base_url.rstrip("/") + "/", path.lstrip("/"))
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname is None or parsed.hostname.lower() != self.hostname:
            raise ProductionAdapterError("业务API路径发生主机跳转")
        data = None if method == "GET" else json.dumps(payload).encode("utf-8")
        if method == "GET":
            url += "?" + urllib.parse.urlencode(
                {"limit": action.get("parameters", {}).get("limit", 20)}
            )
        idempotency_key = self._idempotency_key(request)
        api_request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.config.bearer_token}",
                "Content-Type": "application/json",
                "Idempotency-Key": idempotency_key,
                "X-AgentGuard-Task-ID": str(request.get("task_id", "")),
            },
        )
        try:
            self._validate_resolution(self.hostname)
            with self.opener.open(
                api_request,
                timeout=self.config.timeout_seconds,
            ) as response:
                body = json.loads(response.read().decode("utf-8"))
                status = response.status
        except urllib.error.HTTPError as exc:
            if side_effect and exc.code >= 500:
                raise ProductionOutcomeUnknownError(
                    idempotency_key, self.hostname
                ) from exc
            raise ProductionAdapterError(
                f"业务API明确拒绝请求：HTTP {exc.code}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if side_effect:
                raise ProductionOutcomeUnknownError(
                    idempotency_key, self.hostname
                ) from exc
            raise ProductionAdapterError(
                f"业务API调用失败并默认拒绝：{type(exc).__name__}"
            ) from exc
        except ProductionAdapterError as exc:
            if side_effect and "重定向" in str(exc):
                raise ProductionOutcomeUnknownError(
                    idempotency_key, self.hostname
                ) from exc
            raise
        if status < 200 or status >= 300:
            raise ProductionAdapterError(f"业务API拒绝请求：HTTP {status}")
        return {
            "adapter": "authorized_production_https_api",
            "endpoint_host": self.hostname,
            "http_status": status,
            "side_effect": side_effect,
            "idempotency_key": idempotency_key,
            "response": body,
        }


def production_credentials_present() -> bool:
    required = {
        "AGENTGUARD_BUSINESS_API_BASE_URL",
        "AGENTGUARD_BUSINESS_API_TOKEN",
        "AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS",
    }
    return all(os.environ.get(name) for name in required)

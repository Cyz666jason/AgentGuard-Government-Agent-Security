"""依赖可用性探针：区分"进程存活"与"依赖服务可用"。

* ``/healthz`` 只回答"进程是否还在跑、配置是否已加载"，不触碰外部依赖，
  因此不会因为 OPA 抖动而被编排系统重启。
* ``/readyz`` 真实往返 OPA、签名服务和票据状态服务；任一必需依赖不可用即
  返回 503，调用方不应再把流量导入该实例（fail-closed）。
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping


#: 只读的就绪探测输入。故意使用未注册工具，策略会返回 deny——
#: 我们只需要证明"策略已加载且能算出决定"，不需要它放行任何东西。
READINESS_CANARY_ACTION = {
    "tool": "agentguard.readiness_probe",
    "operation": "probe",
    "resource": "agentguard/readyz",
    "parameters": {},
    "risk_level": "low",
    "data_level": "public",
}

VALID_EFFECTS = {"allow", "require_approval", "deny"}


def readiness_canary() -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "request_id": "agentguard-readyz-probe",
        "task_id": "agentguard-readyz-probe",
        "timestamp": now,
        "subject": {
            "id": "agentguard-readyz-probe",
            "type": "service_account",
            "department": "platform_ops",
            "roles": ["readiness_probe"],
            "clearance": 0,
            "mfa": False,
        },
        "action": dict(READINESS_CANARY_ACTION),
        "context": {
            "source": "readiness_probe",
            "destination_zone": "internal",
            "enforcement_point": "gateway",
            "business_hours": True,
            "repeat_count": 0,
        },
        "environment": {"sandbox": {"enabled": True, "profile": "readiness_probe"}},
        "approval": {},
    }


@dataclass(frozen=True)
class ProbeResult:
    name: str
    healthy: bool
    required: bool
    detail: str
    latency_ms: float
    checked_at: str
    reason_code: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "healthy": self.healthy,
            "required": self.required,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
            "checked_at": self.checked_at,
        }
        if self.reason_code:
            payload["reason_code"] = self.reason_code
        return payload


def _timed(
    name: str, required: bool, probe: Callable[[], str], reason_code: str
) -> ProbeResult:
    started = time.perf_counter()
    checked_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    try:
        detail = probe()
    except Exception as exc:  # 探针必须吞掉异常并转成"不可用"
        return ProbeResult(
            name=name,
            healthy=False,
            required=required,
            detail=f"{type(exc).__name__}: {exc}"[:300],
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
            checked_at=checked_at,
            reason_code=reason_code,
        )
    return ProbeResult(
        name=name,
        healthy=True,
        required=required,
        detail=detail,
        latency_ms=round((time.perf_counter() - started) * 1000, 3),
        checked_at=checked_at,
    )


class DependencyProbes:
    """对 OPA、签名服务、票据状态服务和身份服务做真实往返探测。"""

    def __init__(
        self,
        config: Any,
        opa_client: Any,
        signer: Any,
        ticket_store: Any,
        verifier: Any | None = None,
    ) -> None:
        self.config = config
        self.opa_client = opa_client
        self.signer = signer
        self.ticket_store = ticket_store
        self.verifier = verifier

    # ------------------------------------------------------------ probes

    def probe_opa(self) -> ProbeResult:
        required = "opa" in self.config.required_dependencies

        def run() -> str:
            if self.config.opa_mode == "rest":
                url = f"{self.config.opa_base_url.rstrip('/')}/health"
                with urllib.request.urlopen(
                    url, timeout=self.config.readiness_timeout_seconds
                ) as response:
                    if response.status != 200:
                        raise RuntimeError(f"OPA /health 返回 {response.status}")
            decision = self.opa_client.decide(readiness_canary())
            effect = str(decision.get("effect", ""))
            if effect not in VALID_EFFECTS:
                raise RuntimeError(f"OPA 未返回有效三态决策：{effect!r}")
            return f"mode={self.config.opa_mode}；canary_effect={effect}"

        return _timed("opa", required, run, "S001_OPA_UNAVAILABLE")

    def probe_signer(self) -> ProbeResult:
        required = "signer" in self.config.required_dependencies

        def run() -> str:
            message = b"agentguard-readyz-signer-probe"
            signature = self.signer.sign(message)
            if not signature:
                raise RuntimeError("签名服务返回空签名")
            if not self.signer.verify(message, signature):
                raise RuntimeError("签名服务无法验证自己签发的签名")
            if self.signer.verify(message + b"-tampered", signature):
                raise RuntimeError("签名服务接受了被篡改的消息")
            return f"mode={self.config.signer_mode}；sign_verify_roundtrip=ok"

        return _timed("signer", required, run, "S002_SIGNER_UNAVAILABLE")

    def probe_ticket_state(self) -> ProbeResult:
        required = "ticket_state" in self.config.required_dependencies

        def run() -> str:
            if not self.config.readiness_probe_writes:
                ledger = getattr(self.ticket_store, "ledger", None)
                if ledger is None:
                    raise RuntimeError("票据状态服务未装配账本")
                return "mode=read_only_presence_check"
            digest = "0" * 64
            task_id = "agentguard-readyz-probe"
            token = self.ticket_store.issue(task_id, digest, ttl_seconds=5)
            self.ticket_store.consume(token, task_id, digest)
            try:
                self.ticket_store.consume(token, task_id, digest)
            except Exception:
                return "issue_consume_roundtrip=ok；replay_blocked=ok"
            raise RuntimeError("票据状态服务未阻断重放，视为不可用")

        return _timed("ticket_state", required, run, "S003_TICKET_STATE_UNAVAILABLE")

    def probe_identity(self) -> ProbeResult:
        required = "identity" in self.config.required_dependencies

        def run() -> str:
            if not self.config.oidc_enabled:
                raise RuntimeError("身份服务未启用，但被列为必需依赖")
            if self.verifier is None:
                raise RuntimeError("身份验证器未装配（OIDC discovery 可能失败）")
            url = f"{self.config.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
            with urllib.request.urlopen(
                url, timeout=self.config.readiness_timeout_seconds
            ) as response:
                if response.status != 200:
                    raise RuntimeError(f"OIDC discovery 返回 {response.status}")
            return f"issuer={self.config.oidc_issuer}；discovery=ok"

        if not self.config.oidc_enabled and not required:
            return ProbeResult(
                name="identity",
                healthy=True,
                required=False,
                detail="OIDC 未启用；该实例不校验访问令牌",
                latency_ms=0.0,
                checked_at=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            )
        return _timed("identity", required, run, "S004_IDENTITY_UNAVAILABLE")

    # --------------------------------------------------------- aggregate

    def probe_all(self) -> list[ProbeResult]:
        return [
            self.probe_opa(),
            self.probe_signer(),
            self.probe_ticket_state(),
            self.probe_identity(),
        ]

    def readiness(self) -> dict[str, Any]:
        results = self.probe_all()
        blocking = [item for item in results if item.required and not item.healthy]
        return {
            "ready": not blocking,
            "process_alive": True,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "required_dependencies": list(self.config.required_dependencies),
            "dependencies": {item.name: item.as_dict() for item in results},
            "blocking_dependencies": [item.name for item in blocking],
            "reason_codes": [item.reason_code for item in blocking if item.reason_code],
            "fail_closed": True,
        }


def liveness(config: Any, started_at: float) -> Mapping[str, Any]:
    """存活探针：只证明进程在跑并且配置已加载，不触碰任何外部依赖。"""

    return {
        "alive": True,
        "service": config.service_name,
        "version": config.service_version,
        "uptime_seconds": round(time.monotonic() - started_at, 3),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "note": (
            "存活不代表依赖可用；OPA、签名服务与票据状态服务的可用性请查询 /readyz。"
        ),
    }

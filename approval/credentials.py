"""Signed, server-timed and one-time approval credentials."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol


class ApprovalCredentialError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ApprovalSigner(Protocol):
    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


class ApprovalLedger(Protocol):
    def consume(
        self, approval_id: str, task_id: str, action_digest: str, now: float
    ) -> None: ...


def _canonical(approval: Mapping[str, Any]) -> bytes:
    signed = {str(key): value for key, value in approval.items() if key != "signature"}
    return json.dumps(
        signed, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _epoch_to_rfc3339(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


class SQLiteApprovalLedger:
    """Atomically records each approval_id exactly once."""

    def __init__(self, database: Path | str) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_approvals (
                    approval_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    consumed_at REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database), timeout=10, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def consume(
        self, approval_id: str, task_id: str, action_digest: str, now: float
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO consumed_approvals(approval_id, task_id, action_digest, consumed_at) VALUES (?, ?, ?, ?)",
                    (approval_id, task_id, action_digest, now),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ApprovalCredentialError(
                    "G012_APPROVAL_REPLAY", "审批凭证已被使用，拒绝重复签发执行票据"
                ) from exc


class OpenBaoKvApprovalLedger:
    """Shared one-time approval ledger using an OpenBao KV v2 CAS create."""

    def __init__(
        self,
        address: str,
        token: str,
        mount: str = "agentguard-approvals",
        namespace: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.address = address.rstrip("/")
        self.token = token
        self.mount = mount.strip("/")
        self.namespace = namespace
        self.timeout_seconds = timeout_seconds

    def _request(
        self,
        method: str,
        approval_id: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        safe_id = urllib.parse.quote(approval_id, safe="")
        url = f"{self.address}/v1/{self.mount}/data/{safe_id}"
        headers = {"X-Vault-Token": self.token, "Content-Type": "application/json"}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(
            url,
            data=None if payload is None else json.dumps(payload).encode("utf-8"),
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read()
                return response.status, json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                parsed = json.loads(body.decode("utf-8")) if body else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = {}
            return exc.code, parsed
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ApprovalCredentialError(
                "G013_APPROVAL_LEDGER_UNAVAILABLE",
                f"OpenBao审批账本不可用：{type(exc).__name__}",
            ) from exc

    @staticmethod
    def _detail(body: Mapping[str, Any]) -> str:
        errors = body.get("errors") if isinstance(body, Mapping) else None
        return "; ".join(str(item) for item in errors or [])

    def consume(
        self, approval_id: str, task_id: str, action_digest: str, now: float
    ) -> None:
        payload = {
            "options": {"cas": 0},
            "data": {
                "approval_id": approval_id,
                "task_id": task_id,
                "action_digest": action_digest,
                "consumed_at": now,
            },
        }
        status, body = self._request("POST", approval_id, payload)
        if status in {200, 204}:
            return

        # OpenBao KV v2 uses HTTP 400 both for a CAS collision and for some
        # malformed/configuration errors. Only call this a replay after a
        # successful read proves that this exact approval was already stored.
        if status == 400:
            read_status, read_body = self._request("GET", approval_id)
            if read_status == 200:
                try:
                    record = dict(read_body["data"]["data"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ApprovalCredentialError(
                        "G013_APPROVAL_LEDGER_UNAVAILABLE",
                        "OpenBao审批账本回读格式无效",
                    ) from exc
                expected = {
                    "approval_id": approval_id,
                    "task_id": task_id,
                    "action_digest": action_digest,
                }
                if all(record.get(key) == value for key, value in expected.items()):
                    raise ApprovalCredentialError(
                        "G012_APPROVAL_REPLAY", "审批凭证已在共享账本中核销"
                    )
                raise ApprovalCredentialError(
                    "G013_APPROVAL_LEDGER_UNAVAILABLE", "共享审批账本存在绑定冲突"
                )

        detail = self._detail(body)
        raise ApprovalCredentialError(
            "G013_APPROVAL_LEDGER_UNAVAILABLE",
            f"OpenBao审批账本写入失败：HTTP {status}"
            + (f"（{detail}）" if detail else ""),
        )


class ApprovalCredentialService:
    """Issues signed approvals and verifies them against the server clock."""

    def __init__(
        self,
        signer: ApprovalSigner,
        ledger: ApprovalLedger,
        clock: Any = time.time,
        max_ttl_seconds: int = 3600,
    ) -> None:
        self.signer = signer
        self.ledger = ledger
        self.clock = clock
        self.max_ttl_seconds = max_ttl_seconds

    def issue(
        self,
        request: Mapping[str, Any],
        action_digest: str,
        approver_id: str,
        approver_roles: list[str],
        status: str = "approved",
        ttl_seconds: int = 1800,
    ) -> dict[str, Any]:
        if ttl_seconds <= 0 or ttl_seconds > self.max_ttl_seconds:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID",
                f"审批凭证有效期必须在1到{self.max_ttl_seconds}秒之间",
            )
        if status not in {"approved", "rejected"}:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证状态无效"
            )
        now = float(self.clock())
        approval: dict[str, Any] = {
            "approval_id": f"apr-{uuid.uuid4().hex[:20]}",
            "status": status,
            "approver_id": approver_id,
            "approver_roles": sorted({str(role) for role in approver_roles}),
            "task_id": str(request.get("task_id", "")),
            "action_digest": action_digest,
            "issued_at": _epoch_to_rfc3339(now),
            "expires_at": _epoch_to_rfc3339(now + ttl_seconds),
            "max_uses": 1,
            "use_count": 0,
            "issuer": "agentguard_approval_service",
        }
        approval["signature"] = self.signer.sign(_canonical(approval))
        return approval

    def validate(
        self, approval: Mapping[str, Any], task_id: str, action_digest: str
    ) -> dict[str, Any]:
        required = {
            "approval_id",
            "status",
            "approver_id",
            "approver_roles",
            "task_id",
            "action_digest",
            "issued_at",
            "expires_at",
            "max_uses",
            "use_count",
            "issuer",
            "signature",
        }
        if not required.issubset(approval):
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证字段不完整或未签名"
            )
        try:
            valid_signature = self.signer.verify(
                _canonical(approval), str(approval["signature"])
            )
        except Exception as exc:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证签名服务不可用"
            ) from exc
        if not valid_signature:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证签名无效"
            )
        if str(approval.get("issuer")) != "agentguard_approval_service":
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证签发方无效"
            )
        if str(approval.get("status")) != "approved":
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证不是已批准状态"
            )
        roles = approval.get("approver_roles")
        if not str(approval.get("approver_id", "")) or not isinstance(roles, list) or not roles:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证缺少可信审批人身份或角色"
            )
        if str(approval.get("task_id")) != task_id or str(
            approval.get("action_digest")
        ) != action_digest:
            raise ApprovalCredentialError(
                "G014_APPROVAL_BINDING_MISMATCH", "审批凭证与当前任务或动作不一致"
            )
        try:
            expires_at = datetime.fromisoformat(
                str(approval["expires_at"]).replace("Z", "+00:00")
            ).timestamp()
            issued_at = datetime.fromisoformat(
                str(approval["issued_at"]).replace("Z", "+00:00")
            ).timestamp()
        except (TypeError, ValueError) as exc:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证时间格式无效"
            ) from exc
        now = float(self.clock())
        if issued_at > now + 60:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证签发时间来自未来"
            )
        if expires_at <= issued_at or expires_at - issued_at > self.max_ttl_seconds:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证有效期超出服务端限制"
            )
        if expires_at < now:
            raise ApprovalCredentialError(
                "G011_APPROVAL_EXPIRED", "审批凭证已按网关服务器时间过期"
            )
        try:
            max_uses = int(approval.get("max_uses", 0))
            use_count = int(approval.get("use_count", 0))
        except (TypeError, ValueError) as exc:
            raise ApprovalCredentialError(
                "G010_APPROVAL_CREDENTIAL_INVALID", "审批凭证使用次数格式无效"
            ) from exc
        if max_uses != 1 or use_count != 0:
            raise ApprovalCredentialError(
                "G012_APPROVAL_REPLAY", "审批凭证不是未使用的一次性凭证"
            )
        return dict(approval)

    def consume(self, approval: Mapping[str, Any]) -> None:
        self.ledger.consume(
            str(approval["approval_id"]),
            str(approval["task_id"]),
            str(approval["action_digest"]),
            float(self.clock()),
        )

"""Atomic one-time ticket ledgers for local and shared deployments."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from pathlib import Path
from typing import Any, Protocol


class TicketLedgerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TicketLedger(Protocol):
    def issue(self, payload: dict[str, Any]) -> None: ...

    def consume(
        self, jti: str, task_id: str, action_digest: str, now: float
    ) -> None: ...


class SQLiteTicketLedger:
    """Single-host durable ledger used for tests and offline development."""

    def __init__(self, database: Path | str) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database), timeout=10, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_tickets (
                    jti TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                )
                """
            )

    def issue(self, payload: dict[str, Any]) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO execution_tickets(jti, task_id, action_digest, expires_at, consumed_at) VALUES (?, ?, ?, ?, NULL)",
                (
                    payload["jti"],
                    payload["task_id"],
                    payload["action_digest"],
                    payload["exp"],
                ),
            )

    def consume(self, jti: str, task_id: str, action_digest: str, now: float) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT task_id, action_digest, expires_at, consumed_at FROM execution_tickets WHERE jti = ?",
                (jti,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise TicketLedgerError("G207_UNKNOWN_TICKET", "票据不在核销账本中")
            if row[3] is not None:
                connection.rollback()
                raise TicketLedgerError("G206_TICKET_REPLAY", "一次性执行票据已被使用")
            if row[0] != task_id or row[1] != action_digest:
                connection.rollback()
                raise TicketLedgerError(
                    "G205_TICKET_BINDING_MISMATCH", "账本中的票据绑定不一致"
                )
            if float(row[2]) < now:
                connection.rollback()
                raise TicketLedgerError("G204_TICKET_EXPIRED", "账本中的执行票据已过期")
            updated = connection.execute(
                "UPDATE execution_tickets SET consumed_at = ? WHERE jti = ? AND consumed_at IS NULL",
                (now, jti),
            ).rowcount
            if updated != 1:
                connection.rollback()
                raise TicketLedgerError(
                    "G206_TICKET_REPLAY", "一次性执行票据并发核销失败"
                )
            connection.commit()


class OpenBaoKvTicketLedger:
    """Shared one-time ledger using OpenBao KV v2 check-and-set operations."""

    def __init__(
        self,
        address: str,
        token: str,
        mount: str = "agentguard-tickets",
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
        jti: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        safe_jti = urllib.parse.quote(jti, safe="")
        url = f"{self.address}/v1/{self.mount}/data/{safe_jti}"
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
            parsed = json.loads(body.decode("utf-8")) if body else {}
            return exc.code, parsed
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise TicketLedgerError(
                "G209_TICKET_LEDGER_UNAVAILABLE",
                f"OpenBao KV票据账本不可用：{type(exc).__name__}",
            ) from exc

    def issue(self, payload: dict[str, Any]) -> None:
        status, _ = self._request(
            "POST", payload["jti"], {"options": {"cas": 0}, "data": payload}
        )
        if status not in {200, 204}:
            raise TicketLedgerError(
                "G209_TICKET_LEDGER_UNAVAILABLE", f"OpenBao KV写入失败：HTTP {status}"
            )

    def _read(self, jti: str) -> tuple[dict[str, Any], int]:
        status, body = self._request("GET", jti)
        if status == 404:
            raise TicketLedgerError("G207_UNKNOWN_TICKET", "票据不在共享账本中")
        if status != 200:
            raise TicketLedgerError(
                "G209_TICKET_LEDGER_UNAVAILABLE", f"OpenBao KV读取失败：HTTP {status}"
            )
        try:
            outer = body["data"]
            return dict(outer["data"]), int(outer["metadata"]["version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TicketLedgerError(
                "G209_TICKET_LEDGER_UNAVAILABLE", "OpenBao KV响应格式无效"
            ) from exc

    def consume(self, jti: str, task_id: str, action_digest: str, now: float) -> None:
        record, version = self._read(jti)
        if record.get("consumed_at") is not None:
            raise TicketLedgerError("G206_TICKET_REPLAY", "一次性执行票据已被使用")
        if record.get("task_id") != task_id or record.get("action_digest") != action_digest:
            raise TicketLedgerError(
                "G205_TICKET_BINDING_MISMATCH", "共享账本中的票据绑定不一致"
            )
        if float(record.get("exp", 0)) < now:
            raise TicketLedgerError("G204_TICKET_EXPIRED", "共享账本中的执行票据已过期")
        updated = {**record, "consumed_at": now}
        status, _ = self._request(
            "POST", jti, {"options": {"cas": version}, "data": updated}
        )
        if status in {200, 204}:
            return
        if status == 400:
            latest, _ = self._read(jti)
            if latest.get("consumed_at") is not None:
                raise TicketLedgerError(
                    "G206_TICKET_REPLAY", "一次性执行票据并发核销失败"
                )
        raise TicketLedgerError(
            "G209_TICKET_LEDGER_UNAVAILABLE", f"OpenBao KV原子核销失败：HTTP {status}"
        )

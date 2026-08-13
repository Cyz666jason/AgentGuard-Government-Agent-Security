"""可回滚、路径受限的本地测试业务适配器。

这些适配器执行真实 SQLite 读写，但仅作用于网关 state_dir 下的测试数据库。
它们用于证明“策略允许后才发生副作用”，不连接真实生产系统。
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping


class BusinessAdapterError(RuntimeError):
    pass


class LocalTestBusinessAdapters:
    """两个最小业务适配器：公告只读查询与测试付款账本写入。"""

    def __init__(self, state_dir: Path | str) -> None:
        self.root = Path(state_dir).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.notices_db = self._confined("business/notices.sqlite")
        self.ledger_db = self._confined("business/payment_ledger.sqlite")
        self.notices_db.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _confined(self, relative_path: str) -> Path:
        candidate = (self.root / relative_path).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise BusinessAdapterError("测试适配器路径越界") from exc
        return candidate

    @staticmethod
    def _connect(database: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(str(database), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect(self.notices_db)) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS notices (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    department TEXT NOT NULL,
                    published_at TEXT NOT NULL
                )
                """
            )
            connection.executemany(
                "INSERT OR IGNORE INTO notices(id, title, department, published_at) VALUES (?, ?, ?, ?)",
                [
                    (1, "政务服务系统维护通知", "信息中心", "2026-08-01"),
                    (2, "第三季度材料归档安排", "综合办公室", "2026-08-03"),
                    (3, "安全培训报名通知", "人力资源部", "2026-08-05"),
                ],
            )
            connection.commit()
        with closing(self._connect(self.ledger_db)) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL UNIQUE,
                    payee TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.commit()

    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        action = request.get("action", {})
        key = (str(action.get("tool", "")), str(action.get("operation", "")))
        if key == ("database.query", "query"):
            return self._query_notices(action.get("parameters", {}))
        if key == ("payment.transfer", "transfer"):
            return self._record_payment(request)
        raise BusinessAdapterError(f"没有本地测试业务适配器：{key[0]}/{key[1]}")

    def _query_notices(self, parameters: Mapping[str, Any]) -> dict[str, Any]:
        try:
            limit = max(1, min(100, int(parameters.get("limit", 20))))
        except (TypeError, ValueError) as exc:
            raise BusinessAdapterError("limit 必须是 1 到 100 的整数") from exc
        with closing(self._connect(self.notices_db)) as connection:
            rows = connection.execute(
                "SELECT id, title, department, published_at FROM notices ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        return {
            "adapter": "sqlite_notice_query",
            "database": self.notices_db.name,
            "row_count": len(rows),
            "rows": [dict(row) for row in rows],
            "side_effect": False,
        }

    def _record_payment(self, request: Mapping[str, Any]) -> dict[str, Any]:
        approval = request.get("approval", {})
        if approval.get("status") != "approved":
            raise BusinessAdapterError("付款测试适配器要求已批准的审批凭证")
        action = request.get("action", {})
        parameters = action.get("parameters", {})
        try:
            amount = Decimal(str(parameters.get("amount", "0")))
            amount_cents = int((amount * 100).to_integral_exact())
        except (InvalidOperation, ValueError) as exc:
            raise BusinessAdapterError("付款金额格式无效") from exc
        if amount_cents <= 0:
            raise BusinessAdapterError("付款金额必须大于 0")
        currency = str(parameters.get("currency", "CNY")).upper()
        if currency not in {"CNY", "USD", "EUR"}:
            raise BusinessAdapterError("测试账本不支持该币种")
        task_id = str(request.get("task_id", ""))
        if not task_id:
            raise BusinessAdapterError("缺少 task_id")
        payee = str(action.get("resource", "")).removeprefix("erp://payments/") or "unknown"
        try:
            with closing(self._connect(self.ledger_db)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "INSERT INTO payments(task_id, payee, amount_cents, currency, status) VALUES (?, ?, ?, ?, ?)",
                    (task_id, payee, amount_cents, currency, "recorded_test_only"),
                )
                payment_id = int(cursor.lastrowid)
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise BusinessAdapterError("同一 task_id 的付款已记录，拒绝重复副作用") from exc
        return {
            "adapter": "sqlite_test_payment_ledger",
            "database": self.ledger_db.name,
            "payment_id": payment_id,
            "task_id": task_id,
            "amount_cents": amount_cents,
            "currency": currency,
            "status": "recorded_test_only",
            "side_effect": True,
        }

    def payment_count(self, task_id: str | None = None) -> int:
        query = "SELECT COUNT(*) FROM payments"
        parameters: tuple[Any, ...] = ()
        if task_id is not None:
            query += " WHERE task_id = ?"
            parameters = (task_id,)
        with closing(self._connect(self.ledger_db)) as connection:
            return int(connection.execute(query, parameters).fetchone()[0])

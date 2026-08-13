"""绑定任务和完整动作的一次性执行票据。"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from .ledgers import SQLiteTicketLedger, TicketLedger, TicketLedgerError
from .signers import HmacKeyringSigner, TicketSigner, TicketSignerError


def compute_action_digest(request: Mapping[str, Any]) -> str:
    binding = {"task_id": request.get("task_id", ""), "action": request.get("action", {})}
    canonical = json.dumps(
        binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


class TicketError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ExecutionTicketStore:
    """用 HMAC 校验完整性，并在 SQLite 中原子核销一次性票据。"""

    def __init__(
        self,
        database: Path | str,
        secret: bytes | None = None,
        signer: TicketSigner | None = None,
        ledger: TicketLedger | None = None,
    ) -> None:
        if (secret is None) == (signer is None):
            raise ValueError("secret 与 signer 必须且只能提供一个")
        self.signer = signer or HmacKeyringSigner.single_key(bytes(secret))
        self.ledger = ledger or SQLiteTicketLedger(database)

    def issue(self, task_id: str, action_digest: str, ttl_seconds: int = 30) -> str:
        now = time.time()
        payload = {
            "jti": uuid.uuid4().hex,
            "task_id": task_id,
            "action_digest": action_digest,
            "iat": round(now, 6),
            "exp": round(now + ttl_seconds, 6),
        }
        encoded = _b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        try:
            signature = self.signer.sign(encoded.encode("ascii"))
        except TicketSignerError as exc:
            raise TicketError("G208_TICKET_SIGNER_UNAVAILABLE", str(exc)) from exc
        try:
            self.ledger.issue({**payload, "consumed_at": None})
        except TicketLedgerError as exc:
            raise TicketError(exc.code, str(exc)) from exc
        return f"{encoded}.{signature}"

    def consume(self, token: str | None, task_id: str, action_digest: str) -> dict[str, Any]:
        payload = self._verify_envelope(token)
        now = time.time()
        if float(payload["exp"]) < now:
            raise TicketError("G204_TICKET_EXPIRED", "执行票据已过期")
        if payload["task_id"] != task_id or payload["action_digest"] != action_digest:
            raise TicketError("G205_TICKET_BINDING_MISMATCH", "执行票据与当前任务或动作不一致")

        try:
            self.ledger.consume(payload["jti"], task_id, action_digest, now)
        except TicketLedgerError as exc:
            raise TicketError(exc.code, str(exc)) from exc
        return payload

    def _verify_envelope(self, token: str | None) -> dict[str, Any]:
        if not token:
            raise TicketError("G201_TICKET_MISSING", "工具适配器拒绝无票据调用")
        parts = token.split(".")
        if len(parts) != 2:
            raise TicketError("G202_TICKET_MALFORMED", "执行票据格式无效")
        encoded, received_signature = parts
        try:
            valid = self.signer.verify(encoded.encode("ascii"), received_signature)
        except TicketSignerError as exc:
            raise TicketError("G208_TICKET_SIGNER_UNAVAILABLE", str(exc)) from exc
        if not valid:
            raise TicketError("G203_TICKET_SIGNATURE_INVALID", "执行票据签名无效")
        try:
            payload = json.loads(_b64decode(encoded))
            required = {"jti", "task_id", "action_digest", "iat", "exp"}
            if not isinstance(payload, dict) or not required.issubset(payload):
                raise ValueError("字段不完整")
            return payload
        except Exception as exc:
            raise TicketError("G202_TICKET_MALFORMED", "执行票据载荷无效") from exc

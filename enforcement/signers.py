"""Pluggable execution-ticket signers.

The local signer keeps backwards compatibility for tests.  The OpenBao Transit
signer moves the signing key outside the application process and fails closed
when the key service is unavailable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from typing import Mapping, Protocol


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class TicketSignerError(RuntimeError):
    pass


class TicketSigner(Protocol):
    def sign(self, message: bytes) -> str: ...

    def verify(self, message: bytes, signature: str) -> bool: ...


class HmacKeyringSigner:
    """Versioned local HMAC keyring for tests and offline development."""

    def __init__(self, keys: Mapping[str, bytes], active_key_id: str) -> None:
        normalized = {str(key_id): bytes(secret) for key_id, secret in keys.items()}
        if active_key_id not in normalized:
            raise ValueError("active_key_id 不在本地密钥环中")
        if any(len(secret) < 32 for secret in normalized.values()):
            raise ValueError("票据签名密钥至少需要 32 字节")
        self.keys = normalized
        self.active_key_id = active_key_id

    @classmethod
    def single_key(cls, secret: bytes) -> "HmacKeyringSigner":
        return cls({"local-v1": secret}, "local-v1")

    def sign(self, message: bytes) -> str:
        digest = hmac.new(
            self.keys[self.active_key_id], message, hashlib.sha256
        ).digest()
        return f"{self.active_key_id}:{_b64encode(digest)}"

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            key_id, received = signature.split(":", 1)
            secret = self.keys[key_id]
        except (KeyError, ValueError):
            return False
        expected = _b64encode(hmac.new(secret, message, hashlib.sha256).digest())
        return hmac.compare_digest(expected, received)


class OpenBaoTransitSigner:
    """HMAC signer backed by an OpenBao Transit secrets engine."""

    def __init__(
        self,
        address: str,
        token: str,
        key_name: str = "agentguard-ticket",
        mount: str = "transit",
        namespace: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not address.startswith(("http://", "https://")):
            raise ValueError("OpenBao address 必须是 HTTP(S) URL")
        if not token:
            raise ValueError("OpenBao token 不能为空")
        self.address = address.rstrip("/")
        self.token = token
        self.key_name = key_name
        self.mount = mount.strip("/")
        self.namespace = namespace
        self.timeout_seconds = timeout_seconds

    def _post(self, operation: str, payload: dict[str, str]) -> dict:
        url = f"{self.address}/v1/{self.mount}/{operation}/{self.key_name}"
        headers = {
            "Content-Type": "application/json",
            "X-Vault-Token": self.token,
        }
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds
            ) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise TicketSignerError(
                f"OpenBao Transit {operation} 不可用：{type(exc).__name__}"
            ) from exc
        data = body.get("data")
        if not isinstance(data, dict):
            raise TicketSignerError("OpenBao Transit 响应缺少 data")
        return data

    @staticmethod
    def _input(message: bytes) -> str:
        return base64.b64encode(message).decode("ascii")

    def sign(self, message: bytes) -> str:
        data = self._post(
            "hmac", {"input": self._input(message), "algorithm": "sha2-256"}
        )
        signature = data.get("hmac")
        if not isinstance(signature, str) or not signature:
            raise TicketSignerError("OpenBao Transit 响应缺少 hmac")
        return signature

    def verify(self, message: bytes, signature: str) -> bool:
        data = self._post(
            "verify",
            {
                "input": self._input(message),
                "hmac": signature,
                "algorithm": "sha2-256",
            },
        )
        return data.get("valid") is True

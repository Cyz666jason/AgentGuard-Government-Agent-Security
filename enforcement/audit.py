"""最小化并脱敏记录强制执行事件。"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Mapping


_LOCK = threading.Lock()
_SENSITIVE = ("password", "secret", "token", "authorization", "api_key", "apikey", "cookie", "credential")


def redact(value: Any, key: str = "") -> Any:
    normalized = key.lower().replace("-", "_")
    if any(marker in normalized for marker in _SENSITIVE):
        return "***REDACTED***"
    if isinstance(value, Mapping):
        return {str(item_key): redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class AuditLogger:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: Mapping[str, Any]) -> None:
        line = json.dumps(redact(dict(event)), ensure_ascii=False, sort_keys=True)
        with _LOCK:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

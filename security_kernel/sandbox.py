"""使用 Wasmtime 对工具适配器执行施加能力、CPU 与内存边界。"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

import wasmtime


class WasmSecurityKernel:
    """默认无 WASI、无主机导入、有限燃料和有限内存的 Wasm 沙箱。"""

    def __init__(self, fuel: int = 100_000, memory_bytes: int = 2 * 1024 * 1024) -> None:
        if fuel <= 0 or memory_bytes <= 0:
            raise ValueError("fuel 和 memory_bytes 必须为正数")
        config = wasmtime.Config()
        config.consume_fuel = True
        self.engine = wasmtime.Engine(config)
        self.fuel = fuel
        self.memory_bytes = memory_bytes

    def execute(
        self,
        module_path: Path | str,
        entry: str = "run",
        args: Sequence[int] = (),
    ) -> dict[str, Any]:
        """运行一个无主机能力的 Wasm 模块并返回结构化安全结果。"""

        started = time.perf_counter()
        path = Path(module_path)
        base = {
            "module": path.name,
            "entry": entry,
            "wasi_enabled": False,
            "host_imports_allowed": False,
            "fuel_limit": self.fuel,
            "memory_limit_bytes": self.memory_bytes,
        }
        try:
            module = wasmtime.Module.from_file(self.engine, str(path))
        except Exception as exc:
            return self._blocked(base, started, "K001_MODULE_INVALID", exc)

        imports = [f"{item.module}.{item.name}" for item in module.imports]
        if imports:
            result = self._blocked(
                base,
                started,
                "K002_HOST_IMPORT_FORBIDDEN",
                RuntimeError("模块请求了未授权的主机能力"),
            )
            result["requested_imports"] = imports
            return result

        store = wasmtime.Store(self.engine)
        store.set_limits(
            memory_size=self.memory_bytes,
            table_elements=1_000,
            instances=10,
            tables=10,
            memories=4,
        )
        store.set_fuel(self.fuel)
        try:
            instance = wasmtime.Instance(store, module, [])
        except Exception as exc:
            code = "K004_MEMORY_LIMIT" if "memory" in str(exc).lower() else "K003_INSTANTIATION_BLOCKED"
            return self._blocked(base, started, code, exc, store)

        exports = instance.exports(store)
        if entry not in exports or not isinstance(exports[entry], wasmtime.Func):
            return self._blocked(
                base,
                started,
                "K005_ENTRY_NOT_ALLOWED",
                RuntimeError("未找到允许的导出函数"),
                store,
            )

        try:
            output = exports[entry](store, *[int(value) for value in args])
            remaining = store.get_fuel()
            return {
                **base,
                "status": "executed_isolated",
                "reason_code": "K000_OK",
                "output": output,
                "fuel_consumed": self.fuel - remaining,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            }
        except Exception as exc:
            message = str(exc).lower()
            if "fuel" in message:
                code = "K006_CPU_BUDGET_EXCEEDED"
            elif "memory" in message or "out of bounds" in message:
                code = "K004_MEMORY_LIMIT"
            else:
                code = "K007_RUNTIME_TRAP"
            return self._blocked(base, started, code, exc, store)

    def _blocked(
        self,
        base: dict[str, Any],
        started: float,
        code: str,
        error: Exception,
        store: wasmtime.Store | None = None,
    ) -> dict[str, Any]:
        remaining = None
        if store is not None:
            try:
                remaining = store.get_fuel()
            except Exception:
                remaining = None
        return {
            **base,
            "status": "sandbox_blocked",
            "reason_code": code,
            "error": str(error).splitlines()[0][:240],
            "fuel_consumed": self.fuel - remaining if remaining is not None else None,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        }

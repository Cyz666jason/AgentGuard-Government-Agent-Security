"""OPA 决策点接入：常驻 REST（生产）与逐次 CLI（离线演示）两种模式。

CLI 模式每次决策都要启动一次 OPA 进程，延迟里包含进程启动和策略加载，
**不能**当作生产性能结果；因此 ``performance_note`` 会显式标注这一点。
"""

from __future__ import annotations

import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

from approval.workflow import OpaClient
from enforcement.http_stack import OpaRestClient


CLI_PERFORMANCE_NOTE = (
    "CLI 模式每次请求启动一次 OPA 进程，延迟包含进程启动与策略加载，"
    "仅用于离线演示，不是生产性能结果。"
)
REST_PERFORMANCE_NOTE = (
    "常驻 OPA REST 模式；延迟为纯策略求值加一次本地 HTTP 往返，可用于性能参考。"
)


class OpaRuntimeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def resolve_opa_binary(project_root: Path, configured: str = "") -> Path:
    if configured:
        candidate = Path(configured)
        if not candidate.is_file():
            raise OpaRuntimeError("S010_OPA_BINARY_MISSING", f"未找到 OPA 可执行文件：{candidate}")
        return candidate
    for name in ("opa.exe", "opa"):
        candidate = project_root / "tools" / name
        if candidate.is_file():
            return candidate
    raise OpaRuntimeError(
        "S010_OPA_BINARY_MISSING",
        "未找到 tools/opa(.exe)，请先运行 scripts/bootstrap_opa.ps1 或设置 AGENTGUARD_OPA_BINARY",
    )


class ResidentOpaProcess:
    """按需拉起并守护一个常驻 ``opa run --server`` 进程。"""

    def __init__(
        self,
        project_root: Path | str,
        address: str,
        binary: str = "",
        startup_timeout_seconds: float = 15.0,
    ) -> None:
        self.project_root = Path(project_root)
        self.address = address
        self.binary = resolve_opa_binary(self.project_root, binary)
        self.startup_timeout_seconds = startup_timeout_seconds
        self.process: subprocess.Popen[bytes] | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.address}"

    def start(self) -> "ResidentOpaProcess":
        if self.process is not None:
            return self
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            [
                str(self.binary),
                "run",
                "--server",
                f"--addr={self.address}",
                "policy",
                "data",
            ],
            cwd=self.project_root,
            # OPA emits one access-log line per request. Keeping unread PIPEs
            # here eventually fills the Windows pipe buffer and blocks the
            # policy server, making AgentGuard fail readiness with a timeout.
            # The service does not consume these streams, so discard them.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        deadline = time.monotonic() + self.startup_timeout_seconds
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise OpaRuntimeError(
                    "S011_OPA_PROCESS_EXITED",
                    f"OPA 进程启动后立即退出，退出码 {self.process.returncode}",
                )
            try:
                with urllib.request.urlopen(f"{self.base_url}/health", timeout=1) as response:
                    if response.status == 200:
                        return self
            except Exception:
                time.sleep(0.1)
        self.stop()
        raise OpaRuntimeError(
            "S012_OPA_STARTUP_TIMEOUT",
            f"OPA REST 在 {self.startup_timeout_seconds}s 内未就绪",
        )

    def stop(self, timeout: float = 10.0) -> None:
        if self.process is None:
            return
        process, self.process = self.process, None
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=timeout)

    def __enter__(self) -> "ResidentOpaProcess":
        return self.start()

    def __exit__(self, *_: Any) -> None:
        self.stop()


def build_opa_client(config: Any, project_root: Path | str) -> tuple[Any, str]:
    """按配置返回 ``(client, performance_note)``。"""

    if config.opa_mode == "rest":
        return (
            OpaRestClient(config.opa_base_url, timeout=config.opa_timeout_seconds),
            REST_PERFORMANCE_NOTE,
        )
    return OpaClient(project_root), CLI_PERFORMANCE_NOTE

r"""AgentGuard 网关服务命令行入口。

示例（PowerShell）：

```powershell
$env:AGENTGUARD_TICKET_SECRET_HEX = '<由密钥管理器注入的64位十六进制随机值>'
.\.venv\Scripts\python.exe -m service --port 8080 --opa-mode rest --manage-opa
```

机密只从环境变量或环境变量指定的外部文件读取；命令行**不接受**机密参数，
避免落进 shell 历史和进程列表。
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:  # 允许 `python service/__main__.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service.app import AgentGuardService  # noqa: E402
from service.config import ConfigError, load_config  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service",
        description="AgentGuard 网关服务（/healthz、/readyz、/version、/invoke）",
    )
    parser.add_argument("--host", help="监听地址，默认 127.0.0.1")
    parser.add_argument("--port", type=int, help="监听端口，默认 8080；0 表示随机端口")
    parser.add_argument("--config-file", help="非机密 JSON 配置文件路径")
    parser.add_argument(
        "--opa-mode",
        choices=["rest", "cli"],
        help="rest=常驻 OPA REST（生产）；cli=逐次启动 OPA CLI（仅离线演示）",
    )
    parser.add_argument("--opa-base-url", help="常驻 OPA 地址，默认 http://127.0.0.1:8181")
    parser.add_argument(
        "--manage-opa",
        action="store_true",
        help="由本服务拉起并守护常驻 OPA REST 进程",
    )
    parser.add_argument("--state-dir", help="票据与审批状态目录")
    parser.add_argument(
        "--signer-mode",
        choices=["hmac_env", "openbao_transit"],
        help="票据签名来源",
    )
    parser.add_argument(
        "--enable-local-adapters",
        action="store_true",
        help="启用隔离测试业务适配器（读写本地测试 SQLite）",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="只加载配置并打印一次 /readyz 与 /version，然后退出",
    )
    return parser


def overrides_from_args(args: argparse.Namespace) -> dict[str, Any]:
    mapping = {
        "host": args.host,
        "port": args.port,
        "opa_mode": args.opa_mode,
        "opa_base_url": args.opa_base_url,
        "state_dir": args.state_dir,
        "signer_mode": args.signer_mode,
    }
    overrides = {key: value for key, value in mapping.items() if value is not None}
    if args.manage_opa:
        overrides["manage_opa_process"] = True
    if args.enable_local_adapters:
        overrides["enable_local_adapters"] = True
    return overrides


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(
            config_file=args.config_file, overrides=overrides_from_args(args)
        )
    except ConfigError as exc:
        print(
            json.dumps(
                {"status": "config_error", "reason_code": exc.code, "message": str(exc)},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2

    try:
        service = AgentGuardService(config)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "startup_failed",
                    "reason_code": getattr(exc, "code", type(exc).__name__),
                    "message": str(exc),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 3

    if args.check_only:
        try:
            readiness = service.probes.readiness()
            print(
                json.dumps(
                    {"version": service.version_payload(), "readyz": readiness},
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0 if readiness["ready"] else 1
        finally:
            service.close()

    service.start()
    print(
        json.dumps(
            {
                "status": "listening",
                "url": service.base_url,
                "endpoints": ["/healthz", "/readyz", "/version", "/invoke"],
                "opa_mode": config.opa_mode,
                "performance_representative": config.performance_representative,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        handler_signal = getattr(signal, name, None)
        if handler_signal is None:
            continue
        try:
            signal.signal(handler_signal, lambda *_: service.close())
        except (ValueError, OSError):
            continue

    try:
        service.serve_forever()
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

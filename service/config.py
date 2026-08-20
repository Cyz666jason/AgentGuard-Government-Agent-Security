"""AgentGuard 网关服务配置：只从环境变量或非机密配置文件读取。

安全约定：

* 配置文件**不允许**包含任何机密字段。加载时递归检查键名，命中
  ``secret``/``token``/``password``/``private_key``/``salt`` 等模式即拒绝启动。
* 机密只允许来自环境变量、环境变量指定的外部文件路径，或 OpenBao Transit。
* 机密不进入 ``ServiceConfig``，因此配置可以安全地写进日志与 ``/version``。
* 缺少必需机密时 ``load_config`` 直接抛错，服务不会以不安全状态启动（fail-closed）。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]

ENV_PREFIX = "AGENTGUARD_"

#: 配置文件里出现这些片段的键名一律拒绝，避免机密被提交进仓库。
FORBIDDEN_KEY_FRAGMENTS = (
    "secret",
    "token",
    "password",
    "passwd",
    "private_key",
    "privatekey",
    "credential",
    "salt",
    "apikey",
    "api_key",
)

OPA_MODES = ("rest", "cli")
SIGNER_MODES = ("hmac_env", "openbao_transit")


class ConfigError(RuntimeError):
    """配置无效或缺少必需机密；服务必须拒绝启动。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ServiceConfig:
    """不含任何机密值的服务配置。"""

    host: str = "127.0.0.1"
    port: int = 8080

    # 策略决策点
    opa_mode: str = "rest"
    opa_base_url: str = "http://127.0.0.1:8181"
    opa_decision_path: str = "/v1/data/agent/guard/decision"
    opa_timeout_seconds: float = 3.0
    manage_opa_process: bool = False
    opa_binary: str = ""
    opa_startup_timeout_seconds: float = 15.0

    # 票据与状态
    state_dir: str = str(PROJECT_ROOT / "reports" / "runtime" / "service_state")
    ticket_ttl_seconds: int = 30
    enable_local_adapters: bool = False

    # 签名服务
    signer_mode: str = "hmac_env"
    ticket_secret_source: str = "unset"
    openbao_address: str = ""
    openbao_mount: str = "transit"
    openbao_namespace: str = ""
    openbao_key_name: str = "agentguard-ticket"
    openbao_timeout_seconds: float = 5.0

    # 身份
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = "agentguard"
    oidc_require_mfa: bool = True
    oidc_timeout_seconds: float = 5.0

    # 探针与超时
    readiness_timeout_seconds: float = 2.5
    readiness_probe_writes: bool = True
    request_timeout_seconds: float = 8.0
    shutdown_timeout_seconds: float = 5.0

    # 版本信息
    service_name: str = "agentguard-gateway"
    service_version: str = "0.9.0"
    policy_version_path: str = "policy/agent_guard.rego"

    required_dependencies: tuple[str, ...] = field(
        default_factory=lambda: ("opa", "signer", "ticket_state")
    )

    @property
    def state_path(self) -> Path:
        return Path(self.state_dir)

    @property
    def opa_decision_url(self) -> str:
        return f"{self.opa_base_url.rstrip('/')}{self.opa_decision_path}"

    @property
    def performance_representative(self) -> bool:
        """CLI 模式每次请求都要启动一次 OPA 进程，不能当作生产性能结果。"""

        return self.opa_mode == "rest"

    def redacted(self) -> dict[str, Any]:
        """可以安全写入日志与 ``/version`` 的配置视图。"""

        payload = asdict(self)
        payload["required_dependencies"] = list(self.required_dependencies)
        payload["performance_representative"] = self.performance_representative
        payload["contains_secret_values"] = False
        return payload


def _assert_no_secret_keys(payload: Any, path: str = "") -> None:
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            lowered = str(key).lower()
            if any(fragment in lowered for fragment in FORBIDDEN_KEY_FRAGMENTS):
                raise ConfigError(
                    "C001_SECRET_IN_CONFIG_FILE",
                    f"配置文件不允许包含机密字段：{path}{key}。请改用环境变量或密钥管理器。",
                )
            _assert_no_secret_keys(value, f"{path}{key}.")
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            _assert_no_secret_keys(value, f"{path}{index}.")


def load_config_file(path: Path | str) -> dict[str, Any]:
    """读取非机密 JSON 配置文件；含机密字段则拒绝。"""

    file_path = Path(path)
    if not file_path.is_file():
        raise ConfigError("C002_CONFIG_FILE_MISSING", f"配置文件不存在：{file_path}")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ConfigError("C003_CONFIG_FILE_INVALID", f"配置文件不是合法 JSON：{exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError("C003_CONFIG_FILE_INVALID", "配置文件顶层必须是 JSON 对象")
    _assert_no_secret_keys(payload)
    return payload


def _env(environ: Mapping[str, str], name: str) -> str | None:
    value = environ.get(f"{ENV_PREFIX}{name}")
    if value is None:
        return None
    value = value.strip()
    return value or None


def _as_bool(raw: str, name: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigError("C004_INVALID_VALUE", f"{name} 必须是布尔值，实际为 {raw!r}")


def _coerce(field_name: str, raw: Any, default: Any) -> Any:
    if isinstance(default, bool):
        return raw if isinstance(raw, bool) else _as_bool(str(raw), field_name)
    if isinstance(default, int) and not isinstance(default, bool):
        try:
            return int(str(raw).strip())
        except ValueError as exc:
            raise ConfigError("C004_INVALID_VALUE", f"{field_name} 必须是整数") from exc
    if isinstance(default, float):
        try:
            return float(str(raw).strip())
        except ValueError as exc:
            raise ConfigError("C004_INVALID_VALUE", f"{field_name} 必须是数字") from exc
    if isinstance(default, tuple):
        if isinstance(raw, (list, tuple)):
            return tuple(str(item) for item in raw)
        return tuple(item.strip() for item in str(raw).split(",") if item.strip())
    return str(raw)


#: 配置字段 -> 环境变量后缀。
ENV_FIELD_MAP: dict[str, str] = {
    "host": "SERVICE_HOST",
    "port": "SERVICE_PORT",
    "opa_mode": "OPA_MODE",
    "opa_base_url": "OPA_BASE_URL",
    "opa_decision_path": "OPA_DECISION_PATH",
    "opa_timeout_seconds": "OPA_TIMEOUT_SECONDS",
    "manage_opa_process": "MANAGE_OPA_PROCESS",
    "opa_binary": "OPA_BINARY",
    "opa_startup_timeout_seconds": "OPA_STARTUP_TIMEOUT_SECONDS",
    "state_dir": "STATE_DIR",
    "ticket_ttl_seconds": "TICKET_TTL_SECONDS",
    "enable_local_adapters": "ENABLE_LOCAL_ADAPTERS",
    "signer_mode": "SIGNER_MODE",
    "openbao_address": "OPENBAO_ADDR",
    "openbao_mount": "OPENBAO_MOUNT",
    "openbao_namespace": "OPENBAO_NAMESPACE",
    "openbao_key_name": "OPENBAO_TICKET_KEY",
    "openbao_timeout_seconds": "OPENBAO_TIMEOUT_SECONDS",
    "oidc_enabled": "OIDC_ENABLED",
    "oidc_issuer": "OIDC_ISSUER",
    "oidc_audience": "OIDC_AUDIENCE",
    "oidc_require_mfa": "OIDC_REQUIRE_MFA",
    "oidc_timeout_seconds": "OIDC_TIMEOUT_SECONDS",
    "readiness_timeout_seconds": "READINESS_TIMEOUT_SECONDS",
    "readiness_probe_writes": "READINESS_PROBE_WRITES",
    "request_timeout_seconds": "REQUEST_TIMEOUT_SECONDS",
    "shutdown_timeout_seconds": "SHUTDOWN_TIMEOUT_SECONDS",
    "service_name": "SERVICE_NAME",
    "service_version": "SERVICE_VERSION",
    "required_dependencies": "REQUIRED_DEPENDENCIES",
}

#: 票据签名机密来源（按优先级尝试）。值一律不落盘、不入配置对象。
TICKET_SECRET_HEX_ENV = f"{ENV_PREFIX}TICKET_SECRET_HEX"
TICKET_SECRET_FILE_ENV = f"{ENV_PREFIX}TICKET_SECRET_FILE"
OPENBAO_TOKEN_ENV = f"{ENV_PREFIX}OPENBAO_TOKEN"


def resolve_ticket_secret(environ: Mapping[str, str] | None = None) -> tuple[bytes | None, str]:
    """返回 ``(secret, source)``；没有配置时返回 ``(None, "unset")``。"""

    environ = os.environ if environ is None else environ
    raw_hex = (environ.get(TICKET_SECRET_HEX_ENV) or "").strip()
    if raw_hex:
        try:
            secret = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ConfigError(
                "C005_TICKET_SECRET_INVALID",
                f"{TICKET_SECRET_HEX_ENV} 必须是十六进制字符串",
            ) from exc
        if len(secret) < 32:
            raise ConfigError(
                "C005_TICKET_SECRET_INVALID",
                f"{TICKET_SECRET_HEX_ENV} 至少需要 32 字节（64 个十六进制字符）",
            )
        return secret, "environment_variable"

    secret_file = (environ.get(TICKET_SECRET_FILE_ENV) or "").strip()
    if secret_file:
        path = Path(secret_file)
        if not path.is_file():
            raise ConfigError(
                "C006_TICKET_SECRET_FILE_MISSING", f"票据机密文件不存在：{path}"
            )
        content = path.read_text(encoding="utf-8").strip()
        try:
            secret = bytes.fromhex(content)
        except ValueError:
            secret = content.encode("utf-8")
        if len(secret) < 32:
            raise ConfigError(
                "C005_TICKET_SECRET_INVALID", "票据机密文件内容至少需要 32 字节"
            )
        return secret, "external_file"

    return None, "unset"


def resolve_openbao_token(environ: Mapping[str, str] | None = None) -> str:
    environ = os.environ if environ is None else environ
    return (environ.get(OPENBAO_TOKEN_ENV) or "").strip()


def load_config(
    environ: Mapping[str, str] | None = None,
    config_file: Path | str | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> ServiceConfig:
    """按 默认值 < 配置文件 < 环境变量 < 显式覆盖 的顺序合并配置。"""

    environ = os.environ if environ is None else environ
    defaults = ServiceConfig()
    values: dict[str, Any] = {}

    file_path = config_file if config_file is not None else _env(environ, "CONFIG_FILE")
    if file_path:
        for key, value in load_config_file(file_path).items():
            if not hasattr(defaults, key):
                raise ConfigError("C007_UNKNOWN_CONFIG_KEY", f"未知配置项：{key}")
            values[key] = _coerce(key, value, getattr(defaults, key))

    for field_name, suffix in ENV_FIELD_MAP.items():
        raw = _env(environ, suffix)
        if raw is not None:
            values[field_name] = _coerce(field_name, raw, getattr(defaults, field_name))

    for key, value in (overrides or {}).items():
        if not hasattr(defaults, key):
            raise ConfigError("C007_UNKNOWN_CONFIG_KEY", f"未知配置项：{key}")
        values[key] = value

    if values.get("opa_mode", defaults.opa_mode) not in OPA_MODES:
        raise ConfigError(
            "C004_INVALID_VALUE", f"opa_mode 只能是 {OPA_MODES}"
        )
    signer_mode = values.get("signer_mode", defaults.signer_mode)
    if signer_mode not in SIGNER_MODES:
        raise ConfigError("C004_INVALID_VALUE", f"signer_mode 只能是 {SIGNER_MODES}")

    port = int(values.get("port", defaults.port))
    if not 0 <= port <= 65535:
        raise ConfigError("C004_INVALID_VALUE", "port 必须在 0-65535 之间")

    # fail-closed：签名能力必须在启动前就确定，不允许运行期回落到随机密钥。
    if signer_mode == "hmac_env":
        secret, source = resolve_ticket_secret(environ)
        if secret is None:
            raise ConfigError(
                "C008_TICKET_SECRET_REQUIRED",
                f"signer_mode=hmac_env 需要 {TICKET_SECRET_HEX_ENV} 或 "
                f"{TICKET_SECRET_FILE_ENV}；服务拒绝以随机临时密钥启动。",
            )
        values["ticket_secret_source"] = source
    else:
        if not values.get("openbao_address", defaults.openbao_address):
            raise ConfigError(
                "C009_OPENBAO_ADDRESS_REQUIRED",
                "signer_mode=openbao_transit 需要 AGENTGUARD_OPENBAO_ADDR",
            )
        if not resolve_openbao_token(environ):
            raise ConfigError(
                "C010_OPENBAO_TOKEN_REQUIRED",
                f"signer_mode=openbao_transit 需要 {OPENBAO_TOKEN_ENV}",
            )
        values["ticket_secret_source"] = "openbao_transit"

    if values.get("oidc_enabled", defaults.oidc_enabled) and not values.get(
        "oidc_issuer", defaults.oidc_issuer
    ):
        raise ConfigError(
            "C011_OIDC_ISSUER_REQUIRED", "oidc_enabled=true 时必须提供 oidc_issuer"
        )

    required = values.get("required_dependencies", defaults.required_dependencies)
    unknown = set(required) - {"opa", "signer", "ticket_state", "identity"}
    if unknown:
        raise ConfigError(
            "C004_INVALID_VALUE", f"required_dependencies 包含未知依赖：{sorted(unknown)}"
        )

    merged = {**asdict(defaults), **values}
    merged["required_dependencies"] = tuple(merged["required_dependencies"])
    return ServiceConfig(**merged)

"""AgentGuard 网关服务入口：可配置启动、健康探针与依赖可用性判定。"""

from .app import AgentGuardService
from .config import ConfigError, ServiceConfig, load_config
from .health import DependencyProbes, ProbeResult, liveness, readiness_canary
from .opa_runtime import ResidentOpaProcess, build_opa_client

__all__ = [
    "AgentGuardService",
    "ConfigError",
    "DependencyProbes",
    "ProbeResult",
    "ResidentOpaProcess",
    "ServiceConfig",
    "build_opa_client",
    "liveness",
    "load_config",
    "readiness_canary",
]

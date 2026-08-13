# ToolHive 接入位置与测试边界

ToolHive 可作为 MCP Server 的容器化运行与治理层，放在 Agent 与本项目强制执行网关之间或作为受控工具后端。生产接入时，应让所有 MCP 调用经过身份校验、OPA 决策和执行票据核销，并把 MCP Server 限制在最小权限容器中。

当前测试机没有 Docker/WSL Linux 发行版，因此没有运行 ToolHive 容器，也不把 ToolHive 标记为“已集成实测”。本项目已经用可在 Windows 运行的 Wasmtime 完成了安全内核可行性验证；将来部署 ToolHive 时仍需测试容器逃逸面、挂载目录、网络出口、凭据注入、镜像签名和 MCP 直接连接绕过。

开源地址：https://github.com/stacklok/toolhive

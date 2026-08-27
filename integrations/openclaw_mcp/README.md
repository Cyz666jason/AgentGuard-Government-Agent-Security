# AgentGuard × OpenClaw 最小 MCP 接入

这是一个纯 Python 标准库的 stdio MCP Server。它只暴露
`list_notices` 一个低风险、只读工具。代码不导入 SQLite 或业务适配器，
实际调用固定发送到 AgentGuard `POST /invoke`，因此仍经过策略决策、一次性票据、
安全内核和审计链。

## 架构与边界

```text
OpenClaw / 其他 MCP Client
        │ stdio JSON-RPC（tools/list、tools/call）
        ▼
本目录的只读 MCP 适配器
        │ HTTPS + Bearer，固定 POST /invoke
        ▼
AgentGuard（身份校验 → OPA → 票据 → 安全内核 → 审计）
        │ 仅在放行后
        ▼
受控公告查询适配器 / 业务 API
```

- MCP 参数只有 `limit`，不能传 subject、resource、tool、operation 或审批结果。
- 推荐身份方式是 OIDC Bearer。令牌由受控文件注入并在每次调用时重读，不能作为
  tool argument 由模型提供。AgentGuard 会用验签后的 JWT claims 整体覆盖占位 subject。
- `loopback_static_dev` 只用于本机测试：必须连接 IP 字面量回环地址并从运维侧 JSON
  文件读取身份。它不能用于远程或生产部署。
- HTTP 仅允许回环地址；远程地址强制 HTTPS。禁用系统代理和 HTTP 重定向，避免令牌
  被转发到其他主机。
- 响应只返回公告字段，不返回执行票据、action digest、ticket JTI 或内部配置。

## 本地协议兼容测试

先启动启用了本地测试业务适配器的 AgentGuard，再设置：

```powershell
$env:AGENTGUARD_MCP_BASE_URL = 'http://127.0.0.1:8080'
$env:AGENTGUARD_MCP_IDENTITY_MODE = 'loopback_static_dev'
$env:AGENTGUARD_MCP_DEV_SUBJECT_FILE = (Resolve-Path '.\integrations\openclaw_mcp\dev-subject.example.json')
python -m integrations.openclaw_mcp.protocol_probe --report .\reports\e2e\openclaw\openclaw_mcp_protocol_probe.json
```

报告会保存命令、版本、输入、输出和进程退出码，并明确标记
`openclaw_runtime_used=false`。因此这一步只能称为“协议兼容测试”。

## OpenClaw 注册与实机探针

根据 OpenClaw 官方 MCP CLI，可用已实测的 `mcp set` 形式注册 stdio server，
并只允许这一项工具：

```powershell
$definition = @{
  command = 'C:\path\to\OPA政企智能体安全原型\.venv\Scripts\python.exe'
  args = @('-m', 'integrations.openclaw_mcp')
  cwd = 'C:\path\to\OPA政企智能体安全原型'
  env = @{
    AGENTGUARD_MCP_BASE_URL = 'https://agentguard.internal.example'
    AGENTGUARD_MCP_IDENTITY_MODE = 'oidc'
    AGENTGUARD_MCP_TOKEN_FILE = 'C:\secure\agentguard-user.token'
    AGENTGUARD_MCP_CA_BUNDLE = 'C:\secure\internal-ca.pem'
  }
  requestTimeoutMs = 20000
  connectionTimeoutMs = 8000
  supportsParallelToolCalls = $false
  toolFilter = @{ include = @('list_notices') }
} | ConvertTo-Json -Compress -Depth 8

$node = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
$projectRoot = (Resolve-Path '.').Path  # 从项目根目录执行
$openclawEntry = Join-Path $projectRoot 'third_party\runtime\openclaw-client\node_modules\openclaw\openclaw.mjs'

& $node $openclawEntry mcp set agentguard-notices $definition
& $node $openclawEntry mcp doctor agentguard-notices --probe --json
& $node $openclawEntry mcp probe agentguard-notices --json
```

本机已使用项目内固定版 OpenClaw `2026.7.1-2 (0790d9f)` 完成注册、
Control UI、`doctor --probe` 和真实 `tools/list`，发现且只发现
`agentguard-notices__list_notices`。确定性 MCP 客户端与经授权中转模型分别完成了
低风险调用：前者证明协议链，后者在新的 OpenClaw agent 会话中真实发起
`list_notices(limit=2)`，并由 AgentGuard 审计关联到 OPA 授权和隔离执行。

完整证据分别见 `reports/e2e/openclaw/openclaw_mcp_integration.json`、
`openclaw_agentguard_visual_demo.json`、`openclaw_agentguard_control_ui_turn.json` 与
`openclaw_agentguard_model_turn.json`。其中 Control UI 报告和配套截图证明模型调用、
`limit=2` 输入、隔离工具输出与最终回答确实同时显示在已认证网页会话中。
这些回合使用回环静态测试身份和隔离合成数据，不能表述为生产用户接入。

## 生产化缺口

- 每用户短时 OIDC access token 的签发、刷新、撤销和安全落盘；stdio 进程建议一用户
  一实例，禁止多个用户共享一个服务账号令牌。
- AgentGuard 与 MCP 主机之间的内部 CA/mTLS、网络策略及证书轮换。
- 真实公告业务 API 凭据和脱敏生产数据验证。
- 使用生产模型路由、逐用户 OIDC 身份与真实授权数据的持续回合审计证据。
- 并发、超时、断网、OIDC/OPA 故障与审计对账的预生产测试。

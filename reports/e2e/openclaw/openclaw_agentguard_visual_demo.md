# OpenClaw Control UI × AgentGuard 演示验证报告

- 生成时间：`2026-08-27T18:15:26.7596731Z`
- 总体状态：`passed_with_declared_scope`
- OpenClaw：`OpenClaw 2026.7.1-2 (0790d9f)`
- Control UI：`http://127.0.0.1:18789/`

## 已证明的范围

- 项目内 OpenClaw runtime 实际运行，Gateway 的 Control UI HTTP 页面可访问。
- OpenClaw 已在隔离状态目录中注册唯一的 `agentguard-notices`，并实际执行 `mcp list`、`doctor --probe` 与 `probe`。
- 实际 `tools/list` schema 只公开 `list_notices(limit: integer, 1..100)`，且标为只读、非破坏性。

## 命令退出码

| 命令 | 退出码 |
|---|---:|
| `& <NODE> <OPENCLAW_ENTRY> gateway health --port <PORT> --json` | 0 |
| `& <NODE> <OPENCLAW_ENTRY> mcp list --json` | 0 |
| `& <NODE> <OPENCLAW_ENTRY> mcp doctor agentguard-notices --probe --json` | 0 |
| `& <NODE> <OPENCLAW_ENTRY> mcp probe agentguard-notices --json` | 0 |
| `<PYTHON> -m integrations.openclaw_mcp.protocol_probe --skip-call --report <REPORT>` | 0 |

## 范围边界

- Gateway is bound only to loopback and uses a local temporary token that is stored only below the Git-ignored visual-demo runtime directory and the child-process environment.
- The Control UI HTTP response proves the page is served; this report deliberately does not transfer the Gateway token into a browser or execute an authenticated UI session.
- OpenClaw mcp probe establishes a real MCP session and performs tools/list, but it does not perform tools/call.
- The protocol probe uses --skip-call. The separate model-turn evidence is required before claiming a model-driven tool call.
- This report does not record a model API key or model provider credential.

独立模型回合证据：

- `reports/e2e/openclaw/openclaw_agentguard_model_dataset.json`
- `reports/e2e/openclaw/openclaw_agentguard_model_turn.json`
- `reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json`

上述报告分别覆盖固定模型测试集、CLI 真实模型回合和已认证 Control UI 模型回合；
它们不改变本演示仅覆盖 Gateway/注册/诊断/发现的范围，也不代表公网部署或生产就绪。

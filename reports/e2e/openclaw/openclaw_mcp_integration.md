# OpenClaw × AgentGuard 最小接入实测报告

- 生成时间：`2026-08-20T09:41:30.639378+00:00`
- 总体状态：`passed_with_declared_scope`
- OpenClaw：`OpenClaw 2026.7.1-2 (0790d9f)`
- MCP 适配器：`0.1.0`

## 可对外表述

本历史报告生成于 2026-08-20，记录了 OpenClaw 2026.7.1-2 的实机注册、doctor、MCP tools/list 和确定性只读 tools/call。该报告范围当时未配置模型凭据，因此没有执行 OpenClaw agent 模型回合；这不是对后续模型证据的否定。2026-08-27 的独立模型回合证据见 `openclaw_agentguard_model_dataset.*`、`openclaw_agentguard_model_turn.*` 和 `openclaw_agentguard_control_ui_turn.*`。

## 实测结果

| 检查 | 结果 |
|---|---:|
| agentguard_ready | 通过 |
| openclaw_cli_started | 通过 |
| openclaw_registration_saved | 通过 |
| openclaw_static_doctor_and_live_probe_passed | 通过 |
| openclaw_tools_list_found_only_readonly_tool | 通过 |
| protocol_initialize_and_tools_list_passed | 通过 |
| low_risk_call_executed_without_business_side_effect | 通过 |
| agentguard_audit_record_created | 通过 |
| every_recorded_process_exited_zero | 通过 |

## 低风险调用

- 工具：`list_notices`
- 返回条数：`2`
- 副作用：`False`
- 调用层级：确定性 MCP `tools/call` → 真实本机 AgentGuard → OPA → 一次性票据 → Wasmtime → 隔离测试公告 SQLite。
- 限定：本历史报告范围没有使用模型凭据运行 OpenClaw agent 回合，因此本报告不单独声称模型自主调用；后续模型回合由独立报告记录。

## 证据边界

- OpenClaw 官方 CLI 已实际完成注册、静态诊断和 `probe`，并发现唯一工具。
- OpenClaw `probe` 证明真实 MCP 连接与 `tools/list`；它不执行 `tools/call`。
- 低风险调用由项目内确定性 MCP 客户端执行，输入、输出和退出码保存在同名 JSON 报告。
- 使用的是隔离测试身份与隔离测试数据，不是生产用户凭据或生产数据。
- 本报告只代表 2026-08-20 的注册/协议测试范围；后续模型证据、远程 HTTP 传输证据和生产化验收必须分别查看各自报告。

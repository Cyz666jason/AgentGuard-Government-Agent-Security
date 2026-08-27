# OpenClaw Control UI × AgentGuard 已认证模型回合报告

- 生成时间：`2026-08-27T00:12:07.1830027Z`
- 总体状态：`passed_with_declared_scope`
- 页面：`http://127.0.0.1:18790/`
- 模型：`modelflare/gpt-5.6-sol`
- 会话来源：OpenClaw Control UI 新建 `dashboard` 会话

## 页面中实际完成的回合

用户在已认证 Control UI 中要求模型只调用 `agentguard-notices__list_notices`，参数固定为：

```json
{"limit": 2}
```

页面展开的工具卡实际显示：

- Tool input：`{"limit": 2}`
- Tool output：`status=executed_isolated`、`reason_code=G000_EXECUTED`
- 返回 2 条隔离测试公告
- `side_effect=false`

模型随后依据工具结果回答了两条公告，并明确说明本次查询没有副作用。

## 页面证据

工具调用、输入参数与执行状态：

![OpenClaw Control UI 工具调用](openclaw_agentguard_control_ui_turn.png)

完整两条结果、`side_effect=false` 与最终回答：

![OpenClaw Control UI 工具结果](openclaw_agentguard_control_ui_result.png)

## AgentGuard 审计关联

- 同一请求 `mcp-req-49131a4f77484e91a4e6ab83d516fc89` 依次记录 `authorized` 与 `executed_isolated`。
- 审计参数为 `limit=2`、`item_count=2`，工具为 `database.query`。
- Wasmtime 隔离执行状态为 `executed_isolated`，`host_imports_allowed=false`、`wasi_enabled=false`。
- 审计只保存票据标识，不保存票据值。

## 检查结果

| 检查 | 结果 |
|---|---:|
| authenticated_control_ui_session_established | 通过 |
| gateway_online_indicator_visible | 通过 |
| configured_provider_and_model_used | 通过 |
| new_dashboard_session_created | 通过 |
| model_initiated_tool_call | 通过 |
| only_allowed_tool_called | 通过 |
| tool_input_limit_equals_two | 通过 |
| tool_result_not_error | 通过 |
| tool_result_executed_isolated | 通过 |
| tool_result_contains_two_rows | 通过 |
| tool_result_has_no_side_effect | 通过 |
| final_answer_grounded_in_tool_rows | 通过 |
| agentguard_authorized_and_executed_same_request | 通过 |
| agentguard_ticket_value_not_recorded | 通过 |
| browser_tool_card_and_answer_visible | 通过 |
| secret_values_not_recorded | 通过 |

## 证据边界

- 本报告证明模型在已认证 OpenClaw Control UI 会话中真实调用 AgentGuard MCP 工具，不只是 CLI 或协议探测。
- 回合使用回环静态测试身份与隔离合成公告，不代表生产身份、生产数据或生产就绪。
- Gateway token、模型 API Key、临时票据值与本机绝对路径均未写入报告或截图。

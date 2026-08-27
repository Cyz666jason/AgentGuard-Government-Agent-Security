# OpenClaw × AgentGuard 真实模型回合报告

- 生成时间：`2026-08-27T18:21:08.1738251Z`
- 总体状态：`passed_with_declared_scope`
- 模型：`modelflare/gpt-5.6-sol`
- 模型回合退出码：`0`
- 模型发起工具调用：`agentguard-notices__list_notices`，`limit=2`

## 模型回答

1. 政务服务系统维护通知（信息中心，2026-08-01）
2. 第三季度材料归档安排（综合办公室，2026-08-03）

## 检查结果

| 检查 | 结果 |
|---|---:|
| fixed_project_local_openclaw_version | 通过 |
| isolated_gateway_loaded_current_config | 通过 |
| loopback_gateway_and_agentguard_only | 通过 |
| model_secret_ref_configured | 通过 |
| model_call_succeeded | 通过 |
| configured_provider_and_model_used | 通过 |
| model_initiated_exactly_one_allowed_tool_call | 通过 |
| openclaw_tool_summary_matches_transcript | 通过 |
| mcp_tool_result_succeeded | 通过 |
| result_is_two_read_only_isolated_rows | 通过 |
| final_answer_grounded_in_tool_rows | 通过 |
| agentguard_authorized_and_executed_same_request | 通过 |
| agentguard_ticket_value_not_recorded | 通过 |
| opa_was_healthy_for_turn | 通过 |

## 证据链

- OpenClaw 新会话转录中存在模型 assistant 角色发起的唯一 MCP toolCall。
- 对应 toolResult 返回 `executed_isolated`、2 条隔离测试公告和 `side_effect=false`。
- AgentGuard 审计以同一 request_id 记录 `authorized` 与 `executed_isolated`，票据值未记录。
- 调用期间 OPA 常驻服务健康，Gateway 仅绑定回环地址。

## 范围边界

- 本报告证明授权中转模型在本机隔离演示环境中真实发起了只读工具调用。
- 使用回环静态测试身份与隔离合成数据，不代表生产身份、生产数据或生产就绪。
- 模型 API Key、Gateway token、临时票据密钥和本机绝对路径均未写入报告。

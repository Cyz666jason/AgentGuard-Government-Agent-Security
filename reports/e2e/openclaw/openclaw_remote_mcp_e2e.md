# OpenClaw 远程 MCP 本地双用户 E2E 报告

- 生成时间：`2026-08-27T21:31:40.293071+00:00`
- 状态：`passed_with_declared_scope`
- 证据哈希：`b94b688ce8e8dceff9d32420098898b12ae446d5c1291e8386b2320c4c2ac1e7`

## 结论

真实回环 HTTP 请求已完成远程 MCP 认证、双用户会话隔离、tools/list 和只读 tools/call；本地使用合成 OIDC 与合成公告数据；本报告只覆盖远程传输/认证协议范围，不执行公网部署或 OpenClaw 模型回合，独立模型证据见对应模型报告。

## 检查项

| 检查 | 结果 |
|---|---:|
| protected_resource_metadata_available | 通过 |
| missing_token_is_401 | 通过 |
| invalid_token_is_401 | 通过 |
| issuer_audience_resource_exp_and_scope_enforced | 通过 |
| wrong_origin_is_403 | 通过 |
| two_independent_sessions_initialized | 通过 |
| tools_list_only_exposes_readonly_tool | 通过 |
| both_users_readonly_call_has_no_side_effect | 通过 |
| tenant_scope_is_preserved_per_user | 通过 |
| cross_user_session_is_403 | 通过 |
| prompt_identity_override_is_rejected | 通过 |
| dangerous_tools_are_not_callable | 通过 |
| request_id_links_preflight_and_result_audit | 通过 |
| audit_keeps_user_a_and_b_distinct | 通过 |
| audit_contains_required_correlation_fields | 通过 |
| external_bearer_not_forwarded_to_backend | 通过 |
| runner_completed_without_exception | 通过 |
| report_scope_declares_no_public_deployment | 通过 |
| report_scope_declares_no_model_turn | 通过 |
| report_contains_no_credential_like_values | 通过 |

## 双用户证据

- 用户 A：`synthetic-user-a`，租户：`tenant-a`
- 用户 B：`synthetic-user-b`，租户：`tenant-b`
- 两个独立会话的身份由合成 OIDC 验证器产生，跨会话访问返回 403。
- 两次只读调用均返回 `side_effect=false`，下游收到的凭据参数为 `None`。

## 证据边界

- 这是本机回环地址上的真实 HTTP 请求，不是公网部署证明。
- 本次未连接 Keycloak、公网 DNS、Ingress/证书或真实业务 API。
- 本报告范围未运行 OpenClaw 模型回合；不能用本报告单独表述为模型自主调用完成，模型回合由独立报告覆盖。
- `production_ready=false` 必须保持不变。

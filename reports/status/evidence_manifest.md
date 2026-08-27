# 验证证据清单

生成时间：`2026-08-28T05:44:32+08:00`（中国标准时间）
测试源提交：`HEAD`；source tree hash：`97bd76d518c1c93b9cacae9533ad7b3ef1ba57c0`
测试开始时工作树干净：`False`；清单生成时工作树干净：`False`

## 环境

- OS：`Windows-11-10.0.26200-SP0`
- Python：`Python 3.12.13`；OPA：`Version: 1.19.0`；Node：`v24.19.0`；pnpm：`11.19.0`；OpenClaw：`OpenClaw 2026.7.1-2 (0790d9f)`
- OpenClaw为项目内安装，全局安装：`false`。

## 检查

| 检查 | 退出码 | 结果 | 执行时间 | 证据 |
|---|---:|---|---|---|
| OPA核心策略测试 | 0 | passed | 2026-08-28T05:08:22+08:00 | `reports/core/full_opa_tests.txt` |
| OPA-Envoy部署策略测试 | 0 | passed | 2026-08-28T05:08:22+08:00 | `reports/e2e/network/opa_envoy_policy_tests.txt` |
| Python全量安全回归 | 0 | passed | 2026-08-28T05:09:35+08:00 | `reports/core/full_python_tests.txt` |
| OPA核心55例评测 | 0 | passed | 2026-08-28T05:41:09+08:00 | `reports/core/evaluation_results.csv`；`reports/core/evaluation_summary.json`；`reports/core/evaluation_report.md` |
| 阶段4只读预检 | 2 | blocked_external_environment | 2026-08-28T05:35:06+08:00 | `reports/preflight/stage4_preflight.json`；`reports/preflight/stage4_preflight.md` |
| 发布前敏感信息扫描 | 0 | passed | 2026-08-28T05:44:23.526669+08:00 | `reports/status/prepublish_security_check.json` |
| 状态一致性检查 | 0 | passed | 2026-08-28T05:44:24+08:00 | `reports/status/status_consistency_check.json` |
| 项目内OpenClaw安装与命令可用性 | 0 | passed | 2026-08-27T04:31:40.3898995+08:00 | `reports/e2e/openclaw/openclaw_installation.json`；`reports/e2e/openclaw/openclaw_installation.md` |
| OpenClaw固定5例模型fixture | 0 | passed | 2026-08-27T18:19:45.1861768Z | `reports/e2e/openclaw/openclaw_agentguard_model_dataset.json` |
| OpenClaw CLI真实模型回合 | 0 | passed | 2026-08-27T18:21:08.1738251Z | `reports/e2e/openclaw/openclaw_agentguard_model_turn.json` |
| OpenClaw Control UI真实模型回合 | 0 | passed | 2026-08-27T00:12:07.1830027Z | `reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json` |
| OpenClaw远程MCP双用户HTTP E2E | 0 | passed | 2026-08-27T21:35:05.845970+00:00 | `reports/e2e/openclaw/openclaw_remote_mcp_e2e.json`；`reports/e2e/openclaw/openclaw_remote_mcp_e2e.md` |

## 数据与边界

- `synthetic=true`，`benchmark_type=project_fixture`，不是公开基准成绩。
- 当前唯一允许工具：`agentguard-notices__list_notices`；身份为回环静态开发身份，数据为隔离合成 SQLite。
- `production_ready=false`。模型回合证据不替代生产 OIDC、TLS/mTLS、网络隔离、HA、真实业务凭据和持续审计验收。
- 报告和清单不记录 API Key、Gateway token、Cookie、票据值或其他秘密。

## 工件 SHA-256

| 类型 | 路径 | SHA-256 |
|---|---|---|
| dataset | `datasets/openclaw_agentguard_model_cases.jsonl` | `48b5b3f60c1c3415e58fdb4eb89114510f597f2352de439594c921dc3703128e` |
| dataset_metadata | `datasets/openclaw_agentguard_model_metadata.json` | `d7e8dcba1085ea706fd9f0dda3b2ab12a48a32bdb01dc50b641ccc3ed3857c66` |
| model_report | `reports/e2e/openclaw/openclaw_agentguard_model_dataset.json` | `969e551726541c78b97b4c20a50de4f071281f536ccbfc2c5acda2ed07c5f3c7` |
| transcript_and_audit_report | `reports/e2e/openclaw/openclaw_agentguard_model_turn.json` | `6bd7fd07a6fe35e0e2be8e764147ca3cc1cc28de3342abad27545984ae3213d0` |
| control_ui_and_audit_report | `reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json` | `bff3a8c3797a2cb039a8d6cbed6891e8b2fb0593c9ec59a2236a15275208c7cb` |
| screenshot | `reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.png` | `86d2b4f543a87e22de20d42007e0e8b352caf819e5d521cdf4bc9180d5e31f98` |
| screenshot | `reports/e2e/openclaw/openclaw_agentguard_control_ui_result.png` | `85191097441300183b1ef5a5a10bd9a4cc7b519b3f7b45b8b7fe110edeefd02d` |
| protocol_and_visual_report | `reports/e2e/openclaw/openclaw_agentguard_visual_demo.json` | `308531f7c874933282eb61e57ffb617395e68a10afa9bf883a498e91c29f305f` |
| installation_report | `reports/e2e/openclaw/openclaw_installation.json` | `7b655cc19681214abfad8762dc77c104065605484e0d9b75988b4fd285e533a3` |
| remote_mcp_e2e_report | `reports/e2e/openclaw/openclaw_remote_mcp_e2e.json` | `538fbf102a526b4e08203351ea0cdcc5bd11a9321f819c39e4629a6209c9ab54` |
| remote_mcp_e2e_summary | `reports/e2e/openclaw/openclaw_remote_mcp_e2e.md` | `4a5fe6fb5a853311355427b490b23edb37529ee160f95028b1125182658ed793` |
| evaluation_report | `reports/core/evaluation_summary.json` | `a1c778ec196c325e3ed1ca7a735ec5ec14b6c9c805710144dd3210d5fcd0cbb1` |
| test_log | `reports/core/full_python_tests.txt` | `25c0c6dfacd1ca8619fc38820e1cebeb76415a3e3668e17da2ca4b6a15eefae5` |
| test_log | `reports/core/full_opa_tests.txt` | `c13bf55306d5eb2efe7bbe19fe5c1c091338955a1c231fba2be0944b2e45e564` |

## Git忽略的本地证据哈希

原始转录和审计日志不随 Git 发布；以下仅记录本机忽略目录中的 SHA-256，便于本地完整性核对。

| 类型 | 路径 | SHA-256 | 可用性 |
|---|---|---|---|
| openclaw_cli_transcript | `integrations/openclaw_mcp/.e2e_state/visual-demo/state/agents/main/sessions/309c490b-0464-4d24-a4f0-0b682fc9049e.jsonl` | `9db834b503aafda0c190444e28ce25e46c1f1fc3b4d363619a5df30ff0c68f08` | `git_ignored_local_only` |
| openclaw_control_ui_trajectory | `integrations/openclaw_mcp/.e2e_state/visual-demo/state/agents/main/sessions/9513dfbb-eb51-4ed9-b813-5a2ad4c596bf.trajectory.jsonl` | `7d099301b333bb5bbe8340061766a2ca43da9216194b74dad37c5beaf4ec5b0a` | `git_ignored_local_only` |
| agentguard_enforcement_audit | `integrations/openclaw_mcp/.e2e_state/visual-demo/agentguard-state/enforcement_audit.jsonl` | `50511457990fae2aae1265f8c9d4d658241ae58c63cf7b8783e8b9789c1a28d8` | `git_ignored_local_only` |

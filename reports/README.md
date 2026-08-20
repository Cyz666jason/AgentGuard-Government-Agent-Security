# 测试与评估报告索引

`reports/` 只保存可公开、可复核的测试证据和状态摘要。运行时数据库、密钥、令牌、原始业务数据和临时日志不应进入 Git。

## 目录分组

| 目录 | 内容 | 主要证据 |
|---|---|---|
| [`core/`](core/) | OPA、Python 回归、覆盖率、批量评测和整体安全汇总 | `full_opa_tests.txt`、`full_python_tests.txt`、`evaluation_summary.json`、`full_security_evaluation_summary.json` |
| [`approval/`](approval/) | 人工审批工作流的单测、演示和量化结果 | `approval_evaluation_summary.json`、`approval_evaluation_report.md` |
| [`demos/`](demos/) | 允许、拒绝、待审批、重放、篡改、OPA 故障和安全内核演示 | `full_demo_*.json`、`gateway_audit.jsonl` |
| [`e2e/business/`](e2e/business/) | 授权业务 API 凭据门禁与数据脱敏结果 | `authorized_business_api_e2e.json`、`authorized_data_redaction.json` |
| [`e2e/identity/`](e2e/identity/) | Keycloak/OIDC 真实签名身份链路 | `keycloak_oidc_e2e.json` |
| [`e2e/network/`](e2e/network/) | 常驻 OPA REST、OPA-Envoy、ToolHive 和容器网络强制 | `network_enforcement_e2e.json`、`github_actions_container_product_e2e.json` |
| [`e2e/openbao/`](e2e/openbao/) | OpenBao Transit、共享核销和 Raft 故障切换 | `openbao_kms_ha_e2e.json`、`openbao_raft_ha_e2e.json` |
| [`e2e/isolation/`](e2e/isolation/) | QEMU 独立 Linux 来宾内核与容器产品链路 | `qemu_native_isolation_e2e.json`、`qemu_container_product_e2e.json` |
| [`e2e/openclaw/`](e2e/openclaw/) | OpenClaw 注册、MCP 工具发现和低风险协议调用 | `openclaw_mcp_integration.json`、`openclaw_mcp_integration.md` |
| [`evaluation/public-benchmarks/`](evaluation/public-benchmarks/) | AgentDojo、InjecAgent、AgentHarm 适配器契约测试 | `public_benchmark_fixture_smoke.json`、`public_benchmark_*_fixture.json` |
| [`status/`](status/) | 证据优先级、开源路线、生产化状态、发布与安全扫描 | `productionization_status.md`、`open_source_route_progress.md`、`status_consistency_check.json` |
| [`preflight/`](preflight/) | 外部输入、KVM、阶段4、测试机和 ToolHive 环境的只读预检 | `stage4_preflight.md`、`test_machine_environment.json` |

## 测试口径

- 不同层次的测试保持独立分母：OPA 策略、Python 回归、端到端场景、公开基准适配器不合并成一个“总准确率”。
- `public_benchmark_*_fixture.json` 使用自编合成 fixture，只证明转换、校验和评测契约可运行，不是上游公开基准成绩。
- 本机、GitHub Actions 和外部测试环境的证据不可混用；冲突结论按 `status/evidence_precedence.json` 的固定优先级裁决。
- “预检通过”只表示前置条件已准备，不表示产品实测完成。

## 证据边界

**这些报告不是生产证明。** 它们证明当前代码在报告明确记录的版本、时间、输入和测试环境中满足已定义的检查项；不能替代单位预生产集群验收、真实用户身份、授权业务凭据、脱敏生产数据、跨故障域高可用、mTLS/NetworkPolicy、负载测试和安全验收。

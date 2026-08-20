# AgentGuard 开源路线自动进度看板

> 自动生成时间：2026-08-20T18:32:48+08:00
> 当前测试机范围：**通过**；生产就绪：**否**。

## 五阶段路线

| 阶段 | 状态 | 证据 | 下一动作 |
|---|---|---|---|
| 1 赛题解读 | completed | docs/overview/开源路线自动推进总览_20260813.md#2-赛题解读题目怎样转化为工程任务 | 后续实现继续映射到感知—决策—调用—执行和赛题评分项 |
| 2 开源技术路线与选型 | completed | Keycloak + OPA + LangGraph + 强制网关 + Wasmtime + OPA-Envoy/ToolHive 容器链路 | 生产分支补跨故障域KMS/HA、Kubernetes NetworkPolicy/mTLS与Kata/Firecracker |
| 3 复现效果与问题 | completed_with_gaps | reports/core/full_security_evaluation_summary.json；reports/e2e/network/github_actions_container_product_e2e.json；reports/status/复现问题台账_20260813.md；reports/evaluation/public-benchmarks/public_benchmark_fixture_smoke.json（仅适配器契约） | 导入许可允许的真实公开样本并生成真实策略预测；外部产品实测继续按阶段4门禁执行 |
| 4 相关评估与数据支撑 | partial_external_inputs_required | 三层83条合成定义；三套公开基准适配器使用6条自编fixture验证；阶段4只读预检=blocked_external_environment | 取得许可数据和组织授权后，分别完成真实公开基准、盲测、红队、产品E2E与生产回放 |
| 5 整体大图与清晰语言 | completed | docs/architecture/整体开源技术路线图_20260813.mmd | 所有后续材料复用同一架构语言和边界表述 |

## 最新自动回归

| 检查项 | 结果 | 证据 |
|---|---:|---|
| OPA/Rego单元测试 | 31/31 | `reports/core/full_opa_tests.txt` |
| OPA-Envoy前置策略测试 | 4/4 | `reports/e2e/network/opa_envoy_policy_tests.txt` |
| 三态策略数据集 | 55/55 | `reports/core/evaluation_summary.json` |
| 身份/审批/网关/内核Python测试 | 173/173 | `reports/core/full_python_tests.txt` |
| 常驻OPA REST网络链路 | 5/5 | `reports/e2e/network/network_enforcement_e2e.json` |
| Keycloak/OIDC真实链路 | 7/7 | `reports/e2e/identity/keycloak_oidc_e2e.json` |
| 完整链路演示检查 | 23/23 | `reports/core/full_security_evaluation_summary.json` |
| OpenBao外部密钥与共享票据核销 | 10/10 | `reports/e2e/openbao/openbao_kms_ha_e2e.json` |
| OpenBao三节点Raft故障切换 | 8/8 | `reports/e2e/openbao/openbao_raft_ha_e2e.json` |
| QEMU独立Linux来宾内核隔离 | 11/11 | `reports/e2e/isolation/qemu_native_isolation_e2e.json` |

## 数据与性能

- 三层数据定义：83条（策略55、审批9、执行/内核19），均为合成数据。
- 公开基准适配：AgentDojo、InjecAgent、AgentHarm 三套转换/校验/独立分母管线已通过各2条自编fixture；未导入上游原始数据，不是公开基准成绩。
- 阶段4只读预检：`blocked_external_environment`；产品验证完成：否，生产就绪：否。
- 策略数据危险动作误放行：0；完整链路危险动作误执行：0。
- OPA CLI逐例端到端：均值65.316 ms，P95 72.694 ms；该值包含进程启动，不代表常驻服务纯策略延迟。
- 全部Rego文件总覆盖率：99.61%。

## 未完成边界

- **OPA-Envoy/ToolHive 容器 E2E 仅在 CI Linux Runner 完成**：GitHub Actions ubuntu-latest 上 10/10 通过，覆盖无票据拒绝、伪造票据拒绝、签名票据放行、重放拒绝、跨动作拒绝、后端无宿主端口、OPA 故障 fail-closed 与命名 MCP 容器运行；提交=167b2b0445ca；本机 Windows 无容器运行时，该历史失败记录已标注被取代 下一步：在单位预生产 Kubernetes 集群补 NetworkPolicy、mTLS 与跨节点故障注入
- **Keycloak 当前为本机开发模式测试域**：真实 Keycloak 26.7.1、JWT签名、issuer、audience、角色、部门、密级和MFA声明已 7/7 实测；测试密码改为每次随机生成，但测试域仍使用HTTP和合成MFA声明 下一步：生产改用 HTTPS、组织目录联邦、真实 OTP/WebAuthn 认证流程和密钥轮换，删除测试用户与固定 MFA mapper
- **尚未连接真实外部业务系统**：HTTPS、CA、主机白名单、幂等键、显式写操作双确认、金额上限、可信OIDC审批和结果未知对账均已实现；未获得单位批准的预生产URL、令牌和CA 下一步：获得合法测试凭据后运行真实API E2E；不得生成、猜测或把本地模拟凭据称为真实凭据
- **生产KMS/HA仍需跨故障域加固**：OpenBao票据与审批独立Transit密钥/共享KV 10/10及三节点Raft选主、复制、leader故障切换8/8已完成，但三个节点仍位于同一Windows测试机且关闭TLS 下一步：预生产跨故障域部署，启用TLS与自动解封，并补快照恢复、网络分区和容量压测
- **Kata/Firecracker产品隔离尚未运行**：QEMU独立Linux来宾内核/Alpine用户态/只读启动介质 11/11已验证无网络、无宿主目录和资源限制，但当前为TCG软件模拟 下一步：在Linux/KVM测试机运行Kata或Firecracker产品E2E和性能测试
- **默认演示仍保留 OPA CLI 调用**：网络端到端测试已使用常驻 OPA REST；部分旧演示为便于单文件复现仍逐次启动 CLI 下一步：生产统一切换至 OPA sidecar/OPA-Envoy/Go SDK 或 Wasm 常驻求值，并做压力测试
- **数据仍以合成场景为主**：确定性去标识、秘密删除、IP泛化和哈希报告流水线已实现；AgentDojo/InjecAgent/AgentHarm转换、严格校验和独立分母评测入口已用6条自编fixture验证，但尚未导入上游全量原始数据，也未获得单位批准的真实日志 下一步：按许可取得公开基准并生成真实策略预测；获得数据授权后运行脱敏脚本，隔离训练/调参与盲测数据并开展回放
- **公开仓库已发布，但公开不等于生产验收**：reports/status/github_publication.json 实测远程仓库匿名可读且可见性为 public；密钥、授权数据与运行态状态目录仍被 .gitignore 与发布前扫描挡在仓库外 下一步：保持发布前秘密扫描为 CI 必过项；对外材料继续区分“已开源”与“已生产就绪”

## 统计口径

各测试层的分母保持独立；不把单元测试、数据定义和演示检查相加为一个准确率。当前结论仅覆盖本机、当前代码版本和已定义场景，不能表述为已经生产就绪或系统绝对安全。

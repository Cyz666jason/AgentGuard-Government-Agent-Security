# AgentGuard 生产化自动推进状态

生成时间：2026-08-28T02:49:22.931498+08:00

## 证据优先级

状态不手工写死，由 `evidence/precedence.py` 裁决：

1. 与当前提交历史匹配的 CI 实测证据；
2. 当前机器产生的新鲜实测证据；
3. 与当前提交无关的 CI 证据；
4. 历史环境检查与历史失败记录。

因此本机缺少容器运行时产生的历史失败**不会**覆盖 GitHub Linux Runner 的成功结果；
被取代的历史文件保留原始测量值，并在文件内 `superseded_by` 字段注明测试时间、
测试环境与取代它的新证据。裁决明细见 `reports/status/evidence_precedence.json`。

| 内容 | 状态 | 当前证据 | 尚缺条件/边界 |
|---|---|---|---|
| OPA-Envoy产品容器E2E | completed_ci_test_environment | reports/e2e/network/github_actions_container_product_e2e.json（ci_evidence_ancestor_commit，环境=github_actions/ubuntu-latest，测试时间=2026-08-14T10:40:28.621959+00:00）：GitHub Actions ubuntu-latest 10/10；https://github.com/Cyz666jason/AgentGuard-Government-Agent-Security/actions/runs/31793116819；该提交之后本地又有 5 个提交，未被这次 CI 覆盖；已取代的历史记录：reports/e2e/network/container_product_e2e_attempt.json（local_fresh_evidence，2026-08-28T02:38:32.469688+08:00）；reports/preflight/test_machine_environment.json（historical_environment_check，2026-08-20T17:03:55+08:00） | 已在 GitHub Linux Runner 容器环境实测；本机 Windows 无 Docker/Podman，生产仍需 mTLS 与 NetworkPolicy 加固 |
| ToolHive MCP容器E2E | completed_ci_test_environment | CLI/checksum=True；reports/e2e/network/github_actions_container_product_e2e.json（ci_evidence_ancestor_commit，环境=github_actions/ubuntu-latest，测试时间=2026-08-14T10:40:28.621959+00:00）：GitHub Actions ubuntu-latest 10/10；https://github.com/Cyz666jason/AgentGuard-Government-Agent-Security/actions/runs/31793116819；该提交之后本地又有 5 个提交，未被这次 CI 覆盖；已取代的历史记录：reports/e2e/network/container_product_e2e_attempt.json（local_fresh_evidence，2026-08-28T02:38:32.469688+08:00）；reports/preflight/test_machine_environment.json（historical_environment_check，2026-08-20T17:03:55+08:00）；reports/preflight/toolhive_environment_check.json（historical_environment_check，2026-08-07T08:43:13+08:00） | 已在 GitHub Linux Runner 观察到命名 MCP 工作负载容器运行；doctor 在临时 Runner 上返回 1，仅作环境提示不作功能判定 |
| 外部密钥与共享票据状态 | completed_ha_test_environment | OpenBao Transit+KV 10/10（run_id=standalone，测试时间=2026-08-28T02:36:24.652309+08:00，证据年龄=0.22h，fresh）；三节点Raft故障切换 8/8（run_id=standalone，测试时间=2026-08-28T02:37:19.110116+08:00，证据年龄=0.2h，fresh） | 本机三进程已验证HA；正式生产仍需跨故障域、TLS、自动解封、备份恢复和容量压测 |
| 原生程序独立来宾内核隔离 | completed_test_environment | QEMU guest kernel 11/11（run_id=standalone，测试时间=2026-08-28T02:38:21.799585+08:00，证据年龄=0.18h，fresh） | 不是Kata/Firecracker，当前为TCG软件模拟且无KVM |
| 阶段4外部环境与授权输入预检 | blocked_external_environment | 只读预检：prepared=0，awaiting=1，blocked=4；production_ready=false，product_validation_completed=false；报告=reports/preflight/stage4_preflight.json | 预检只核对本地前置条件、非密配置和授权输入，不替代KVM、跨故障域、Kubernetes、身份基础设施或真实业务产品E2E |
| 真实业务系统凭据与E2E | awaiting_authorized_input | HTTPS、主机白名单、CA、幂等键、双确认写门、可信OIDC审批与对账状态已实现；报告=skipped_missing_authorized_credentials | 未提供单位批准的预生产URL、令牌、CA和审批人OIDC令牌，不会生成或猜测真实凭据 |
| 脱敏生产数据 | awaiting_authorized_input | 确定性去标识、秘密字段删除、IP泛化和SHA-256报告已实现 | 未提供获批原始日志；测试样例不能冒充生产数据 |
| 远程GitHub仓库发布 | published_public | reports/status/github_publication.json（historical_environment_check，环境=git_remote_probe，测试时间=2026-08-20T10:32:44+00:00）：remote=https://github.com/Cyz666jason/AgentGuard-Government-Agent-Security.git；visibility=public；probe=anonymous_git_ls_remote | 仓库已公开可读；公开发布不等于生产验收，密钥与授权数据仍不入库 |
| OpenClaw模型、CLI与Control UI回环E2E（测试范围） | completed_test_environment | reports/e2e/openclaw/openclaw_agentguard_model_dataset.json；reports/e2e/openclaw/openclaw_agentguard_model_turn.json；reports/e2e/openclaw/openclaw_agentguard_control_ui_turn.json（核验时间=2026-08-27T18:21:08.1738251Z；固定合成模型测试集=5/5；CLI检查=14/14；Control UI检查=16/16） | 固定5例合成模型测试集、CLI真实模型回合和已认证Control UI回合均通过；仅限回环静态开发身份、隔离合成SQLite与只读工具，不代表生产接入 |

## 生产就绪

`production_ready` = **false**。仍未满足的硬性条件：

- Kata/Firecracker 产品级 KVM 隔离未在 Linux/KVM 环境验证
- OpenBao 跨故障域、TLS、自动解封、快照恢复与容量压测未验证
- Kubernetes NetworkPolicy 与 mTLS 未在真实集群验证
- Keycloak HTTPS、高可用、目录联邦与真实 MFA 未验证
- 未接入单位授权的真实业务 API
- 未获得授权生产数据用于脱敏与回放

## 结论

已经自动完成 OpenBao 外部密钥与共享票据状态验证、三节点 Raft 选主/复制/主节点故障切换、
QEMU 独立 Linux 来宾内核隔离、OPA-Envoy 与 ToolHive 的 Linux 容器 E2E（GitHub Actions 实测）、
OpenClaw 固定合成模型测试集与 CLI/Control UI 回环模型回合（测试范围）、公开仓库发布、真实业务 HTTPS 接入代码、生产数据脱敏流水线，以及阶段4只读预检与验收模板。需要 Linux/KVM、多台服务器、
单位授权数据或真实预生产凭据的项目保留为外部阻塞，只允许使用
`awaiting_authorized_input`、`blocked_external_environment`、
`configuration_prepared_not_verified` 三种状态，不能自动伪造为完成。

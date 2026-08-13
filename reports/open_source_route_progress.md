# AgentGuard 开源路线自动进度看板

> 自动生成时间：2026-08-14T03:07:41+08:00
> 当前测试机范围：**通过**；生产就绪：**否**。

## 五阶段路线

| 阶段 | 状态 | 证据 | 下一动作 |
|---|---|---|---|
| 1 赛题解读 | completed | docs/开源路线自动推进总览_20260813.md#2-赛题解读题目怎样转化为工程任务 | 后续实现继续映射到感知—决策—调用—执行和赛题评分项 |
| 2 开源技术路线与选型 | completed | Keycloak + OPA + LangGraph + 强制网关 + Wasmtime | 生产分支补OPA-Envoy、ToolHive、KMS/HA与原生隔离 |
| 3 复现效果与问题 | completed_with_gaps | reports/full_security_evaluation_summary.json；reports/复现问题台账_20260813.md | 补产品级容器E2E、并发、故障注入和真实业务适配器 |
| 4 相关评估与数据支撑 | partial | 三层83条合成定义；各类测试分母独立统计 | 取得授权后加入脱敏日志、盲测集、红队和生产回放 |
| 5 整体大图与清晰语言 | completed | docs/整体开源技术路线图_20260813.mmd | 所有后续材料复用同一架构语言和边界表述 |

## 最新自动回归

| 检查项 | 结果 | 证据 |
|---|---:|---|
| OPA/Rego单元测试 | 31/31 | `reports/full_opa_tests.txt` |
| OPA-Envoy前置策略测试 | 4/4 | `reports/opa_envoy_policy_tests.txt` |
| 三态策略数据集 | 55/55 | `reports/evaluation_summary.json` |
| 身份/审批/网关/内核Python测试 | 46/46 | `reports/full_python_tests.txt` |
| 常驻OPA REST网络链路 | 5/5 | `reports/network_enforcement_e2e.json` |
| Keycloak/OIDC真实链路 | 5/5 | `reports/keycloak_oidc_e2e.json` |
| 完整链路演示检查 | 17/17 | `reports/full_security_evaluation_summary.json` |
| OpenBao外部密钥与共享票据核销 | 7/7 | `reports/openbao_kms_ha_e2e.json` |
| QEMU独立Linux来宾内核隔离 | 9/9 | `reports/qemu_native_isolation_e2e.json` |

## 数据与性能

- 三层数据定义：83条（策略55、审批9、执行/内核19），均为合成数据。
- 策略数据危险动作误放行：0；完整链路危险动作误执行：0。
- OPA CLI逐例端到端：均值67.653 ms，P95 75.892 ms；该值包含进程启动，不代表常驻服务纯策略延迟。
- 全部Rego文件总覆盖率：99.61%。

## 未完成边界

- **Envoy/ToolHive 指定产品的容器部署未启动**：本机没有 Docker/Podman/Linux；已用等价的双端口 HTTP PEP 完成核心强制链路 5/5 实测，ToolHive v0.28.3 CLI 与官方校验和已验证 下一步：在具备容器运行时的 Linux 预生产机复用 deployment/ 配置，补产品级 ext_authz、mTLS、NetworkPolicy 和 MCP 容器证据
- **Keycloak 当前为本机开发模式测试域**：真实 Keycloak 26.7.1、JWT 签名、issuer、audience、角色、部门、密级和 MFA 声明已 5/5 实测，但测试域使用 HTTP 和固定测试声明 下一步：生产改用 HTTPS、组织目录联邦、真实 OTP/WebAuthn 认证流程和密钥轮换，删除测试用户与固定 MFA mapper
- **尚未连接真实外部业务系统**：HTTPS、CA、主机白名单、幂等键、审批检查和fail-closed适配器已经实现；未获得单位批准的预生产URL、令牌和CA 下一步：获得合法测试凭据后运行真实API E2E；不得生成、猜测或把本地模拟凭据称为真实凭据
- **生产级KMS/HA仍需多节点集群**：OpenBao Transit密钥外置/轮换和KV CAS双网关核销7/7已完成，但本机dev server仍是单服务进程 下一步：在预生产部署多节点OpenBao Raft或云KMS加高可用数据库，补leader切换和灾难恢复
- **Kata/Firecracker产品隔离尚未运行**：QEMU独立Linux来宾内核9/9已验证无网络、无宿主目录和资源限制，但当前为TCG软件模拟 下一步：在Linux/KVM测试机运行Kata或Firecracker产品E2E和性能测试
- **默认演示仍保留 OPA CLI 调用**：网络端到端测试已使用常驻 OPA REST；部分旧演示为便于单文件复现仍逐次启动 CLI 下一步：生产统一切换至 OPA sidecar/OPA-Envoy/Go SDK 或 Wasm 常驻求值，并做压力测试
- **数据仍以合成场景为主**：确定性去标识、秘密删除、IP泛化和哈希报告流水线已实现，但未获得单位批准的真实日志 下一步：获得数据许可后运行脱敏脚本，隔离训练/调参与盲测数据并开展回放
- **远程GitHub仓库尚未发布**：GitHub CLI已安装、本地Git仓库和敏感文件扫描已完成，但命令行和网页均未登录 下一步：用户登录GitHub后创建私有仓库并推送；不得代替用户生成账号或凭据

## 统计口径

各测试层的分母保持独立；不把单元测试、数据定义和演示检查相加为一个准确率。当前结论仅覆盖本机、当前代码版本和已定义场景，不能表述为已经生产就绪或系统绝对安全。

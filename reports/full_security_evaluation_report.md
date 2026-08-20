# 陈彦钊负责部分：完整实现与测试机实测报告

生成日期：2026-08-20

## 总结

原先列出的高优先级缺口均已完成测试级补齐：真实 Keycloak/OIDC 7/7、常驻 OPA REST 网络强制链路 5/5、OpenBao共享审批/票据 10/10、QEMU隔离 11/11。测试机上 OPA 单元测试 31/31 通过，OPA-Envoy 网络策略测试 4/4 通过，OPA 数据集 55/55 通过，Python 身份/审批/网关/内核测试 173/173 通过，关键演示与新增端到端检查 23/23 通过；危险、拒绝、重放、篡改、身份伪造和沙箱攻击场景的误执行次数为 0。

## 已完成内容

1. **可信身份**：实际启动 Keycloak 26.7.1，验证 JWT 签名、issuer、audience、过期时间、角色、部门、密级与 MFA 声明；请求 JSON 中伪造的主体会被签名身份覆盖。
2. **权限策略**：OPA/Rego 输出 allow、require_approval、deny，校验角色、密级、工具、参数、任务、审批凭证和危险行为。
3. **审批控制**：LangGraph + SQLite 持久化暂停/恢复，审批绑定 task_id 与完整动作摘要，恢复后再次执行 OPA。
4. **网络强制阻断**：常驻 OPA REST→HTTP 网关→一次性票据→受保护 HTTP 后端实际跨端口运行；阻断直连、过期、篡改、重放并在 OPA 故障时 fail-closed。
5. **安全内核与业务适配器**：Wasmtime 无 WASI、2 MiB 内存和燃料预算预检后，公告查询真实读取 SQLite，批准付款真实写入专用测试账本；失败回滚且同 task_id 拒绝重复副作用。

## 测试机环境

- 系统：Windows-11-10.0.26200-SP0
- CPU：AMD64 Family 25 Model 97 Stepping 2, AuthenticAMD，逻辑处理器 32
- 内存：15.7 GiB
- Python：3.12.13
- OPA / LangGraph / Wasmtime：1.19.0 / 1.2.10 / 47.0.1
- 本机容器条件：Docker=False；Linux 发行版=False
- 容器 E2E 执行环境：github_actions_linux_runner，10/10 通过，证据 `reports/github_actions_container_product_e2e.json`

## 关键攻击与故障验证

| 验证项 | 结果 |
|---|---|
| 低风险动作经网关与 Wasmtime 执行 | 通过 |
| 高风险未审批只返回暂停 | 通过 |
| 危险命令由策略阻断 | 通过 |
| 合法审批后隔离执行 | 通过 |
| 一次性票据重放阻断 | 通过 |
| 授权后修改参数阻断 | 通过 |
| OPA 故障默认拒绝 | 通过 |
| OPA→LangGraph→网关→Wasmtime 全链路 | 通过 |
| 无限循环被燃料预算终止 | 通过 |
| WASI 文件能力请求被拒绝 | 通过 |
| 网络级 OPA→网关→受保护后端链路 | 通过 |
| 无票据 HTTP 直连后端被拒绝 | 通过 |
| 真实 Keycloak/OIDC 身份签名校验 | 通过 |
| OIDC 身份覆盖不可信 JSON 主体 | 通过 |
| 审批后真实测试账本副作用 | 通过 |
| 审批人OIDC身份及审批签名已验证 | 通过 |
| OpenBao外部密钥与共享票据核销 | 通过 |
| 同一审批跨双网关只能核销一次 | 通过 |
| OpenBao三节点Raft主节点故障切换 | 通过 |
| QEMU独立Linux来宾内核隔离 | 通过 |
| QEMU只读启动介质无挂载错误 | 通过 |
| OPA-Envoy容器化网络授权E2E | 通过 |
| ToolHive MCP容器工作负载E2E | 通过 |

## 缺漏、问题与下一步

| 严重性 | 当前缺漏/问题 | 原因 | 建议处理 |
|---|---|---|---|
| 低 | OPA-Envoy/ToolHive 容器 E2E 仅在 CI Linux Runner 完成 | GitHub Actions ubuntu-latest 上 10/10 通过，覆盖无票据拒绝、伪造票据拒绝、签名票据放行、重放拒绝、跨动作拒绝、后端无宿主端口、OPA 故障 fail-closed 与命名 MCP 容器运行；提交=167b2b0445ca；本机 Windows 无容器运行时，该历史失败记录已标注被取代 | 在单位预生产 Kubernetes 集群补 NetworkPolicy、mTLS 与跨节点故障注入 |
| 中 | Keycloak 当前为本机开发模式测试域 | 真实 Keycloak 26.7.1、JWT签名、issuer、audience、角色、部门、密级和MFA声明已 7/7 实测；测试密码改为每次随机生成，但测试域仍使用HTTP和合成MFA声明 | 生产改用 HTTPS、组织目录联邦、真实 OTP/WebAuthn 认证流程和密钥轮换，删除测试用户与固定 MFA mapper |
| 中 | 尚未连接真实外部业务系统 | HTTPS、CA、主机白名单、幂等键、显式写操作双确认、金额上限、可信OIDC审批和结果未知对账均已实现；未获得单位批准的预生产URL、令牌和CA | 获得合法测试凭据后运行真实API E2E；不得生成、猜测或把本地模拟凭据称为真实凭据 |
| 中 | 生产KMS/HA仍需跨故障域加固 | OpenBao票据与审批独立Transit密钥/共享KV 10/10及三节点Raft选主、复制、leader故障切换8/8已完成，但三个节点仍位于同一Windows测试机且关闭TLS | 预生产跨故障域部署，启用TLS与自动解封，并补快照恢复、网络分区和容量压测 |
| 中 | Kata/Firecracker产品隔离尚未运行 | QEMU独立Linux来宾内核/Alpine用户态/只读启动介质 11/11已验证无网络、无宿主目录和资源限制，但当前为TCG软件模拟 | 在Linux/KVM测试机运行Kata或Firecracker产品E2E和性能测试 |
| 中 | 默认演示仍保留 OPA CLI 调用 | 网络端到端测试已使用常驻 OPA REST；部分旧演示为便于单文件复现仍逐次启动 CLI | 生产统一切换至 OPA sidecar/OPA-Envoy/Go SDK 或 Wasm 常驻求值，并做压力测试 |
| 中 | 数据仍以合成场景为主 | 确定性去标识、秘密删除、IP泛化和哈希报告流水线已实现；AgentDojo/InjecAgent/AgentHarm转换、严格校验和独立分母评测入口已用6条自编fixture验证，但尚未导入上游全量原始数据，也未获得单位批准的真实日志 | 按许可取得公开基准并生成真实策略预测；获得数据授权后运行脱敏脚本，隔离训练/调参与盲测数据并开展回放 |
| 低 | 公开仓库已发布，但公开不等于生产验收 | reports/github_publication.json 实测远程仓库匿名可读且可见性为 public；密钥、授权数据与运行态状态目录仍被 .gitignore 与发布前扫描挡在仓库外 | 保持发布前秘密扫描为 CI 必过项；对外材料继续区分“已开源”与“已生产就绪” |

## 结论边界

本次可以证明可信身份、策略、审批、网络阻断、票据、安全内核和真实本地测试业务副作用形成闭环，
OPA-Envoy 与 ToolHive 的容器化强制链路已在 GitHub Actions Linux Runner 上取得 10/10 实测证据，
公开仓库已发布。但这些都**不等于生产就绪**：容器 E2E 是 CI 测试环境而非单位预生产集群，
仍缺 Kubernetes NetworkPolicy 与 mTLS、Kata/Firecracker KVM 隔离、OpenBao 跨故障域与 TLS/自动解封、
Keycloak HTTPS/高可用/目录联邦/真实 MFA，也没有接入单位授权的真实业务 API 与获批生产数据；
测试账本仍然不能说成真实转账。本机 Windows 无容器运行时留下的历史失败记录已保留并标注被取代，
不再作为当前结论。

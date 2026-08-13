# 陈彦钊负责部分：完整实现与测试机实测报告

生成日期：2026-08-14

## 总结

原先列出的三个高优先级缺口均已完成测试级补齐：真实 Keycloak/OIDC 5/5、常驻 OPA REST 网络强制链路 5/5、真实本地 SQLite 业务读写 6/6。测试机上 OPA 单元测试 31/31 通过，OPA-Envoy 网络策略测试 4/4 通过，OPA 数据集 55/55 通过，Python 身份/审批/网关/内核测试 46/46 通过，关键演示与新增端到端检查 17/17 通过；危险、拒绝、重放、篡改、身份伪造和沙箱攻击场景的误执行次数为 0。

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
- 容器条件：Docker=False；Linux 发行版=False

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
| OpenBao外部密钥与共享票据核销 | 通过 |
| QEMU独立Linux来宾内核隔离 | 通过 |

## 缺漏、问题与下一步

| 严重性 | 当前缺漏/问题 | 原因 | 建议处理 |
|---|---|---|---|
| 中 | Envoy/ToolHive 指定产品的容器部署未启动 | 本机没有 Docker/Podman/Linux；已用等价的双端口 HTTP PEP 完成核心强制链路 5/5 实测，ToolHive v0.28.3 CLI 与官方校验和已验证 | 在具备容器运行时的 Linux 预生产机复用 deployment/ 配置，补产品级 ext_authz、mTLS、NetworkPolicy 和 MCP 容器证据 |
| 中 | Keycloak 当前为本机开发模式测试域 | 真实 Keycloak 26.7.1、JWT 签名、issuer、audience、角色、部门、密级和 MFA 声明已 5/5 实测，但测试域使用 HTTP 和固定测试声明 | 生产改用 HTTPS、组织目录联邦、真实 OTP/WebAuthn 认证流程和密钥轮换，删除测试用户与固定 MFA mapper |
| 中 | 尚未连接真实外部业务系统 | HTTPS、CA、主机白名单、幂等键、审批检查和fail-closed适配器已经实现；未获得单位批准的预生产URL、令牌和CA | 获得合法测试凭据后运行真实API E2E；不得生成、猜测或把本地模拟凭据称为真实凭据 |
| 中 | 生产级KMS/HA仍需多节点集群 | OpenBao Transit密钥外置/轮换和KV CAS双网关核销7/7已完成，但本机dev server仍是单服务进程 | 在预生产部署多节点OpenBao Raft或云KMS加高可用数据库，补leader切换和灾难恢复 |
| 中 | Kata/Firecracker产品隔离尚未运行 | QEMU独立Linux来宾内核9/9已验证无网络、无宿主目录和资源限制，但当前为TCG软件模拟 | 在Linux/KVM测试机运行Kata或Firecracker产品E2E和性能测试 |
| 中 | 默认演示仍保留 OPA CLI 调用 | 网络端到端测试已使用常驻 OPA REST；部分旧演示为便于单文件复现仍逐次启动 CLI | 生产统一切换至 OPA sidecar/OPA-Envoy/Go SDK 或 Wasm 常驻求值，并做压力测试 |
| 中 | 数据仍以合成场景为主 | 确定性去标识、秘密删除、IP泛化和哈希报告流水线已实现，但未获得单位批准的真实日志 | 获得数据许可后运行脱敏脚本，隔离训练/调参与盲测数据并开展回放 |
| 中 | 远程GitHub仓库尚未发布 | GitHub CLI已安装、本地Git仓库和敏感文件扫描已完成，但命令行和网页均未登录 | 用户登录GitHub后创建私有仓库并推送；不得代替用户生成账号或凭据 |

## 结论边界

本次可以证明可信身份、策略、审批、网络阻断、票据、安全内核和真实本地测试业务副作用在测试机上形成闭环，但不能声称已经完成生产部署。没有 Docker/Linux，因此不能把等价 HTTP PEP 说成 Envoy/ToolHive 产品级容器实测；也不能把测试账本说成真实转账。剩余事项均为生产化或特定部署环境补齐，不再是本原型核心控制链路的高优先级缺口。

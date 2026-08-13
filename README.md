# AgentGuard：政企大模型智能体权限、审批、阻断与安全内核原型

这是面向赛题“工具调用和任务执行的安全约束与审批控制”的可运行 OPA 原型。它把智能体准备执行的真实动作统一成 JSON，使用 Rego 规则输出三态决策，并要求 MCP/API 网关强制执行：

- `allow`：满足最小权限要求，可以执行；
- `require_approval`：暂停任务，绑定具体任务和参数后进入人工审批；
- `deny`：立即阻断，并输出可审计原因码。

项目不是静态调研材料，已经使用 Keycloak 26.7.1、OPA 1.19.0、LangGraph 1.2.10、Wasmtime 47.0.1、OpenBao 2.6.1 和 QEMU 11.1.0 在测试机实际运行并生成测试报告。

## 已完成的课题内容

1. **动态权限策略**：综合主体角色、密级、工具、操作、资源、金额、时段、批量规模、目标网络区域和任务历史判断。
2. **关键操作审批**：对转账、写入、删除、外发、命令执行、导出和部署等动作返回 `require_approval`。
3. **审批防绕过**：审批凭证绑定 `task_id + 完整 action` 的 SHA-256 摘要，并检查有效期、审批人角色、职责分离和一次性使用。
4. **异常任务阻断**：阻断未知/停用工具、越权角色、密级不足、受保护资源、敏感数据外发、破坏性命令、无沙箱高风险执行、绕过网关、异常重复和非白名单外联。
5. **审计与脱敏**：决策输出包含请求、任务、主体、工具、资源、结果和风险分；`system.log.mask` 隐藏密码、令牌、API Key 和审批摘要。
6. **可复现实验**：31 个 Rego 单元测试、55 个批量场景、覆盖率和性能基准均已生成。
7. **强制阻断网关**：OPA 故障时默认拒绝，只为 `allow` 签发短时 HMAC 执行票据，工具后端原子核销一次。
8. **执行防绕过**：阻断无票据直连、票据篡改、过期、跨动作使用、重复使用和 16 路并发重放。
9. **安全内核**：Wasmtime 默认关闭 WASI 和全部主机导入，限制内存和燃料预算，阻断无限循环、文件能力请求和超量内存。
10. **可信身份**：实际启动 Keycloak，严格验证 JWT 签名、issuer、audience、角色、部门、密级和 MFA；覆盖请求中的伪造 JSON subject。
11. **网络强制执行**：常驻 OPA REST、HTTP 网关和受票据保护的后端跨独立端口运行；无票据直连和 OPA 故障均默认阻断。
12. **真实测试业务副作用**：公告查询读取真实 SQLite，审批后付款写入隔离测试账本；失败回滚、路径限制和 task_id 幂等均已测试。
13. **密钥外置与共享核销**：OpenBao Transit 外置签名密钥并完成轮换，KV v2 CAS 供两个网关共享核销，32 路竞争只执行一次。
14. **原生工具隔离验证**：QEMU 启动独立 Alpine Linux 来宾内核，限制 1 vCPU/256 MiB、关闭网络和宿主目录共享。
15. **生产接入流水线**：真实业务适配器要求 HTTPS、CA、主机白名单、幂等键与审批；真实数据在进入评估前执行确定性去标识和秘密删除。

## 技术位置

```text
用户 / Agent / 服务账号
        ↓
候选动作标准化（JSON Schema）
        ↓
OPA / Rego 策略决策点
        ├─ allow ─────────→ 网关签发一次性票据 → 工具适配器核销
        ├─ require_approval → 暂停 → 人工审批 → 绑定摘要 → 再次校验
        └─ deny ──────────→ 网关阻断 → 决策日志/审计告警
                                      ↓
                          Wasmtime 无主机能力沙箱
```

OPA 负责“算出决定”，网关负责“执行决定”。只有 OPA 而没有统一网关时，其他调用路径仍可能绕过策略。

## 当前实测结果

| 指标 | 实测结果 |
|---|---:|
| OPA 严格语法检查 | 通过 |
| Rego 单元测试 | 31/31 通过 |
| 批量评测用例 | 55 |
| 三态决策准确率 | 100% |
| 原因码准确率 | 100% |
| 危险动作阻断率 | 100% |
| 合法动作放行率 | 100% |
| 需审批动作路由准确率 | 100% |
| 非法审批凭证阻断率 | 100% |
| 危险动作误放行 | 0 |
| 两个生产策略文件覆盖率 | 100% |
| 全部 Rego 文件覆盖率（包含测试代码） | 99.61% |
| OPA 纯策略基准 | 约 0.35-0.36 ms/次 |
| 身份/审批/网关/内核/生产接入 Python 测试 | 46/46 通过 |
| OPA-Envoy 网络前置策略测试 | 4/4 通过 |
| 完整链路关键演示与实服检查 | 18/18 通过 |
| Keycloak/OIDC 真实端到端 | 5/5 通过 |
| 常驻 OPA REST 网络强制链路 | 5/5 通过 |
| 真实本地业务适配器 | 6/6 通过 |
| OpenBao Transit + 共享KV票据核销 | 7/7 通过 |
| OpenBao 三节点Raft选主、复制与主节点故障切换 | 8/8 通过 |
| QEMU 独立 Linux 来宾内核隔离 | 9/9 通过 |
| 阻断或沙箱攻击误执行次数 | 0 |

批量评测脚本逐条启动 OPA CLI，耗时会随机器负载波动，最新均值与 P95 以 `reports/open_source_route_progress.md` 自动看板为准；该值主要包含进程启动和策略加载，不是 sidecar、Wasm 或 Go SDK 常驻部署的纯决策延迟。

## 一键复现

Windows PowerShell：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_all.ps1
```

完整四部分安装与测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_full.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_complete_security.ps1
```

完整脚本结束时还会自动刷新：

- `reports/open_source_route_progress.json`：机器可读的五阶段路线、指标、数据集和缺漏状态；
- `reports/open_source_route_progress.md`：可直接检查的中文进度看板。

如果 `python` 不在 PATH，可显式指定：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_all.ps1 -Python "C:\path\to\python.exe"
```

脚本会：

1. 从 OPA 官方 GitHub 下载固定版本 1.19.0，并验证 SHA-256；
2. 生成 JSONL/CSV 数据集和有效审批样例；
3. 执行格式、严格语法和 31 个单元测试；
4. 生成覆盖率、性能基准和 55 个批量用例的量化报告。

## 三个演示命令

```powershell
python .\scripts\gateway_demo.py .\samples\allow_low_risk.json
python .\scripts\gateway_demo.py .\samples\require_approval.json
python .\scripts\gateway_demo.py .\samples\deny_dangerous_command.json
```

对应效果分别是“网关放行”“暂停进入人工审批”“立即阻断”。审批通过后的样例位于 `samples/allow_with_approval.json`。

## 第二阶段：LangGraph 人工审批与任务恢复（已实现）

原来的 OPA 只负责判断，现在项目已经补上可运行的审批工作流：

1. OPA 返回 `require_approval` 时，LangGraph 的 `interrupt()` 立即暂停任务；
2. SQLite 按唯一 `thread_id` 保存检查点，程序关闭后仍可从同一任务恢复；
3. 人工选择批准、拒绝或修改；批准凭证绑定 `task_id + 完整 action` 的 SHA-256；
4. 恢复后不直接执行，必须再次调用 OPA；拒绝、跨任务复用或参数变化都会返回 `deny`；
5. 当前执行节点是安全模拟，只产生 `simulated_only` 回执，不会真的转账、删文件或运行命令。

安装与全量验证：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_approval.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_approval_all.ps1
```

单独演示四条路径：

```powershell
.\.venv\Scripts\python.exe -m approval.demo --scenario allow
.\.venv\Scripts\python.exe -m approval.demo --scenario approve
.\.venv\Scripts\python.exe -m approval.demo --scenario reject
.\.venv\Scripts\python.exe -m approval.demo --scenario tamper
```

实测结果为 10/10 个工作流测试通过：低风险直通、高风险暂停、批准恢复、拒绝阻断、修改后重新审批、审批后参数篡改阻断、自批阻断、无审批角色阻断、跨任务复用阻断、进程重启后恢复。量化结果在 `reports/approval_evaluation_report.md`，9 条工作流数据在 `datasets/approval_workflow_cases.jsonl`。

## 第三阶段：强制阻断网关（已实现）

`enforcement/` 是真实执行前的统一策略执行点。它采用 fail-closed：OPA 返回拒绝、需要审批、未知结果或 OPA 自身不可用时都不会产生执行票据。只有 `allow` 才签发绑定 `task_id + 完整 action` 的 30 秒 HMAC 票据；工具适配器在 SQLite 事务中原子核销，第二次使用必然返回 `G206_TICKET_REPLAY`。网关还阻断无票据直连、签名篡改、票据过期、授权后改参数和未注册工具适配器，并对审计字段递归脱敏。

## 第四阶段：Wasmtime 安全内核（已实现）

`security_kernel/` 使用 Wasmtime 执行受控 WebAssembly 工具适配器。默认不注入 WASI、文件系统、网络、环境变量或其他主机函数；每次执行限制为 2 MiB 内存和固定燃料预算。测试证明无限循环被 `K006_CPU_BUDGET_EXCEEDED` 终止，WASI 文件写入导入被 `K002_HOST_IMPORT_FORBIDDEN` 拒绝，超量初始内存和非白名单入口同样不能运行。

OPA→LangGraph→强制网关→Wasmtime 的完整审批链路已经实际跑通。主报告位于 `reports/full_security_evaluation_report.md`。

## 高优先级缺口补齐（已实测）

- `identity/`：Keycloak 26.7.1 测试域和 OIDC 验证器；无令牌、篡改令牌、错误身份来源均阻断。
- `enforcement/http_stack.py`：常驻 OPA REST→HTTP 网关→一次性票据→受保护 HTTP 后端，网络端到端 5/5。
- `enforcement/adapters.py`：受限于状态目录的真实 SQLite 查询与付款测试账本，6/6。
- `third_party/README.md`：Keycloak、Java 与 ToolHive 官方下载、版本和校验和。ToolHive CLI 已验证；因本机无容器运行时，产品级 MCP 容器仍是中优先级环境项。
- `enforcement/signers.py`、`enforcement/ledgers.py`：OpenBao Transit密钥外置、版本轮换和KV v2 CAS共享核销，实服7/7；三节点Raft选主、复制与leader故障切换8/8。
- `scripts/run_qemu_native_isolation_e2e.py`：QEMU独立Linux guest kernel隔离，实测9/9。
- `integrations/`：获批真实API与真实数据的安全接入入口；未提供凭据或数据时默认跳过并明确报告。

## 作为 OPA 服务运行

```powershell
.\tools\opa.exe run --server --addr 127.0.0.1:8181 --config-file .\config\opa.yaml .\policy .\data
```

另开终端调用：

```powershell
$body = @{ input = Get-Content .\samples\allow_low_risk.json -Raw | ConvertFrom-Json } | ConvertTo-Json -Depth 20
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8181/v1/data/agent/guard/decision -ContentType application/json -Body $body
```

也可以使用 `docker compose up` 启动固定版本镜像。

## 目录说明

```text
policy/       核心策略与决策日志脱敏规则
data/         可信工具、角色权限、阈值和名单配置
tests/        Rego 单元测试
identity/     Keycloak 测试域、OIDC JWT 验证与可信 subject 映射
approval/     LangGraph 暂停/恢复、SQLite 检查点、演示与自动化测试
enforcement/  强制阻断网关、HTTP PEP、一次性票据、真实测试适配器、审计与全链路测试
integrations/  获批预生产API适配器、真实数据脱敏和接入测试
security_kernel/ Wasmtime 安全内核、受控模块和资源攻击测试
deployment/   OPA-Envoy 与 ToolHive 的生产接入参考及测试边界
schemas/      候选动作和决策输出 JSON Schema
samples/      放行、审批、阻断和审批后放行样例
datasets/     55 个 OPA + 9 个审批 + 19 个阻断/内核用例
scripts/      完整环境安装、一键测试、演示和评测
reports/      四层实际测试、测试机环境、覆盖率、性能和缺漏报告
docs/         可直接用于技术报告、PPT和答辩的中文内容
```

## 工程边界

- OPA 不执行真实命令，也不保存长流程状态；本原型已用 LangGraph + SQLite 实现暂停/恢复，生产环境可换用 PostgreSQL 检查点或 Temporal。
- OpenBao Transit密钥外置/轮换和KV v2 CAS双网关共享核销已7/7实测，三节点Raft选主、复制和leader故障切换已8/8实测；生产仍需跨故障域、TLS、自动解封、备份恢复和容量压测。
- 常驻 OPA REST 与双端口 HTTP 强制链路已经端到端实测；OPA-Envoy 与 ToolHive 指定产品的容器运行仍因本机没有 Docker/Linux 而未标记完成。
- Wasmtime已限制WebAssembly工具；QEMU独立Linux来宾内核已9/9验证。Kata/Firecracker产品E2E仍需Linux/KVM测试机。
- 工具适配器已经真实读写隔离 SQLite 测试业务库，但不会调用真实银行、ERP、生产文件或系统命令。
- 当前 55 个样例是合成的政企安全测试数据，不包含真实个人信息，部署前应结合单位制度、资源目录和密级规则扩充。
- 真实业务URL、令牌、CA和单位日志没有被提供，因此只完成安全接入代码和自动预检，不能把测试样例表述成生产E2E。
- GitHub CLI、本地仓库和敏感文件扫描已完成；远程私有仓库仍需用户登录GitHub后才能发布。

## 生产化自动推进

完成可由本机安全执行的全部生产化验证：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_productionization.ps1
```

获得单位批准的 JSONL 后，输入文件只读、脱敏结果与报告写入被 Git 忽略的隔离目录：

```powershell
$env:AGENTGUARD_REDACTION_SALT_HEX = '<由密钥管理器注入的64位十六进制随机盐>'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_productionization.ps1 -AuthorizedJsonl 'C:\approved\business-log.jsonl'
```

获得 GitHub 登录授权后，先做发布前敏感信息扫描，再自动创建私有仓库并推送：

```powershell
gh auth login --web --git-protocol https
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\publish_private_github.ps1
```

状态总表为 `reports/productionization_status.md`；外部凭据、获批数据和远程登录缺失时脚本会明确跳过或失败关闭，不会伪造完成。

需要反复检查并自动续跑全部剩余项时，可使用统一入口：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_remaining_automatically.ps1
```

完成一次 GitHub 授权后，加 `-PublishGitHub` 即可自动创建并推送默认私有仓库：

```powershell
gh auth login --web --git-protocol https
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_remaining_automatically.ps1 -PublishGitHub
```

## 官方资料

- OPA GitHub：https://github.com/open-policy-agent/opa
- OPA 文档：https://www.openpolicyagent.org/docs
- Rego 策略测试：https://www.openpolicyagent.org/docs/policy-testing
- OPA 决策日志：https://www.openpolicyagent.org/docs/management-decision-logs
- LangGraph GitHub：https://github.com/langchain-ai/langgraph
- LangGraph 中断与人工介入：https://docs.langchain.com/oss/python/langgraph/interrupts
- LangGraph 持久化：https://docs.langchain.com/oss/python/langgraph/persistence
- OPA-Envoy：https://github.com/open-policy-agent/opa-envoy-plugin
- OPA-Envoy 官方文档：https://www.openpolicyagent.org/docs/envoy
- Wasmtime：https://github.com/bytecodealliance/wasmtime
- ToolHive：https://github.com/stacklok/toolhive

代码采用 MIT License；`datasets/` 下的合成数据采用 CC BY 4.0。

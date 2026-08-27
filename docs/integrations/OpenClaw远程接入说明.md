# OpenClaw 远程只读 MCP 接入说明

> 项目：OPA 政企智能体安全原型 / AgentGuard
>
> 版本范围：OpenClaw 2026.7.1-2；MCP Streamable HTTP；仅 `list_notices`
>
> 当前状态：`remote_mcp_ready_for_deployment`
>
> 生产结论：`production_ready=false`

这份说明对应仓库里的远程 HTTP MCP 适配器和部署模板。它把“其他用户的
OpenClaw 可以远程调用”拆成一个可验收的基础版：OpenClaw 通过 HTTPS 连接
`/mcp`，使用 OAuth/OIDC Authorization Code + PKCE 获取每用户访问令牌；服务
验证令牌后，只把可信 claims 形成的身份上下文交给 AgentGuard。模型不能通过
提示词或 `tools/call.arguments` 自报身份，也不能看到或转发访问令牌。

当前工作区没有可用于本次任务的公网 Linux 主机、域名 DNS、证书或 Keycloak
管理权限，所以本文和模板不宣称公网部署或外部真实 E2E 已完成。部署到目标
环境后必须重新执行本文的验收清单，状态才能按实际证据更新。

## 1. 能力和安全边界

远程服务只注册一个工具：

| 工具 | 输入 | 结果 | 副作用 |
|---|---|---|---|
| `list_notices` | `limit`，1 到 100 的整数；禁止其他字段 | 公告 `id/title/department/published_at` | `false` |

服务端还会再次拒绝未知工具，因此 OpenClaw 的客户端过滤不是安全边界。删除、
付款、发布、外发、命令执行、Shell、浏览器、部署和任意数据库工具都不可见、
不可调用。每次调用仍要走 AgentGuard 的 OPA 决策、一次性票据、安全内核和
审计；OPA、OIDC、票据、业务后端或审计不可用时默认失败关闭。

执行链如下：

```text
OpenClaw
  └─ HTTPS Streamable HTTP /mcp
      └─ Origin 校验 + Bearer 验签 + RFC 9728 元数据
          └─ issuer/audience/resource/sub/scope/azp/client/角色/部门/MFA
              └─ AgentGuard（OPA → 票据 → 安全内核 → 受控公告适配器 → 审计）
```

远程 MCP 层不会把外部 Bearer Token 传给业务 API。嵌入式受控部署中，AgentGuard
接收已验证的 requester-scoped subject；拆分部署时应使用内部短时断言或 mTLS，
不得把原始外部 Token 作为后端凭据。

## 2. 仓库资产

- `integrations/openclaw_mcp/http_server.py`：`POST/GET /mcp`、会话绑定、
  Origin 校验、大小/并发/超时/用户级限流、`/healthz`、`/readyz` 和 RFC 9728
  Protected Resource Metadata。
- `integrations/openclaw_mcp/auth.py`：OIDC JWT/JWKS 验证后的 MCP resource
  server 检查；不保存原始令牌。
- `integrations/openclaw_mcp/openclaw-remote-config.example.json`：OpenClaw
  远程配置模板，使用 OAuth、PKCE、20 秒请求超时、5 秒连接超时和工具白名单。
- `deployment/openclaw-mcp/`：Dockerfile、Compose、Kubernetes 模板和
  `keycloak-test-realm.example.json`。

镜像入口为：

```text
python -m integrations.openclaw_mcp --transport streamable-http
```

容器只读、非 root、禁用本地测试业务适配器。公网 TLS 必须在受批准的 Ingress
或反向代理终止，容器本身不接受明文公网流量。

## 3. OIDC/Keycloak 要求

在测试 realm 导入 `deployment/openclaw-mcp/keycloak-test-realm.example.json`
前，先把其中的 `<OPENCLAW_HOST>` 替换成测试 OpenClaw 的真实地址。该文件不含
密码或 client secret，且使用公开客户端：

1. Authorization Code + PKCE，challenge method 固定为 `S256`。
2. 禁止 Implicit Flow 和 Resource Owner Password/Direct Access Grants。
3. 只申请 `agentguard.notices.read` scope。
4. 在用户 claims 中提供 `sub`、`department`、`clearance`、`mfa` 和可用角色；
   多租户环境额外提供 `tenant_id`。
5. 生产 realm 必须启用组织认可的 MFA、用户生命周期、撤销/轮换和审计策略。

`MCP_EXPECTED_RESOURCE` 必须能在访问令牌中得到验证。示例 realm 已在
`agentguard-mcp` 客户端加入 `oidc-audience-mapper`，把
`https://mcp.example.gov.cn/mcp` 作为 access token 的 `aud` 值。部署到实际域名
时，必须把该 mapper 的 `included.custom.audience` 与
`MCP_RESOURCE_URL` 改成完全一致的 HTTPS `/mcp` URL；不能只修改服务端环境变量。
如果组织的授权服务器支持 RFC 8707 `resource` 请求/声明，也可以改为发出同一
URL 的 `resource` claim，服务端会优先校验该 claim。无匹配的 `aud` 或 `resource`
时，服务端返回 `401 MCP_A_RESOURCE_INVALID`。

服务端会拒绝以下情况：无 token、错签名、过期、错误 issuer/audience/resource、
缺少 `agentguard.notices.read`、缺少/冲突 `azp` 与 `client_id`、缺少 subject/角色/
部门、MFA 未完成、客户端或部门不在允许集合。服务端只相信验签后的 claims，
绝不相信提示词中“我是管理员”之类的自报信息。

Protected Resource Metadata 地址：

```text
GET https://<MCP_HOST>/.well-known/oauth-protected-resource/mcp
GET https://<MCP_HOST>/.well-known/oauth-protected-resource
```

响应只包含 `resource`、`authorization_servers`、支持的 scope 和
`bearer_methods_supported`，不含令牌、密码、Cookie 或私钥。OpenClaw 登录时应
根据该元数据发现 Keycloak 授权服务；若目标版本要求显式配置，也可在配置中写
授权服务器的 discovery 地址。

## 4. 部署前配置

所有尖括号和值均为部署方输入，不能照抄到生产：

| 配置 | 说明 |
|---|---|
| `MCP_RESOURCE_URL` | 必须是 HTTPS 的完整 `/mcp` 资源 URL；必须与 Keycloak audience mapper 或 RFC 8707 `resource` claim 完全一致 |
| `MCP_OIDC_ISSUER` | Keycloak realm issuer（无尾部斜杠） |
| `MCP_OIDC_AUDIENCE` | OIDC JWT 的基础 audience，例如 `agentguard`；MCP 资源 URL 另由 `MCP_EXPECTED_RESOURCE` 校验 |
| `MCP_OIDC_CLIENT_ID` / `MCP_ALLOWED_CLIENT_IDS` | 允许的 OpenClaw OAuth 客户端；生产按组织命名 |
| `MCP_REQUIRED_SCOPE` | 固定为 `agentguard.notices.read`，除非重新评审工具与策略 |
| `MCP_REQUIRED_ROLES` | 允许使用只读公告工具的最小角色 |
| `MCP_ALLOWED_DEPARTMENTS` | 可选的部门 allowlist；空值表示由 OPA/业务授权继续约束 |
| `MCP_ALLOWED_ORIGINS` | OpenClaw Web/API 的精确 Origin，禁止通配符 |
| `MCP_MAX_REQUEST_BYTES` / `MCP_MAX_RESPONSE_BYTES` | 默认各 1 MiB |
| `MCP_MAX_CONCURRENT_REQUESTS` | 默认 32；按容量压测后调整 |
| `MCP_RATE_LIMIT_PER_MINUTE` | 默认每 subject 每分钟 120 次 |
| `MCP_REQUEST_TIMEOUT_SECONDS` | 默认 8 秒；边缘超时应大于后端上限 |
| `AGENTGUARD_ENABLE_LOCAL_ADAPTERS` | 生产必须为 `false`；本地 SQLite 仅供测试 |
| `AGENTGUARD_TICKET_SECRET_FILE` 或 OpenBao | 由秘密管理器注入，至少 32 字节，绝不进 Git |

AgentGuard 的 OPA、票据状态、审计和真实公告业务适配器必须使用组织批准的
地址与凭据。若只启动模板而没有受控业务适配器，调用应阻断；不能为了让演示
“成功”而把本地测试适配器带入生产。

## 5. Docker Compose（本地/预生产）

模板位置：`deployment/openclaw-mcp/docker-compose.yml`。它只绑定
`127.0.0.1:8000`，网络使用 internal，票据密钥是外部 Compose secret。示例：

```powershell
Set-Location -LiteralPath '<PROJECT_ROOT>'
docker compose -f .\deployment\openclaw-mcp\docker-compose.yml config
docker compose -f .\deployment\openclaw-mcp\docker-compose.yml up --build
```

没有预先创建 `agentguard_ticket_secret` 时，Compose 拒绝启动是预期结果；不要
在 `.env` 或命令行里临时放入真实密钥。Compose 成功启动也只能证明本地容器
编排，不是公网验收。

## 6. Kubernetes

`deployment/openclaw-mcp/kubernetes/` 提供：

- `deployment.yaml`：1 副本的安全预生产基线、非 root、只读根文件系统、探针、
  资源上限、无 ServiceAccount token 自动挂载；`ENABLE_LOCAL_ADAPTERS=false`。
  当前模板使用本地 HMAC 签名器和每 Pod 状态卷，不能直接扩成多副本；生产扩容
  前必须切换共享 OpenBao/审计/票据状态并重新验证重放与会话一致性。
- `service.yaml`：ClusterIP，仅让 Ingress 暴露。
- `ingress.yaml`：HTTPS、精确 `/mcp` 与 RFC 9728 元数据路径、请求体 1 MiB，
  禁用代理缓冲；明文 HTTP 返回 `421`，不做 30x 重定向；证书 Secret 由组织
  证书控制器提供。模板使用 ingress-nginx `server-snippet`，平台必须确认该
  注解已启用并经过审查；若集群禁用 snippet，必须配置等效的控制器级 HTTP
  拒绝策略后再应用。
- `networkpolicy.yaml`：默认拒绝后，仅允许 Ingress、DNS、显式 OPA 和 Keycloak
  命名空间/端口；不能改成 `0.0.0.0/0`。
- `secretref.yaml`：External Secrets Operator 示例，生成
  `agentguard-openclaw-mcp-secrets`，只映射票据签名密钥。
- `pdb.yaml`、`hpa.yaml`、`configmap.yaml`：可用性与非机密配置模板。

应用前必须把示例镜像替换为发布流水线产生的真实 digest，确认 CNI 实际执行
NetworkPolicy，并完成跨命名空间拒绝测试。模板中的域名、IngressClass、Keycloak
标签、OPA 标签和 SecretStore 都是占位值。

## 7. 外部 OpenClaw 配置和命令

把 `integrations/openclaw_mcp/openclaw-remote-config.example.json` 复制到
目标 OpenClaw 的受控配置中，替换真实 URL。其核心结构是：

```json
{
  "mcp": {
    "servers": {
      "agentguard-notices": {
        "url": "https://<MCP_HOST>/mcp",
        "transport": "streamable-http",
        "auth": "oauth",
        "oauth": {"scope": "agentguard.notices.read"},
        "timeout": 20,
        "connectTimeout": 5,
        "sslVerify": true,
        "supportsParallelToolCalls": false,
        "toolFilter": {"include": ["list_notices"]}
      }
    }
  }
}
```

也可以使用 OpenClaw CLI（命令中的 `openclaw` 应替换为目标机固定版本的
受控入口；不要依赖本项目的全局命令）：

```powershell
openclaw mcp add agentguard-notices `
  --url https://<MCP_HOST>/mcp `
  --transport streamable-http `
  --auth oauth `
  --oauth-scope agentguard.notices.read `
  --timeout 20 `
  --connect-timeout 5 `
  --include list_notices

openclaw mcp login agentguard-notices
openclaw mcp doctor agentguard-notices --probe
openclaw mcp probe agentguard-notices --json
```

`mcp login` 应打开 Keycloak 授权页面并完成 PKCE；不要把 access token 粘贴到
模型提示词、Issue、配置仓库或截图。`doctor --probe` 与 `probe --json` 的结果
只作为目标环境的连接/工具发现证据，不能替代 AgentGuard 审计和负向验收。

预期 `tools/list` 只有 `list_notices`。`tools/call` 示例：

```json
{
  "name": "list_notices",
  "arguments": {"limit": 1}
}
```

增加 `subject`、`tenant_id`、`operation`、`approval` 或其他字段应被服务端拒绝。

## 8. 必测验收清单

部署目标环境后，至少保存请求 ID、状态码、原因码、审计关联和结果状态，不能
保存 Token、Cookie、密码、私钥或完整 Authorization 头：

1. 无 Token 返回 `401`，带 `WWW-Authenticate`；错签名、过期、错误 issuer、
   audience/resource 同样返回 `401`。
2. 缺少 `agentguard.notices.read`、角色或部门不允许时返回 `403`；错误 Origin
   或缺少必需 Origin 时拒绝；明文远程 HTTP 和重定向被拒绝。
3. 用户 A/B 的审计 `subject_id` 不同；A 使用 B 的会话或租户数据被拒绝；提示词
   自报管理员不改变 claims。
4. `tools/list` 只有 `list_notices`；删除、付款、发布、命令执行等工具既不出现
   也不能调用；多余参数和 `limit` 越界被拒绝。
5. 正常 `list_notices(limit=1)` 只有在 OPA、票据、安全内核、公告适配器和审计
   全部可用时成功，结果 `side_effect=false`。
6. MCP、AgentGuard、OPA 和执行审计共享同一个 `request_id`；审计包含
   `subject_id/session_id/client_id/tool/operation/opa_decision/reason_code/result_status`。
7. 任一后端、OPA、OIDC、审计或票据依赖不可用时，服务 readiness 失败或调用
   fail-closed，不返回业务数据。
8. 日志/报告敏感扫描为 0：无令牌、密码、Cookie、私钥和真实 client secret。

本地仓库已有的 `integrations/openclaw_mcp/tests/test_http_server.py` 只覆盖注入
式 verifier/backend 的协议边界。它不能证明目标 Keycloak、Ingress、CNI 或真实
业务 API 已部署；公网 E2E 仍须在外部环境完成。

## 9. 故障与回滚

- OIDC/JWKS 暂时不可用：保持 `readyz` 非就绪；不要切换为静态身份或关闭 MFA。
- OPA、票据状态、审计或业务 API 不可用：返回阻断/503，不重试产生副作用；先
  恢复依赖并对账。
- 证书、issuer、audience 或 Origin 变更：先更新 IdP/Ingress 与 allowlist，再滚动
  Deployment；旧配置不能悄悄放宽。
- 回滚时先在 OpenClaw 禁用 `agentguard-notices`，再回滚镜像；保留审计和票据
  状态以支持对账，禁止删除仍被引用的 Secret。

## 10. 状态声明

`remote_mcp_ready_for_deployment` 仅表示仓库中已提供远程 MCP 代码、受控启动
入口、配置示例、Keycloak 测试模板、容器/Kubernetes 骨架和本地协议测试。由于
本次没有目标公网环境、DNS、证书、Keycloak 管理权限和真实业务授权数据，不能
写成“外部接入完成”或“生产安全验收完成”。在真实环境完成上述清单、持续模型
回合审计和故障注入后，才能单独评估是否提升状态；`production_ready=false`
在此之前必须保持不变。

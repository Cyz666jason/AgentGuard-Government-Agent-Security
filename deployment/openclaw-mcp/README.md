# AgentGuard × OpenClaw 远程 MCP 部署模板

本目录是“外部 OpenClaw 远程只读接入基础版”的可审查部署起点。它包含
Streamable HTTP MCP 的镜像、Compose 本地编排和 Kubernetes 模板；模板不会
伪造公网域名、证书、Keycloak 管理权限或真实业务数据。

当前发布状态：`remote_mcp_ready_for_deployment`。这表示代码、配置边界和
部署骨架已经准备好交给目标环境验收；不表示已经部署到公网，且
`production_ready=false` 必须保留。

## 文件

- `Dockerfile`：非 root、只读根文件系统友好的 Python 镜像；不包含 OpenClaw、
  开发身份或任何密钥。
- `docker-compose.yml`：仅回环绑定的本地/预生产模板。票据签名密钥通过外部
  Compose secret 注入，不能用仓库中的默认值启动。
- `kubernetes/`：Deployment、Service、Ingress、NetworkPolicy、ExternalSecret
  SecretRef、PDB、HPA 与 ConfigMap。`kustomization.yaml` 默认不应用
  `secretref.yaml`，因为目标集群必须先批准 External Secrets Operator 和
  `ClusterSecretStore`。
- `keycloak-test-realm.example.json`：没有用户密码或 client secret 的测试
  realm 模板，采用公开客户端 + PKCE S256。生产必须重新创建客户端、重定向 URI、
  MFA 策略和用户/部门授权。

## 应用前检查

1. 由发布流水线构建镜像并替换 `kubernetes/deployment.yaml` 中的示例镜像和
   digest；示例 digest 不是可部署值。
2. 为 `mcp.example.gov.cn` 签发证书，将证书交给受批准的 Ingress 控制器；
   MCP 容器本身不终止公网 TLS。
   Ingress 模板明确关闭 HTTP→HTTPS 30x 重定向，并要求明文 HTTP 在边缘返回
   `421`；这是为了避免携带 bearer token 的 MCP 请求被重定向。该行为依赖
   `nginx.ingress.kubernetes.io/server-snippet`，平台必须确认
   `allow-snippet-annotations` 已启用并经过审查；若平台禁用 snippet，应配置
   等效的控制器级拒绝策略（同样返回 `421`，不得改为重定向）。
3. 在目标 IdP 创建 Keycloak realm/client，启用 Authorization Code + PKCE
   (S256)，仅注册真实 OpenClaw 回调地址，并授予最小 scope
   `agentguard.notices.read`。同时配置 audience mapper（示例 realm 已配置）或
   RFC 8707 `resource` claim，把实际 `MCP_RESOURCE_URL`（完整 HTTPS `/mcp`）
   放入 access token；否则服务端会以 `MCP_A_RESOURCE_INVALID` 拒绝令牌。
4. 在秘密管理器创建 `agentguard/remote-mcp/ticket-secret`（至少 32 字节随机
   值），由 `secretref.yaml` 映射成 `agentguard-openclaw-mcp-secrets`。不得把
   值填入 YAML、ConfigMap、命令行或 Git。
5. 明确 AgentGuard 的 OPA、票据状态、审计和公告业务适配器地址，并把它们加入
   NetworkPolicy 的显式 allow 规则；不要添加 `0.0.0.0/0` 出站规则。
6. 先从未授权命名空间、错误 Origin、明文 HTTP、错误 issuer/audience、无 scope、
   过期/错签名 token 和跨租户 token 做负向测试；通过后才能接入 OpenClaw。

## 本地模板检查

```powershell
Set-Location -LiteralPath '<PROJECT_ROOT>'
docker compose -f .\deployment\openclaw-mcp\docker-compose.yml config
```

Compose 的 `external` secret 故意要求运维先创建 `agentguard_ticket_secret`，
因此没有 secret 时的失败是预期的安全行为。该模板绑定 `127.0.0.1:8000`，
不是公网 E2E 证据。

## Kubernetes 应用顺序

```powershell
kubectl create namespace agentguard --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n agentguard -f .\deployment\openclaw-mcp\kubernetes\configmap.yaml
# 仅在 External Secrets Operator、ClusterSecretStore 和密钥路径获批后：
kubectl apply -n agentguard -f .\deployment\openclaw-mcp\kubernetes\secretref.yaml
kubectl apply -k .\deployment\openclaw-mcp\kubernetes
kubectl -n agentguard rollout status deployment/agentguard-openclaw-mcp
```

`kubectl apply -k` 会再次应用 ConfigMap，但不会自动包含 `secretref.yaml`。
在应用 Ingress 前要确认 DNS、证书、IngressClass 和内部审计路径；Ingress
只允许 `/mcp` 和 RFC 9728 受保护资源元数据路径。

## 停止与回滚

先从 OpenClaw 配置移除/禁用 `agentguard-notices`，再缩容或回滚 Deployment。
保留审计和票据状态，按组织留存策略处理；不要删除仍可能用于对账的状态卷或
Secret。若依赖（OPA、OIDC、审计、业务 API）不可用，服务应保持就绪失败并拒绝
工具调用。

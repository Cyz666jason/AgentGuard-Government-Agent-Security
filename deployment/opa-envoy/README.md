# OPA-Envoy 生产强制阻断参考配置

本目录用于把本项目的“策略执行点”迁移到 Envoy `ext_authz`。关键安全设置是 `failure_mode_allow: false`：OPA-Envoy 超时或不可用时，Envoy 默认拒绝，而不是绕过授权。

`envoy_guard.rego` 只负责网络层第一道检查：只有携带执行票据且访问内部工具适配器路径的 POST 请求才可能转发。后端仍必须调用 `ExecutionTicketStore.consume()` 完成 HMAC、任务/动作绑定、有效期和一次性原子核销；不能只检查请求头是否存在。

测试机没有 Docker、可用 Linux/WSL 发行版和 Envoy，因此本目录是已编写但未在本机端到端启动的生产参考配置。部署时应：

1. 固定并验证 OPA-Envoy、Envoy 镜像摘要；
2. 将 Envoy、OPA-Envoy 与工具适配器放在同一 Pod/主机安全域；
3. 用 NetworkPolicy/防火墙禁止客户端直连工具后端；
4. 使用 mTLS/SPIFFE 替代仅依赖网络位置；
5. 从 KMS/HSM 注入票据密钥并支持轮换；
6. 用组织批准的镜像版本替换配置管理系统中的镜像变量。

官方资料：

- https://www.openpolicyagent.org/docs/envoy
- https://github.com/open-policy-agent/opa-envoy-plugin
- https://www.openpolicyagent.org/docs/envoy/tutorial-standalone-envoy

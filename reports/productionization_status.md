# AgentGuard 生产化自动推进状态

生成时间：2026-08-14T06:19:13.742936+08:00

| 内容 | 状态 | 当前证据 | 尚缺条件/边界 |
|---|---|---|---|
| OPA-Envoy产品容器E2E | blocked_external_environment | 策略4/4；容器E2E=False；run_id=403cfd8e1f22；fresh=True | 当前机器无Docker/Podman；脚本已就绪，有运行时会真实启动并做故障注入 |
| ToolHive MCP容器E2E | blocked_external_environment | CLI/checksum=True；container=False；run_id=403cfd8e1f22 | ToolHive doctor确认没有Docker/Podman/Kubernetes |
| 外部密钥与共享票据状态 | completed_ha_test_environment | OpenBao Transit+KV 10/10 run_id=403cfd8e1f22；三节点Raft故障切换 8/8 run_id=403cfd8e1f22 | 本机三进程已验证HA；正式生产仍需跨故障域、TLS、自动解封、备份恢复和容量压测 |
| 原生程序独立来宾内核隔离 | completed_test_environment | QEMU guest kernel 11/11；run_id=403cfd8e1f22；fresh=True | 不是Kata/Firecracker，当前为TCG软件模拟且无KVM |
| 真实业务系统凭据与E2E | ready_for_credentials | HTTPS、主机白名单、CA、幂等键、双确认写门、可信OIDC审批与对账状态已实现；报告=skipped_missing_authorized_credentials | 未提供单位批准的预生产URL、令牌、CA和审批人OIDC令牌，不会生成或猜测真实凭据 |
| 脱敏生产数据 | ready_for_authorized_data | 确定性去标识、秘密字段删除、IP泛化和SHA-256报告已实现 | 未提供获批原始日志；测试样例不能冒充生产数据 |
| 远程GitHub私有仓库 | ready_for_authentication | 本地git仓库、.gitignore、许可证；发布前扫描=passed | GitHub CLI和网页均未登录；不能代替用户创建账号或凭据 |

## 结论

已经自动完成 OpenBao 外部密钥与共享票据状态验证、三节点Raft选主/复制/主节点故障切换、QEMU 独立 Linux 来宾内核隔离、本地 Git 仓库、真实业务 HTTPS 接入代码和生产数据脱敏流水线。需要管理员权限、单位授权数据、真实预生产凭据或用户 GitHub 登录的项目保留为外部阻塞，不能自动伪造为完成。

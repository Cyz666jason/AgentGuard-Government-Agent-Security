# 阶段4：外部环境与授权输入验证计划

## 1. 阶段目标与证据边界

阶段4将已完成的测试级安全链路放入真实产品和组织环境，验证：

1. Kata Containers和Firecracker在Linux/KVM上的真实隔离效果与开销；
2. OpenBao在三个故障域中的TLS、自动解封、快照恢复、分区和容量能力；
3. Kubernetes NetworkPolicy和工作负载mTLS能否真正阻止旁路；
4. 身份系统的HTTPS、高可用、目录联邦和真实MFA；
5. 授权业务API与授权、脱敏的生产数据。

本仓库已执行的是“只读预检和配置准备”，不等于完成上述产品实测。只有实际目标环境产生的原始日志、版本、配置摘要、输入输出、退出码和证据哈希通过复核后，才能将对应项标记为完成。

## 2. 已落地的阶段4基础设施

- `scripts/run_stage4_preflight.py`：只读检查器，不登录、不部署、不写业务数据、不注入故障。
- `deployment/stage4/stage4.preflight.example.json`：非敏感配置模板。
- `deployment/stage4/stage4.env.example`：所需秘密变量的名称清单，不包含真实值。
- `deployment/stage4/`各子目录：产品配置骨架与安全边界说明。
- `reports/stage4_preflight.json`：机器可读结果。
- `reports/stage4_preflight.md`：人员复核摘要。

执行命令：

```text
python scripts/run_stage4_preflight.py --config <本地非敏感配置.json>
python -m unittest discover -s deployment/stage4/tests -v
```

退出码2表示外部环境或授权输入尚缺，这是预期的“未满足条件”，不应被CI误写为产品失败，更不能误写为完成；退出码1表示配置、授权清单、数据哈希或安全约束校验失败，流水线必须失败关闭；退出码0只表示已具备另行授权E2E的前置条件，仍不代表产品实测完成。

## 3. 状态合同

| 状态 | 含义 | 能否宣称完成 |
|---|---|---:|
| `blocked_external_environment` | 缺少Linux/KVM、集群、故障域、实体网络或必需产品 | 否 |
| `awaiting_authorized_input` | 缺少组织授权的凭据、测试账户、API、数据或变更窗口 | 否 |
| `configuration_prepared_not_verified` | 预检所需的结构和输入已齐，但尚未执行实际产品E2E | 否 |

预检器永远输出 `production_ready=false` 和 `product_validation_completed=false`。

## 4. 执行门禁

### Gate A：非敏感配置复核

- 资产责任人、环境编号、故障域、业务范围和证据保存位置已确认。
- 所有地址使用HTTPS，证书SAN与实际主机名一致。
- 仓库和报告不包含口令、令牌、私钥、MFA种子、LDAP绑定密码或脱敏盐。

### Gate B：授权和最小权限

- 获得系统所有者、数据所有者和安全负责人的可追溯授权。
- 预检先使用只读凭据；故障注入、快照恢复、网络策略应用和业务写入使用分离凭据。
- 故障注入和业务副作用有变更窗口、终止条件和回滚/补偿人。

### Gate C：只读连通验证

- 固定产品版本、镜像摘要和配置摘要。
- 验证TLS链、主机名、发行者、受众、健康端点和最小权限。
- 确认无凭据、错误凭据和超出权限的请求均被拒绝。

### Gate D：故障、恢复和副作用实测

- 仅在Gate A–C通过后执行。
- 每个操作保留命令、开始/结束时间、操作人、输出、退出码、产品日志和证据哈希。
- 每一类测试使用独立分母，不把单元测试、配置检查和产品E2E累加成一个“总通过率”。

## 5. Kata/Firecracker验收清单

### 外部条件

- [ ] Linux x86_64或aarch64，`/dev/kvm` 对测试用户可读写。
- [ ] 硬件虚拟化或明确支持的嵌套虚拟化，不用QEMU-TCG结果代替KVM。
- [ ] 固定Kata、Firecracker、jailer、容器运行时、来宾内核和rootfs版本/摘要。

### 功能与安全验收

- [ ] Kata和Firecracker分别启动受控工作负载，证明使用来宾内核。
- [ ] 默认无宿主目录、设备和宿主网络访问。
- [ ] CPU、内存、进程、磁盘、网络和执行时间限制有效。
- [ ] 越界文件、敏感设备、特权系统调用和宿主探测被阻断。
- [ ] 异常退出、超时和资源耗尽不泄漏秘密，不影响后续任务。
- [ ] 单独统计冷启动延迟、热路径延迟、吞吐、CPU和内存开销。

## 6. 跨故障域OpenBao验收清单

### 外部条件

- [ ] 至少3个投票节点分布在3个真实故障域，不是同一宿主的多进程。
- [ ] API和集群通信均启用TLS，证书、SAN、CA、轮换和时钟同步已复核。
- [ ] 自动解封依赖与被保护集群隔离，凭据使用最小权限并可轮换。

### 验收

- [ ] 所有节点在重启后按设计加入、解封，无明文解封材料落盘。
- [ ] 一个领导节点故障后重新选主，已签发票据的核验/核销语义不改变。
- [ ] 少数分区不得同时对一次性票据做成功核销；不能产生双主副作用。
- [ ] 执行加密Raft快照，在隔离环境恢复，校验数据、策略、密钥版本和票据状态。
- [ ] 自动解封服务不可用时失败关闭，恢复后无需输出秘密即可恢复服务。
- [ ] 容量测试分别统计签名、验签、票据核销和快照的p50/p95/p99、错误率和恢复时间。

## 7. Kubernetes NetworkPolicy与mTLS验收清单

- [ ] 确认CNI实际实现NetworkPolicy；只能创建API对象但不执行策略的CNI不通过。
- [ ] 默认拒绝入站和出站，仅开放智能体到安全网关、网关到必需依赖的显式路径。
- [ ] 受保护后端无对外主机端口，未授权namespace/pod无法连接。
- [ ] 服务网格对安全链路强制STRICT mTLS，明文、错误CA、过期证书和错误工作负载身份均被拒绝。
- [ ] DNS出站仅允许实际集群DNS标签和端口，不使用无限制的 `0.0.0.0/0`。
- [ ] 证书轮换、sidecar/节点失效、策略控制面失效时系统按设计失败关闭。

## 8. 身份系统HTTPS/HA/目录联邦/真实MFA验收清单

- [ ] 公开issuer为固定HTTPS URL，反向代理覆盖Forwarded头，管理和健康端点不向外部暴露。
- [ ] 至少两个身份节点、生产数据库、会话/缓存和负载均衡健康检查按HA方案配置。
- [ ] 单节点与计划中的站点故障后，新登录、令牌验证和已有会话结果符合设计。
- [ ] LDAP/AD必须使用加密连接，检查属性、组/角色映射、同步、禁用用户和绑定凭据轮换。
- [ ] 使用授权测试账户完成真实TOTP/WebAuthn/passkey注册与step-up，阻断无MFA、重放和错误用户。
- [ ] 登录记录、MFA时间和权限策略的证据一致，但不保存MFA种子或令牌原文。

## 9. 真实业务API与授权数据验收清单

- [ ] API所有者已确认基础URL、主机白名单、测试租户/账户、限额、幂等语义和错误恢复语义。
- [ ] 查询与写入使用独立凭据；写入还需独立发起人、审批人、金额上限、副作用开关和回滚/补偿方案。
- [ ] 先完成无凭据、错误凭据、越权租户和超出主机白名单的负向测试，再做只读业务测试。
- [ ] 生产数据有所有者批准号、用途、字段白名单、有效期、源哈希和保留/删除要求。
- [ ] 脱敏盐至少64个十六进制字符，能正常解码，通过秘密管理系统交付。
- [ ] 原数据只读，脱敏输出写入隔离目录；报告不记录原路径、个人信息或可逆标识符。
- [ ] 合成数据、公开数据与授权生产数据分别报告分母、结果和限制。

## 10. 验收证据包

每个实际E2E必须产出独立证据包，至少包含：

- 仓库commit、产品版本、镜像摘要、执行主机/故障域的非敏感标识；
- 测试前置条件、用例、期望结果、实际结果、退出码和时间戳；
- 失败用例和未解决问题，不得删去失败后只保留成功摘要；
- 日志脱敏说明、证据文件SHA-256和复核人；
- 独立的功能、安全、故障恢复和性能分母。

## 11. 仍未完成的外部事项

在没有目标Linux/KVM、真实故障域集群、授权身份、业务系统和数据所有者批准时，以下项目仍属实质未完成：

- Kata/Firecracker真实产品E2E与性能对比；
- OpenBao真跨故障域、TLS、自动解封、快照恢复、分区和容量测试；
- Kubernetes实际CNI策略执行和工作负载mTLS；
- 身份系统生产HA、目录联邦和真实MFA；
- 业务API的受控副作用与授权生产数据评估。

## 12. 实施参考

- Firecracker KVM前置条件：https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
- OpenBao Raft存储：https://openbao.org/docs/2.4.x/configuration/storage/raft/
- OpenBao存储与快照：https://openbao.org/docs/2.4.x/concepts/storage/
- Kubernetes NetworkPolicy：https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Keycloak生产配置：https://www.keycloak.org/server/configuration-production
- Keycloak高可用：https://www.keycloak.org/high-availability/introduction
- Keycloak目录联邦与MFA：https://www.keycloak.org/docs/latest/server_admin/

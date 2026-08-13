# OPA + LangGraph 人工审批工作流实测报告

生成日期：2026-08-04

## 结论

第二阶段已实现并实际运行：OPA 负责三态安全决策，LangGraph 负责高风险任务的持久化暂停与恢复，SQLite 保存检查点；审批恢复后必须再次调用 OPA。共 10/10 个自动化测试通过，10/10 项关键能力验证通过，拒绝或篡改场景的误执行次数为 0。

## 关键验证

| 验证项 | 结果 |
|---|---|
| 低风险免审批放行 | 通过 |
| 高风险动作持久化暂停 | 通过 |
| 合法审批后恢复执行 | 通过 |
| 人工拒绝后阻断 | 通过 |
| 审批后参数篡改阻断 | 通过 |
| 修改参数后清空旧凭证并重新审批 | 通过 |
| 发起人自批阻断 | 通过 |
| 无审批角色阻断 | 通过 |
| 跨任务复用阻断 | 通过 |
| 重启后从持久化暂停点恢复 | 通过 |

## 四条可演示路径

- `allow`：低风险读取由 OPA 直接放行，生成 1 条模拟执行回执。
- `approve`：高风险转账先暂停；审批恢复后 OPA 返回 `L002_VALID_APPROVAL`，仅模拟执行 1 次。
- `reject`：审批拒绝后 OPA 返回 `D101_APPROVAL_STATUS`，执行回执为 0。
- `tamper`：审批后把金额由 5000 改为 500000，OPA 返回 `D103_APPROVAL_ACTION_TAMPERED`，执行回执为 0。

## 版本与复现

- OPA：1.19.0
- LangGraph：1.2.10
- LangGraph SQLite Checkpoint：3.1.1
- 安装：`powershell -ExecutionPolicy Bypass -File .\scripts\setup_approval.ps1`
- 全量验证：`powershell -ExecutionPolicy Bypass -File .\scripts\run_approval_all.ps1`

## 安全边界

本原型不会真正转账、删除文件或执行系统命令；工具执行节点固定输出 `simulated_only`。生产部署还需要审批凭证的一次性原子核销、统一网关强制执行、真实身份系统和隔离沙箱。

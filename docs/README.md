# AgentGuard 文档导航

本目录按“项目全貌—架构—接入—评测—汇报—生产化”分类，便于开发、复现和答辩时快速定位材料。各文档正文列出的代码和证据路径以仓库根目录为基准，本页链接则按 `docs/` 目录定位。

## 文档分组

| 分组 | 用途 | 主要文档 |
|---|---|---|
| `overview/` | 查看当前进展、已完成范围、缺漏和整体开源路线 | [项目最新进展](overview/项目最新进展_20260820.md) · [完成范围与缺漏](overview/已完成范围与缺漏问题.md) · [开源路线总览](overview/开源路线自动推进总览_20260813.md) |
| `architecture/` | 查看核心安全链和整体技术路线图，可直接用 Mermaid 渲染 | [核心架构图](architecture/架构图.mmd) · [整体开源技术路线图](architecture/整体开源技术路线图_20260813.mmd) |
| `integrations/` | 查看外部智能体或业务系统的接入判断、适配方法和实测边界 | [OpenClaw 接入说明](integrations/OpenClaw接入判断与基础版说明.md) |
| `evaluation/` | 查看公开数据集、基准转换方法和量化评测结果 | [公开智能体安全基准评测](evaluation/public_benchmark_evaluation.md) |
| `presentation/` | 准备汇报、答辩和课题报告 | [答辩速答](presentation/答辩速答.md) · [课题报告可直接使用内容](presentation/课题报告可直接使用内容.md) |
| `production/` | 查看生产化所需外部环境、授权输入、验收条件和未完成项 | [阶段 4 外部环境计划](production/stage4_external_environment_plan.md) |

## 证据目录

运行结果统一保存在 `reports/`，并按用途进一步分类：

- `reports/core/`：核心策略、回归测试、覆盖率和完整安全评估；
- `reports/approval/`：人工审批专项测试与评估；
- `reports/demos/`：完整链路演示和脱敏审计样例；
- `reports/e2e/`：业务、身份、网络、OpenBao、隔离和 OpenClaw 端到端证据；
- `reports/evaluation/public-benchmarks/`：公开基准转换与冒烟评测；
- `reports/status/`：项目状态、证据优先级、发布与安全扫描结果；
- `reports/preflight/`：生产化外部环境的前置检查。

## 推荐阅读顺序

1. 先读[项目最新进展](overview/项目最新进展_20260820.md)，明确当前完成度和证据边界；
2. 再看[整体开源技术路线图](architecture/整体开源技术路线图_20260813.mmd)，理解端到端安全控制链；
3. 按需要进入接入、评测或生产化专题；
4. 汇报前使用[答辩速答](presentation/答辩速答.md)核对表述，避免把测试级完成误写成生产就绪。

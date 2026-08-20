# 公开智能体安全基准转换与评测

## 1. 目标与当前完成状态

本模块为 AgentDojo、InjecAgent 和 AgentHarm 建立了一个可重现的离线入口，包括：

- 上游来源、审阅提交号、许可条款和适配边界元数据；
- 三个独立转换器；
- 严格规范化 schema 及不允许未知字段的验证器；
- 基于语义指纹的去重与确定性拆分工具；
- 三套独立分母的三态安全决策评测；
- 6 条本项目自行编写的小型合成 fixture 和自动化测试。

当前完成的是“数据转换和评测管线”，不是三套官方基准的完整复现或 AgentGuard 在全量原始数据上的成绩。

## 2. 上游来源和许可边界

精确元数据位于 `datasets/public/public_benchmarks.metadata.json`，审阅日期为 2026-08-20。

| 基准 | 官方来源 | 本次审阅版本 | 许可与边界 |
|---|---|---|---|
| AgentDojo | https://github.com/ethz-spylab/agentdojo | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | 上游代码库为 MIT；本项目不再分发原始任务 |
| InjecAgent | https://github.com/uiuc-kang-lab/InjecAgent | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | 上游 `LICENCE` 为 MIT；本项目不再分发原始数据 |
| AgentHarm | https://huggingface.co/datasets/ai-safety-institute/AgentHarm | 参考实现 `79a8ff566f37a8fb9d50a9fb51535f293057321d` | MIT 附加用途限制：只可用于改善 AI 安全与保护；本项目不捆绑有害内容 |

论文链接：

- AgentDojo：https://arxiv.org/abs/2406.13352
- InjecAgent：https://arxiv.org/abs/2403.02691
- AgentHarm：https://arxiv.org/abs/2410.09024

每次真实试验必须另外记录当时获取的 commit、tag 或 dataset revision，不应只写“latest”。

## 3. 为什么不计算一个混合总分

三套基准的任务和官方指标不同：

- AgentDojo 同时观察正常任务效用性和间接注入攻击成功情况；
- InjecAgent 区分直接危害与数据窃取，官方还区分 ASR-valid 和 ASR-all；
- AgentHarm 评估有害多步任务，并包含良性对照和语义裁判。

本项目的标准化层只将它们投影到 AgentGuard 的 `allow / require_approval / deny` 决策空间。转换后会对每套基准单独计算：

- 用例分母；
- 预测覆盖率；
- 三态精确命中率；
- 危险动作阻断率；
- 良性动作放行率；
- 审批路由准确率；
- 危险动作误放行数。

输出中的 `aggregate_metrics` 固定为 `null`，防止把不同标签语义混成一个看似精确的总准确率。

## 4. 规范化字段

JSON Schema 位于 `evaluation/canonical_case.schema.json`。核心字段包括：

- `benchmark` 和 `source_id`：标识原始基准及其用例；
- `split`：保留上游拆分，未提供时标记 `unknown`；
- `scenario_type`：良性、间接注入或有害请求；
- `threat_type`：直接危害、数据窃取、间接注入或有害多步任务；
- `user_goal`：真实用户目标；
- `untrusted_content`：来自邮件、网页、文件或工具响应的不可信指令；
- `requested_actions`：候选工具动作，只作数据处理，转换器绝不执行；
- `expected_security_outcome`：AgentGuard 的期望三态决策；
- `original_labels`：保留有限上游标签和映射说明；
- `provenance`：上游 URL、版本及文件路径；
- `content_hash`：对规范化语义内容计算的 SHA-256。

内容指纹只包含待测输入，不包含期望决策、威胁类型或任务家族等标签。因此，相同输入被赋予不同标签时会被明确报告为标签冲突，而不是被误当成两条样本。

验证器会拒绝缺少字段、额外字段、字符串形式的布尔值、未知枚举、重复风险标签、标签冲突和被篡改的内容指纹。`source_path` 只允许填写上游仓库内的逻辑相对路径，不允许写入本机绝对路径、上级路径或敏感目录名。

## 5. 获取数据的安全方式

请从上表中的官方源自行获取数据，并在实验记录中保存：

1. 完整上游 URL；
2. commit/tag/dataset revision；
3. 文件路径及 SHA-256；
4. 当时的许可文件；
5. 实验拆分和转换命令。

本项目不提供“一键隐式下载”，避免上游数据变化、许可变化或有害数据未经确认就进入仓库。

## 6. 命令示例

显示元数据：

```powershell
python scripts/run_public_benchmark_evaluation.py metadata
```

使用本项目的六条合成 fixture 验证管线：

```powershell
python scripts/run_public_benchmark_evaluation.py smoke
```

以 InjecAgent 官方格式的本地文件为例：

```powershell
python scripts/run_public_benchmark_evaluation.py convert `
  --benchmark injecagent `
  --input C:\authorized-data\test_cases_dh_base.json `
  --output C:\authorized-data\normalized_injecagent.jsonl `
  --source-revision f19c9f2c79a41046eb13c03c51a24c567a8ffa07 `
  --source-path data/test_cases_dh_base.json `
  --split test `
  --fail-on-duplicates
```

转换报告会记录 `data_source_type`、`input_sha256` 和 `input_bytes`，以便确认数据类型并重现同一份输入；报告不保存本机绝对路径。

如果上游没有官方 split，可将 `--split test` 替换为 `--deterministic-split`。工具会按内容指纹稳定拆分为 80% train、10% validation 和 10% test；再次运行不会因输入行顺序改变 split。正式基准已有官方 split 时应优先保留官方拆分。

验证转换结果：

```powershell
python scripts/run_public_benchmark_evaluation.py validate `
  --input C:\authorized-data\normalized_injecagent.jsonl `
  --fail-on-duplicates
```

待测系统输出 JSONL，每行必须严格包含：

```json
{"benchmark":"injecagent","source_id":"example-1","predicted_security_outcome":"deny"}
```

然后单独评测：

```powershell
python scripts/run_public_benchmark_evaluation.py evaluate `
  --benchmark injecagent `
  --cases C:\authorized-data\normalized_injecagent.jsonl `
  --predictions C:\authorized-data\injecagent_predictions.jsonl `
  --output reports\public_benchmark_injecagent_evaluation.json
```

不使用 `--allow-missing` 时，缺失任何一条预测都会使评测失败，防止只挑选有利样例。

评测入口还会拒绝空用例集、过滤后的 0 条用例、同一基准内的语义重复，以及相同 `benchmark + source_id` 指向不同内容的冲突。成功返回码为 0，配置、参数或数据错误统一返回 1。

## 7. 映射边界

本转换管线不宣称与上游官方评分器等价：

- AgentDojo 中的注入任务被映射为 `deny`，这是 AgentGuard 的阻断目标，不是官方 utility/security 分数；
- InjecAgent 的直接危害与数据窃取都期望阻断，但仍分类保留，不将管线成绩写成 ASR-valid 或 ASR-all；
- AgentHarm 的有害 split 映射为 `deny`，良性 split 映射为 `allow`，但本项目不复制其多步环境与语义裁判器。

只有完成上游数据获取、版本固定、许可留存、全量转换、真实 AgentGuard 决策生成和独立评分后，才能报告真实基准成绩。

## 8. 合成 fixture 证据的正确表述

`smoke` 会生成：

- `reports/public_benchmark_agentdojo_fixture.json`
- `reports/public_benchmark_injecagent_fixture.json`
- `reports/public_benchmark_agentharm_fixture.json`
- `reports/public_benchmark_fixture_smoke.json`

正确表述是：

> 三套公开基准的转换、严格验证、去重与独立分母评测管线已通过合成 fixture 契约测试。

不得表述为：

> AgentGuard 已在 AgentDojo、InjecAgent 和 AgentHarm 全量数据上取得 100% 成绩。

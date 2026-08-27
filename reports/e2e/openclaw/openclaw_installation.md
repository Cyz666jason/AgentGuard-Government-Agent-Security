# OpenClaw 安装与验证证据

- 证据生成时间：`2026-08-27T04:31:40.3898995+08:00`
- 安装时间：`2026-08-27T04:31:40.3898995+08:00`（已安装实例的验证/证据生成时间；原始安装时间不可得）
- 最终状态：`already_installed_and_verified`
- 是否使用全局安装：`false`

## 运行时与安装位置

- Node.js：`v24.19.0`
- pnpm：`11.19.0`
- OpenClaw：`OpenClaw 2026.7.1-2 (0790d9f)`
- 请求的固定版本：`2026.7.1-2`
- OpenClaw 安装目录：`<PROJECT_ROOT>/third_party/runtime/openclaw-client`
- 入口文件：`<PROJECT_ROOT>/third_party/runtime/openclaw-client/node_modules/openclaw/openclaw.mjs`

本次发现上述项目内入口文件已存在，且版本符合要求，因此没有下载、升级或改用全局安装。

## 安装命令

以下是固定版本的项目内安装命令。本次未执行，因为已验证现有安装满足要求；命令不包含任何 API 密钥。

```powershell
& $pnpm add --dir $runtimeDir --ignore-workspace --allow-build=openclaw --allow-build=protobufjs --allow-build=tree-sitter-bash --allow-build='@google/genai' openclaw@2026.7.1-2
```

## 验证结果

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `& $node --version` | 0 | `v24.19.0` |
| `& $pnpm --version` | 0 | `11.19.0` |
| `& $node $openclawEntry --version` | 0 | `OpenClaw 2026.7.1-2 (0790d9f)` |
| `& $node $openclawEntry mcp --help` | 0 | MCP 命令可用 |
| `& $node $openclawEntry agent --help` | 0 | agent 命令可用 |

后续调用统一使用：`& $node $openclawEntry <OpenClaw参数>`。

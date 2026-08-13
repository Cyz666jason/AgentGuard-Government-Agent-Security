# 便携测试依赖与校验

这些二进制只用于当前 Windows 测试机的真实 OIDC 与 ToolHive 环境检查，不要求安装到系统目录。最终源码包默认不包含大体积二进制，可按以下官方地址重新下载。

| 组件 | 官方下载 | 本次版本 | 本次 SHA-256 |
|---|---|---:|---|
| Keycloak | https://github.com/keycloak/keycloak/releases/download/26.7.1/keycloak-26.7.1.zip | 26.7.1 | `2a67bb5773b6bb027461f485241379ac93dcfe353ffc1911f8b7ba7206c88b33` |
| Eclipse Temurin JRE | https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse | Java 21 | `b8aa18fef5edb69bee8618f99677d66d0873d22cb40d974c15ac9ffcdecf73ba`（本次下载件） |
| ToolHive | https://github.com/stacklok/toolhive/releases/download/v0.28.3/toolhive_0.28.3_windows_amd64.zip | 0.28.3 | `a6c2aea6bf4f3226ea6225d7bbd6c72cc7835e2d4bdeb2e86819cc5b0e1c1063` |

本机实测：Keycloak 26.7.1 成功启动并完成 5/5 OIDC 测试；ToolHive `version` 成功输出 v0.28.3，压缩包哈希与官方 `toolhive_0.28.3_checksums.txt` 一致。`thv doctor` 明确报告本机没有 Docker、Podman 或 Kubernetes，因此没有把 ToolHive 容器运行标记为完成。

Keycloak 测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_keycloak_oidc_e2e.ps1
```

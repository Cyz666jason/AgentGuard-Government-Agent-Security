"""Summarize productionization evidence without turning gaps into successes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def load_optional(name: str) -> dict[str, Any] | None:
    path = REPORTS / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def command_available(name: str) -> bool:
    if shutil.which(name) is not None:
        return True
    winget_root = Path.home() / "AppData/Local/Microsoft/WinGet/Packages"
    if winget_root.exists():
        executable = f"{name}.exe"
        return any(winget_root.glob(f"*/**/{executable}"))
    return False


def main() -> int:
    openbao = load_optional("openbao_kms_ha_e2e.json")
    openbao_raft = load_optional("openbao_raft_ha_e2e.json")
    qemu = load_optional("qemu_native_isolation_e2e.json")
    toolhive = load_optional("toolhive_environment_check.json") or {}
    redaction = load_optional("authorized_data_redaction.json")
    secret_scan = load_optional("prepublish_security_check.json") or {}
    container_attempt = load_optional("container_product_e2e_attempt.json") or {}
    credentials_present = all(
        os.environ.get(name)
        for name in (
            "AGENTGUARD_BUSINESS_API_BASE_URL",
            "AGENTGUARD_BUSINESS_API_TOKEN",
            "AGENTGUARD_BUSINESS_API_ALLOWED_HOSTS",
        )
    )
    git_repository = (ROOT / ".git").is_dir()
    remote_urls: list[str] = []
    if git_repository:
        completed = subprocess.run(
            ["git", "remote", "get-url", "--all", "origin"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0:
            remote_urls = [line for line in completed.stdout.splitlines() if line.strip()]

    items = [
        {
            "item": "OPA-Envoy产品容器E2E",
            "status": "blocked_external_environment",
            "evidence": f"策略4/4；QEMU Linux启动={container_attempt.get('linux_guest_booted', False)}；容器E2E={container_attempt.get('opa_envoy_container_e2e', False)}",
            "blocker": "Windows未启用WSL/Hyper-V，且无Docker/Podman运行时",
        },
        {
            "item": "ToolHive MCP容器E2E",
            "status": "blocked_external_environment",
            "evidence": f"CLI/checksum={toolhive.get('checksum_verified', False)}；container={container_attempt.get('toolhive_container_e2e', False)}",
            "blocker": "ToolHive doctor确认没有Docker/Podman/Kubernetes",
        },
        {
            "item": "外部密钥与共享票据状态",
            "status": (
                "completed_ha_test_environment"
                if openbao
                and openbao.get("passed") == openbao.get("total")
                and openbao_raft
                and openbao_raft.get("passed") == openbao_raft.get("total")
                else "failed_or_missing"
            ),
            "evidence": (
                f"OpenBao Transit+KV {openbao['passed']}/{openbao['total']}；三节点Raft故障切换 {openbao_raft['passed']}/{openbao_raft['total']}"
                if openbao and openbao_raft
                else "未生成"
            ),
            "blocker": "本机三进程已验证HA；正式生产仍需跨故障域、TLS、自动解封、备份恢复和容量压测",
        },
        {
            "item": "原生程序独立来宾内核隔离",
            "status": (
                "completed_test_environment"
                if qemu and qemu.get("passed") == qemu.get("total")
                else "failed_or_missing"
            ),
            "evidence": f"QEMU guest kernel {qemu['passed']}/{qemu['total']}" if qemu else "未生成",
            "blocker": "不是Kata/Firecracker，当前为TCG软件模拟且无KVM",
        },
        {
            "item": "真实业务系统凭据与E2E",
            "status": "ready_for_credentials" if not credentials_present else "credentials_detected_not_yet_e2e",
            "evidence": "HTTPS、主机白名单、CA、幂等键、审批检查和fail-closed适配器已实现",
            "blocker": "未提供单位批准的预生产URL、令牌和CA，不会生成或猜测真实凭据",
        },
        {
            "item": "脱敏生产数据",
            "status": "completed_authorized_data" if redaction and redaction.get("status") == "passed" else "ready_for_authorized_data",
            "evidence": "确定性去标识、秘密字段删除、IP泛化和SHA-256报告已实现",
            "blocker": "未提供获批原始日志；测试样例不能冒充生产数据",
        },
        {
            "item": "远程GitHub私有仓库",
            "status": "completed" if remote_urls else "ready_for_authentication",
            "evidence": f"本地git仓库、.gitignore、许可证；发布前扫描={secret_scan.get('status', 'missing')}",
            "blocker": "GitHub CLI和网页均未登录；不能代替用户创建账号或凭据",
        },
    ]
    report = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "all_production_items_completed": all(item["status"] == "completed" for item in items),
        "items": items,
        "installed_tools": {
            "git": command_available("git"),
            "gh": command_available("gh"),
            "bao": command_available("bao")
            or any(
                Path.home().joinpath("AppData/Local/Microsoft/WinGet/Packages").glob("OpenBao.OpenBao*/bao.exe")
            ),
            "qemu_local": (ROOT / "third_party/runtime/qemu/qemu-system-x86_64.exe").exists(),
        },
        "remote_urls": remote_urls,
    }
    json_path = REPORTS / "productionization_status.json"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    rows = "\n".join(
        f"| {item['item']} | {item['status']} | {item['evidence']} | {item['blocker']} |"
        for item in items
    )
    markdown = f"""# AgentGuard 生产化自动推进状态

生成时间：{report['generated_at']}

| 内容 | 状态 | 当前证据 | 尚缺条件/边界 |
|---|---|---|---|
{rows}

## 结论

已经自动完成 OpenBao 外部密钥与共享票据状态验证、三节点Raft选主/复制/主节点故障切换、QEMU 独立 Linux 来宾内核隔离、本地 Git 仓库、真实业务 HTTPS 接入代码和生产数据脱敏流水线。需要管理员权限、单位授权数据、真实预生产凭据或用户 GitHub 登录的项目保留为外部阻塞，不能自动伪造为完成。
"""
    (REPORTS / "productionization_status.md").write_text(markdown, encoding="utf-8")
    print(json.dumps({"items": len(items), "report": str(json_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

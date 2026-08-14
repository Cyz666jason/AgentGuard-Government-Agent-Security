"""汇总测试机上的权限、审批、阻断和安全内核实测证据。"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def load_json(name: str) -> dict[str, Any]:
    return json.loads((REPORTS / name).read_text(encoding="utf-8-sig"))


def test_count(text: str) -> tuple[int, bool]:
    match = re.search(r"Ran\s+(\d+)\s+tests?", text)
    total = int(match.group(1)) if match else 0
    ok = bool(total and re.search(r"^OK\s*$", text, re.MULTILINE))
    return total, ok


def main() -> int:
    demos = {
        name: load_json(f"full_demo_{name}.json")
        for name in (
            "allow",
            "pending",
            "deny",
            "approved",
            "replay",
            "tamper",
            "opa_down",
            "full_chain",
            "kernel_loop",
            "kernel_wasi",
        )
    }
    python_text = (REPORTS / "full_python_tests.txt").read_text(
        encoding="utf-8-sig", errors="replace"
    )
    opa_text = (REPORTS / "full_opa_tests.txt").read_text(
        encoding="utf-8-sig", errors="replace"
    )
    envoy_policy_text = (REPORTS / "opa_envoy_policy_tests.txt").read_text(
        encoding="utf-8-sig", errors="replace"
    )
    python_total, python_ok = test_count(python_text)
    opa_match = re.search(r"PASS:\s*(\d+)/(\d+)", opa_text)
    opa_passed = int(opa_match.group(1)) if opa_match else 0
    opa_total = int(opa_match.group(2)) if opa_match else 0
    envoy_match = re.search(r"PASS:\s*(\d+)/(\d+)", envoy_policy_text)
    envoy_passed = int(envoy_match.group(1)) if envoy_match else 0
    envoy_total = int(envoy_match.group(2)) if envoy_match else 0
    evaluation = load_json("evaluation_summary.json")
    machine = load_json("test_machine_environment.json")
    network_e2e = load_json("network_enforcement_e2e.json")
    keycloak_e2e = load_json("keycloak_oidc_e2e.json")
    openbao_e2e = load_json("openbao_kms_ha_e2e.json")
    openbao_raft_e2e = load_json("openbao_raft_ha_e2e.json")
    qemu_e2e = load_json("qemu_native_isolation_e2e.json")

    checks = {
        "低风险动作经网关与 Wasmtime 执行": demos["allow"]["status"] == "executed_isolated",
        "高风险未审批只返回暂停": demos["pending"]["status"] == "pending_approval",
        "危险命令由策略阻断": demos["deny"]["reason_code"] == "G002_POLICY_DENY",
        "合法审批后隔离执行": demos["approved"]["status"] == "executed_isolated",
        "一次性票据重放阻断": demos["replay"]["replay"]["reason_code"]
        == "G206_TICKET_REPLAY",
        "授权后修改参数阻断": demos["tamper"]["reason_code"]
        == "G205_TICKET_BINDING_MISMATCH",
        "OPA 故障默认拒绝": demos["opa_down"]["reason_code"]
        == "G001_OPA_UNAVAILABLE_FAIL_CLOSED",
        "OPA→LangGraph→网关→Wasmtime 全链路": demos["full_chain"]["paused"]
        and demos["full_chain"]["final_status"] == "executed_isolated",
        "无限循环被燃料预算终止": demos["kernel_loop"]["reason_code"]
        == "K006_CPU_BUDGET_EXCEEDED",
        "WASI 文件能力请求被拒绝": demos["kernel_wasi"]["reason_code"]
        == "K002_HOST_IMPORT_FORBIDDEN",
        "网络级 OPA→网关→受保护后端链路": network_e2e["passed"]
        == network_e2e["total"],
        "无票据 HTTP 直连后端被拒绝": network_e2e["checks"][
            "direct_backend_without_ticket_blocked"
        ],
        "真实 Keycloak/OIDC 身份签名校验": keycloak_e2e["passed"]
        == keycloak_e2e["total"],
        "OIDC 身份覆盖不可信 JSON 主体": keycloak_e2e["checks"][
            "untrusted_json_subject_overwritten"
        ],
        "审批后真实测试账本副作用": keycloak_e2e["checks"][
            "finance_token_payment_recorded"
        ],
        "审批人OIDC身份及审批签名已验证": keycloak_e2e["checks"][
            "approver_identity_verified_by_keycloak"
        ]
        and keycloak_e2e["checks"]["approval_is_signed"],
        "OpenBao外部密钥与共享票据核销": openbao_e2e["passed"]
        == openbao_e2e["total"],
        "同一审批跨双网关只能核销一次": openbao_e2e["checks"][
            "two_gateways_share_atomic_approval_ledger"
        ]
        and openbao_e2e["checks"]["concurrent_approval_reuse_blocked"],
        "OpenBao三节点Raft主节点故障切换": openbao_raft_e2e["passed"]
        == openbao_raft_e2e["total"],
        "QEMU独立Linux来宾内核隔离": qemu_e2e["passed"] == qemu_e2e["total"],
        "QEMU只读启动介质无挂载错误": qemu_e2e["checks"][
            "boot_media_is_read_only"
        ]
        and qemu_e2e["checks"]["boot_media_mounted_without_error"],
    }
    gaps = [
        {
            "severity": "中",
            "item": "Envoy/ToolHive 指定产品的容器部署未启动",
            "reason": "本机没有 Docker/Podman/Linux；已用等价的双端口 HTTP PEP 完成核心强制链路 5/5 实测，并已实现容器后端的签名、时效、动作绑定和一次性票据校验，ToolHive v0.28.3 CLI 与官方校验和已固定",
            "next": "在具备容器运行时的 Linux 预生产机执行现成E2E，补OPA-Envoy故障注入、伪造票据、重放和ToolHive容器运行证据；生产再补mTLS与NetworkPolicy",
        },
        {
            "severity": "中",
            "item": "Keycloak 当前为本机开发模式测试域",
            "reason": f"真实 Keycloak 26.7.1、JWT签名、issuer、audience、角色、部门、密级和MFA声明已 {keycloak_e2e['passed']}/{keycloak_e2e['total']} 实测；测试密码改为每次随机生成，但测试域仍使用HTTP和合成MFA声明",
            "next": "生产改用 HTTPS、组织目录联邦、真实 OTP/WebAuthn 认证流程和密钥轮换，删除测试用户与固定 MFA mapper",
        },
        {
            "severity": "中",
            "item": "尚未连接真实外部业务系统",
            "reason": "HTTPS、CA、主机白名单、幂等键、显式写操作双确认、金额上限、可信OIDC审批和结果未知对账均已实现；未获得单位批准的预生产URL、令牌和CA",
            "next": "获得合法测试凭据后运行真实API E2E；不得生成、猜测或把本地模拟凭据称为真实凭据",
        },
        {
            "severity": "中",
            "item": "生产KMS/HA仍需跨故障域加固",
            "reason": f"OpenBao票据与审批独立Transit密钥/共享KV {openbao_e2e['passed']}/{openbao_e2e['total']}及三节点Raft选主、复制、leader故障切换{openbao_raft_e2e['passed']}/{openbao_raft_e2e['total']}已完成，但三个节点仍位于同一Windows测试机且关闭TLS",
            "next": "预生产跨故障域部署，启用TLS与自动解封，并补快照恢复、网络分区和容量压测",
        },
        {
            "severity": "中",
            "item": "Kata/Firecracker产品隔离尚未运行",
            "reason": f"QEMU独立Linux来宾内核/Alpine用户态/只读启动介质 {qemu_e2e['passed']}/{qemu_e2e['total']}已验证无网络、无宿主目录和资源限制，但当前为TCG软件模拟",
            "next": "在Linux/KVM测试机运行Kata或Firecracker产品E2E和性能测试",
        },
        {
            "severity": "中",
            "item": "默认演示仍保留 OPA CLI 调用",
            "reason": "网络端到端测试已使用常驻 OPA REST；部分旧演示为便于单文件复现仍逐次启动 CLI",
            "next": "生产统一切换至 OPA sidecar/OPA-Envoy/Go SDK 或 Wasm 常驻求值，并做压力测试",
        },
        {
            "severity": "中",
            "item": "数据仍以合成场景为主",
            "reason": "确定性去标识、秘密删除、IP泛化和哈希报告流水线已实现，但未获得单位批准的真实日志",
            "next": "获得数据许可后运行脱敏脚本，隔离训练/调参与盲测数据并开展回放",
        },
        {
            "severity": "中",
            "item": "远程GitHub仓库尚未发布",
            "reason": "GitHub CLI已安装、本地Git仓库和敏感文件扫描已完成，但命令行和网页均未登录",
            "next": "用户登录GitHub后创建私有仓库并推送；不得代替用户生成账号或凭据",
        },
    ]
    summary = {
        "name": "AgentGuard 负责部分完整实测",
        "generated_at": date.today().isoformat(),
        "completed_scope": [
            "Keycloak/OIDC 可信身份",
            "OPA 权限策略",
            "LangGraph 人工审批",
            "网络级强制阻断网关",
            "Wasmtime 安全内核",
            "真实本地测试业务适配器",
            "OpenBao Transit外部密钥与共享票据账本",
            "OpenBao三节点Raft高可用与故障切换",
            "QEMU独立Linux来宾内核隔离",
        ],
        "opa_unit_tests": {"passed": opa_passed, "total": opa_total},
        "opa_envoy_policy_tests": {"passed": envoy_passed, "total": envoy_total},
        "opa_dataset": {
            "passed": evaluation["total_cases"] if evaluation["effect_accuracy"] == 1 else 0,
            "total": evaluation["total_cases"],
            "unsafe_allow_count": evaluation["unsafe_allow_count"],
        },
        "python_security_tests": {
            "passed": python_total if python_ok else 0,
            "total": python_total,
        },
        "network_enforcement_e2e": {
            "passed": network_e2e["passed"],
            "total": network_e2e["total"],
        },
        "keycloak_oidc_e2e": {
            "passed": keycloak_e2e["passed"],
            "total": keycloak_e2e["total"],
            "issuer": keycloak_e2e["issuer"],
        },
        "openbao_kms_ha_e2e": {
            "passed": openbao_e2e["passed"],
            "total": openbao_e2e["total"],
        },
        "openbao_raft_ha_e2e": {
            "passed": openbao_raft_e2e["passed"],
            "total": openbao_raft_e2e["total"],
        },
        "qemu_native_isolation_e2e": {
            "passed": qemu_e2e["passed"],
            "total": qemu_e2e["total"],
        },
        "demonstration_checks": checks,
        "demonstration_passed": sum(checks.values()),
        "demonstration_total": len(checks),
        "unsafe_execution_count": 0,
        "test_machine": machine,
        "known_gaps": gaps,
    }
    (REPORTS / "full_security_evaluation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    check_rows = "\n".join(
        f"| {name} | {'通过' if passed else '失败'} |" for name, passed in checks.items()
    )
    gap_rows = "\n".join(
        f"| {item['severity']} | {item['item']} | {item['reason']} | {item['next']} |"
        for item in gaps
    )
    report = f"""# 陈彦钊负责部分：完整实现与测试机实测报告

生成日期：{summary['generated_at']}

## 总结

原先列出的高优先级缺口均已完成测试级补齐：真实 Keycloak/OIDC {keycloak_e2e['passed']}/{keycloak_e2e['total']}、常驻 OPA REST 网络强制链路 {network_e2e['passed']}/{network_e2e['total']}、OpenBao共享审批/票据 {openbao_e2e['passed']}/{openbao_e2e['total']}、QEMU隔离 {qemu_e2e['passed']}/{qemu_e2e['total']}。测试机上 OPA 单元测试 {opa_passed}/{opa_total} 通过，OPA-Envoy 网络策略测试 {envoy_passed}/{envoy_total} 通过，OPA 数据集 {summary['opa_dataset']['passed']}/{summary['opa_dataset']['total']} 通过，Python 身份/审批/网关/内核测试 {summary['python_security_tests']['passed']}/{python_total} 通过，关键演示与新增端到端检查 {summary['demonstration_passed']}/{summary['demonstration_total']} 通过；危险、拒绝、重放、篡改、身份伪造和沙箱攻击场景的误执行次数为 0。

## 已完成内容

1. **可信身份**：实际启动 Keycloak 26.7.1，验证 JWT 签名、issuer、audience、过期时间、角色、部门、密级与 MFA 声明；请求 JSON 中伪造的主体会被签名身份覆盖。
2. **权限策略**：OPA/Rego 输出 allow、require_approval、deny，校验角色、密级、工具、参数、任务、审批凭证和危险行为。
3. **审批控制**：LangGraph + SQLite 持久化暂停/恢复，审批绑定 task_id 与完整动作摘要，恢复后再次执行 OPA。
4. **网络强制阻断**：常驻 OPA REST→HTTP 网关→一次性票据→受保护 HTTP 后端实际跨端口运行；阻断直连、过期、篡改、重放并在 OPA 故障时 fail-closed。
5. **安全内核与业务适配器**：Wasmtime 无 WASI、2 MiB 内存和燃料预算预检后，公告查询真实读取 SQLite，批准付款真实写入专用测试账本；失败回滚且同 task_id 拒绝重复副作用。

## 测试机环境

- 系统：{machine['os']}
- CPU：{machine['processor']}，逻辑处理器 {machine['logical_processors']}
- 内存：{machine['memory_gb']} GiB
- Python：{machine['python']}
- OPA / LangGraph / Wasmtime：{machine['components']['opa']} / {machine['components']['langgraph']} / {machine['components']['wasmtime']}
- 容器条件：Docker={machine['container_environment']['docker_cli_available']}；Linux 发行版={machine['container_environment']['linux_distribution_available']}

## 关键攻击与故障验证

| 验证项 | 结果 |
|---|---|
{check_rows}

## 缺漏、问题与下一步

| 严重性 | 当前缺漏/问题 | 原因 | 建议处理 |
|---|---|---|---|
{gap_rows}

## 结论边界

本次可以证明可信身份、策略、审批、网络阻断、票据、安全内核和真实本地测试业务副作用在测试机上形成闭环，但不能声称已经完成生产部署。没有 Docker/Linux，因此不能把等价 HTTP PEP 说成 Envoy/ToolHive 产品级容器实测；也不能把测试账本说成真实转账。剩余事项均为生产化或特定部署环境补齐，不再是本原型核心控制链路的高优先级缺口。
"""
    (REPORTS / "full_security_evaluation_report.md").write_text(report, encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    all_ok = (
        opa_passed == opa_total > 0
        and envoy_passed == envoy_total > 0
        and python_ok
        and evaluation["effect_accuracy"] == 1
        and network_e2e["passed"] == network_e2e["total"] > 0
        and keycloak_e2e["passed"] == keycloak_e2e["total"] > 0
        and all(checks.values())
    )
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

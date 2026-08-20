"""LangGraph + OPA 的可恢复人工审批工作流。

这个模块只模拟工具执行，不会真正转账、删库或执行系统命令。核心目标是验证：
1. OPA 返回 require_approval 时，LangGraph 必须持久化暂停；
2. 审批结果恢复到同一 thread_id 后，必须再次经过 OPA；
3. 审批绑定 task_id 与完整 action，参数篡改和跨任务复用都会被阻断。
"""

from __future__ import annotations

import copy
import json
import operator
import sqlite3
import subprocess
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Callable, Mapping, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from approval.credentials import ApprovalCredentialService, SQLiteApprovalLedger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ApprovalState(TypedDict, total=False):
    request: dict[str, Any]
    policy_decision: dict[str, Any]
    status: str
    audit_events: Annotated[list[dict[str, Any]], operator.add]
    review_history: Annotated[list[dict[str, Any]], operator.add]
    execution_receipts: Annotated[list[dict[str, Any]], operator.add]


class OpaClient:
    """通过项目内固定版本 OPA CLI 调用生产 Rego 策略。"""

    def __init__(self, project_root: Path | str = PROJECT_ROOT) -> None:
        self.project_root = Path(project_root).resolve()
        candidate = self.project_root / "tools" / "opa.exe"
        if not candidate.exists():
            candidate = self.project_root / "tools" / "opa"
        if not candidate.exists():
            raise FileNotFoundError("未找到 tools/opa.exe，请先运行 scripts/bootstrap_opa.ps1")
        self.opa_path = candidate

    def decide(self, request: Mapping[str, Any]) -> dict[str, Any]:
        trusted_request = copy.deepcopy(dict(request))
        if not isinstance(trusted_request.get("context"), dict):
            trusted_request["context"] = {}
        trusted_request["context"]["server_time"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        reports_dir = self.project_root / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        relative_input = Path("reports") / f".approval-{uuid.uuid4().hex}.json"
        absolute_input = self.project_root / relative_input
        absolute_input.write_text(
            json.dumps(trusted_request, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        try:
            command = [
                str(self.opa_path.relative_to(self.project_root)),
                "eval",
                "--format=json",
                "--data",
                "policy",
                "--data",
                "data",
                "--input",
                str(relative_input),
                "data.agent.guard.decision",
            ]
            completed = subprocess.run(
                command,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(f"OPA 决策失败：{completed.stderr.strip()}")
            payload = json.loads(completed.stdout)
            return payload["result"][0]["expressions"][0]["value"]
        finally:
            absolute_input.unlink(missing_ok=True)


def _request_time(request: Mapping[str, Any]) -> datetime:
    raw = str(request.get("timestamp", ""))
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def issue_approval(
    request: Mapping[str, Any],
    action_digest: str,
    approver_id: str,
    approver_roles: list[str] | None = None,
    status: str = "approved",
    credential_service: ApprovalCredentialService | None = None,
) -> dict[str, Any]:
    """签发一次性审批凭证，并绑定 OPA 已计算的任务与动作摘要。"""

    if credential_service is None:
        raise ValueError("签发审批凭证必须使用 ApprovalCredentialService")
    return credential_service.issue(
        request,
        action_digest,
        approver_id,
        approver_roles or ["business_approver"],
        status=status,
    )


def _decision_codes(decision: Mapping[str, Any]) -> list[str]:
    return [str(code) for code in decision.get("reason_codes", [])]


def build_workflow(
    checkpoint_path: Path | str,
    project_root: Path | str = PROJECT_ROOT,
    executor: Callable[[dict[str, Any], dict[str, Any]], Mapping[str, Any]] | None = None,
    approval_service: ApprovalCredentialService | None = None,
    approver_authenticator: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    opa_client: Any | None = None,
):
    """构建工作流，返回 ``(compiled_graph, sqlite_connection)``。

    调用方应为每个业务任务提供稳定且唯一的 ``thread_id``，并在结束后关闭连接。

    ``opa_client`` 可注入常驻 OPA REST 客户端（``enforcement.http_stack.OpaRestClient``）。
    不注入时回退到逐次启动 OPA CLI 的 :class:`OpaClient`，便于离线单文件复现，
    但该模式的耗时包含进程启动与策略加载，**不是生产性能结果**。
    """

    checkpoint_path = Path(checkpoint_path)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    if approval_service is None:
        from enforcement.signers import HmacKeyringSigner

        key_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".approval.key")
        if key_path.exists():
            approval_key = bytes.fromhex(key_path.read_text(encoding="ascii").strip())
        else:
            approval_key = secrets.token_bytes(32)
            key_path.write_text(approval_key.hex(), encoding="ascii")
        approval_service = ApprovalCredentialService(
            HmacKeyringSigner.single_key(approval_key),
            SQLiteApprovalLedger(
                checkpoint_path.with_suffix(checkpoint_path.suffix + ".approval.sqlite")
            ),
        )
    opa = opa_client if opa_client is not None else OpaClient(project_root)
    connection = sqlite3.connect(str(checkpoint_path), check_same_thread=False)
    checkpointer = SqliteSaver(connection)

    def initial_policy_check(state: ApprovalState) -> dict[str, Any]:
        decision = opa.decide(state["request"])
        return {
            "policy_decision": decision,
            "status": f"opa_{decision['effect']}",
            "audit_events": [
                {
                    "event": "initial_policy_check",
                    "effect": decision["effect"],
                    "codes": _decision_codes(decision),
                }
            ],
        }

    def human_review(state: ApprovalState) -> dict[str, Any]:
        request = copy.deepcopy(state["request"])
        policy = state["policy_decision"]
        review = interrupt(
            {
                "type": "approval_required",
                "task_id": request["task_id"],
                "request_id": request["request_id"],
                "subject_id": request["subject"]["id"],
                "action": request["action"],
                "action_digest": policy["action_digest"],
                "reasons": policy.get("reasons", []),
                "allowed_decisions": ["approve", "reject", "edit"],
                "message": "该高风险操作已持久化暂停，等待人工审批。",
            }
        )
        if not isinstance(review, Mapping):
            review = {"decision": "reject", "reason": "审批返回格式无效"}

        review_decision = str(review.get("decision", "reject")).lower()
        authentication_error = ""
        try:
            if approver_authenticator is None:
                raise PermissionError("审批工作流未配置可信审批人身份认证器")
            authenticated_approver = approver_authenticator(review)
            approver_id = str(authenticated_approver.get("id", ""))
            approver_roles = list(authenticated_approver.get("roles", []))
            if not approver_id or not approver_roles:
                raise PermissionError("审批人身份缺少ID或角色")
        except Exception as exc:
            authentication_error = type(exc).__name__
            approver_id = "unauthenticated"
            approver_roles = []
            if review_decision in {"approve", "edit"}:
                review_decision = "reject"

        if review_decision == "edit":
            edited = review.get("edited_parameters", {})
            if isinstance(edited, Mapping):
                request["action"]["parameters"].update(dict(edited))
            request["approval"] = {}
            audit_event = "approval_edited_requires_new_review"
        else:
            approval_status = "approved" if review_decision == "approve" else "rejected"
            request["approval"] = issue_approval(
                request,
                policy["action_digest"],
                approver_id=approver_id,
                approver_roles=approver_roles,
                status=approval_status,
                credential_service=approval_service,
            )
            # 仅用于安全测试：先签发绑定原动作的凭证，再模拟审批后参数被篡改。
            tamper_parameters = review.get("tamper_parameters", {})
            if isinstance(tamper_parameters, Mapping) and tamper_parameters:
                request["action"]["parameters"].update(dict(tamper_parameters))
            audit_event = "approval_resumed"

        history_item = {
            "decision": review_decision,
            "approver_id": approver_id,
            "reason": str(review.get("reason", "")),
            "identity_source": "verified_authenticator" if not authentication_error else "rejected",
        }
        if authentication_error:
            history_item["authentication_error"] = authentication_error
        return {
            "request": request,
            "status": f"review_{review_decision}",
            "review_history": [history_item],
            "audit_events": [{"event": audit_event, **history_item}],
        }

    def policy_recheck(state: ApprovalState) -> dict[str, Any]:
        decision = opa.decide(state["request"])
        return {
            "policy_decision": decision,
            "status": f"opa_recheck_{decision['effect']}",
            "audit_events": [
                {
                    "event": "policy_recheck",
                    "effect": decision["effect"],
                    "codes": _decision_codes(decision),
                }
            ],
        }

    def execute_simulated(state: ApprovalState) -> dict[str, Any]:
        decision = state["policy_decision"]
        request = state["request"]
        if executor is not None:
            outcome = dict(executor(copy.deepcopy(request), copy.deepcopy(decision)))
            receipt = outcome.get("receipt")
            receipts = [dict(receipt)] if isinstance(receipt, Mapping) else []
            return {
                "status": str(outcome.get("status", "blocked")),
                "execution_receipts": receipts,
                "audit_events": [
                    {
                        "event": "external_enforcement_result",
                        "status": str(outcome.get("status", "blocked")),
                        "reason_code": str(outcome.get("reason_code", "")),
                    }
                ],
            }
        approval = request.get("approval", {})
        if isinstance(approval, Mapping) and approval.get("approval_id"):
            try:
                validated = approval_service.validate(
                    approval,
                    str(request.get("task_id", "")),
                    str(decision.get("action_digest", "")),
                )
                approval_service.consume(validated)
            except Exception as exc:
                return {
                    "status": "blocked",
                    "execution_receipts": [],
                    "audit_events": [
                        {
                            "event": "approval_credential_blocked",
                            "status": "blocked",
                            "reason_code": str(
                                getattr(
                                    exc,
                                    "code",
                                    "G010_APPROVAL_CREDENTIAL_INVALID",
                                )
                            ),
                        }
                    ],
                }
        receipt = {
            "receipt_id": f"sim-{uuid.uuid4().hex[:16]}",
            "task_id": request["task_id"],
            "action_digest": decision["action_digest"],
            "tool": request["action"]["tool"],
            "operation": request["action"]["operation"],
            "result": "simulated_only",
        }
        return {
            "status": "executed_simulated",
            "execution_receipts": [receipt],
            "audit_events": [{"event": "tool_execution_simulated", **receipt}],
        }

    def blocked(state: ApprovalState) -> dict[str, Any]:
        decision = state["policy_decision"]
        return {
            "status": "blocked",
            "audit_events": [
                {
                    "event": "execution_blocked",
                    "effect": decision["effect"],
                    "codes": _decision_codes(decision),
                }
            ],
        }

    def route_after_policy(state: ApprovalState) -> str:
        return str(state["policy_decision"]["effect"])

    builder = StateGraph(ApprovalState)
    builder.add_node("initial_policy_check", initial_policy_check)
    builder.add_node("human_review", human_review)
    builder.add_node("policy_recheck", policy_recheck)
    builder.add_node("execute_simulated", execute_simulated)
    builder.add_node("blocked", blocked)

    builder.add_edge(START, "initial_policy_check")
    builder.add_conditional_edges(
        "initial_policy_check",
        route_after_policy,
        {
            "allow": "execute_simulated",
            "require_approval": "human_review",
            "deny": "blocked",
        },
    )
    builder.add_edge("human_review", "policy_recheck")
    builder.add_conditional_edges(
        "policy_recheck",
        route_after_policy,
        {
            "allow": "execute_simulated",
            "require_approval": "human_review",
            "deny": "blocked",
        },
    )
    builder.add_edge("execute_simulated", END)
    builder.add_edge("blocked", END)

    return builder.compile(checkpointer=checkpointer), connection

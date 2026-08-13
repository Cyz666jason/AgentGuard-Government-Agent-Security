"""OPA 决策之后的强制执行点（PEP）与安全工具适配器。"""

from __future__ import annotations

import copy
import secrets
import uuid
from pathlib import Path
from typing import Any, Mapping

from approval.workflow import OpaClient, PROJECT_ROOT
from identity import OidcIdentityError, OidcVerifier
from security_kernel import WasmSecurityKernel

from .audit import AuditLogger
from .adapters import BusinessAdapterError, LocalTestBusinessAdapters
from .tickets import ExecutionTicketStore, TicketError, compute_action_digest
from .signers import TicketSigner
from .ledgers import TicketLedger


DEFAULT_REGISTRY = {
    ("database.query", "query"): {
        "module": "database_query.wat",
        "argument": "limit",
    },
    ("payment.transfer", "transfer"): {
        "module": "payment_transfer.wat",
        "argument": "amount",
    },
}


class EnforcementGateway:
    """所有工具调用的唯一入口：决策、签票、核销、隔离执行、审计。"""

    def __init__(
        self,
        opa_client: Any,
        ticket_store: ExecutionTicketStore,
        kernel: WasmSecurityKernel,
        audit_logger: AuditLogger,
        module_dir: Path | str,
        registry: Mapping[tuple[str, str], Mapping[str, str]] | None = None,
        business_adapters: Any | None = None,
    ) -> None:
        self.opa = opa_client
        self.tickets = ticket_store
        self.kernel = kernel
        self.audit = audit_logger
        self.module_dir = Path(module_dir)
        self.registry = dict(DEFAULT_REGISTRY if registry is None else registry)
        self.business_adapters = business_adapters

    def authorize(self, request: Mapping[str, Any], ttl_seconds: int = 30) -> dict[str, Any]:
        safe_request = copy.deepcopy(dict(request))
        try:
            decision = self.opa.decide(safe_request)
        except Exception as exc:
            return self._block(
                safe_request,
                "G001_OPA_UNAVAILABLE_FAIL_CLOSED",
                f"OPA 不可用，默认拒绝：{type(exc).__name__}",
                policy_effect="error",
                http_status=503,
            )

        effect = str(decision.get("effect", "deny"))
        if effect == "deny":
            return self._block(
                safe_request,
                "G002_POLICY_DENY",
                "OPA 策略拒绝工具调用",
                policy_effect=effect,
                policy_reason_codes=list(decision.get("reason_codes", [])),
            )
        if effect == "require_approval":
            result = {
                "status": "pending_approval",
                "http_status": 202,
                "reason_code": "G003_APPROVAL_PENDING",
                "policy_effect": effect,
                "action_digest": decision.get("action_digest", ""),
                "receipt": None,
            }
            self._audit(safe_request, result)
            return result
        if effect != "allow":
            return self._block(
                safe_request,
                "G002_POLICY_DENY",
                "未知策略结果，默认拒绝",
                policy_effect=effect,
            )

        action = safe_request.get("action", {})
        tool_key = (str(action.get("tool", "")), str(action.get("operation", "")))
        if tool_key not in self.registry:
            return self._block(
                safe_request,
                "G004_UNREGISTERED_ADAPTER",
                "OPA 允许，但网关没有注册对应的安全工具适配器",
                policy_effect=effect,
            )

        current_digest = compute_action_digest(safe_request)
        if not secrets.compare_digest(str(decision.get("action_digest", "")), current_digest):
            return self._block(
                safe_request,
                "G005_POLICY_DIGEST_MISMATCH",
                "OPA 摘要与网关独立计算结果不一致",
                policy_effect=effect,
            )
        try:
            token = self.tickets.issue(
                str(safe_request.get("task_id", "")), current_digest, ttl_seconds=ttl_seconds
            )
        except TicketError as exc:
            return self._block(
                safe_request,
                exc.code,
                str(exc),
                policy_effect="ticket_signing_error",
                http_status=503,
            )
        result = {
            "status": "authorized",
            "http_status": 200,
            "reason_code": "G000_AUTHORIZED",
            "policy_effect": effect,
            "action_digest": current_digest,
            "ticket": token,
            "receipt": None,
        }
        self._audit(safe_request, {**result, "ticket": "***REDACTED***"})
        return result

    def dispatch(self, request: Mapping[str, Any], ticket: str | None) -> dict[str, Any]:
        safe_request = copy.deepcopy(dict(request))
        action = safe_request.get("action", {})
        tool_key = (str(action.get("tool", "")), str(action.get("operation", "")))
        if tool_key not in self.registry:
            return self._block(
                safe_request,
                "G004_UNREGISTERED_ADAPTER",
                "后端没有注册对应工具适配器",
                policy_effect="not_evaluated",
            )
        digest = compute_action_digest(safe_request)
        try:
            ticket_payload = self.tickets.consume(
                ticket, str(safe_request.get("task_id", "")), digest
            )
        except TicketError as exc:
            return self._block(
                safe_request,
                exc.code,
                str(exc),
                policy_effect="ticket_validation",
            )

        specification = self.registry[tool_key]
        parameter_name = specification["argument"]
        raw_argument = action.get("parameters", {}).get(parameter_name, 0)
        try:
            argument = max(-(2**31), min(2**31 - 1, int(raw_argument)))
        except (TypeError, ValueError):
            return self._block(
                safe_request,
                "G008_ADAPTER_ARGUMENT_INVALID",
                "工具适配器参数无法转换为受限整数",
                policy_effect="allowed_then_adapter_blocked",
            )
        sandbox_result = self.kernel.execute(
            self.module_dir / specification["module"], args=(argument,)
        )
        if sandbox_result["status"] != "executed_isolated":
            return self._block(
                safe_request,
                str(sandbox_result["reason_code"]),
                "安全内核阻断工具模块",
                policy_effect="allowed_then_sandbox_blocked",
                sandbox=sandbox_result,
            )
        business_result = None
        if self.business_adapters is not None:
            try:
                business_result = self.business_adapters.execute(safe_request)
            except Exception as exc:
                return self._block(
                    safe_request,
                    "G009_BUSINESS_ADAPTER_FAILED",
                    f"业务适配器执行失败并默认拒绝：{type(exc).__name__}",
                    policy_effect="allowed_then_business_adapter_blocked",
                    sandbox=sandbox_result,
                )
        receipt = {
            "receipt_id": f"iso-{uuid.uuid4().hex[:16]}",
            "task_id": safe_request.get("task_id", ""),
            "action_digest": digest,
            "ticket_jti": ticket_payload["jti"],
            "tool": action.get("tool", ""),
            "operation": action.get("operation", ""),
            "result": (
                "authorized_preproduction_business_operation"
                if business_result is not None
                and business_result.get("adapter") == "authorized_production_https_api"
                else (
                    "local_test_business_operation"
                    if business_result is not None
                    else "wasmtime_isolated_simulation"
                )
            ),
            "sandbox": sandbox_result,
            "business_result": business_result,
        }
        result = {
            "status": "executed_isolated",
            "http_status": 200,
            "reason_code": "G000_EXECUTED",
            "policy_effect": "allow",
            "receipt": receipt,
        }
        self._audit(safe_request, result)
        return result

    def invoke(self, request: Mapping[str, Any]) -> dict[str, Any]:
        authorization = self.authorize(request)
        if authorization["status"] != "authorized":
            return authorization
        return self.dispatch(request, authorization["ticket"])

    def invoke_authenticated(
        self,
        request: Mapping[str, Any],
        authorization_header: str | None,
        verifier: OidcVerifier,
    ) -> dict[str, Any]:
        try:
            authenticated = verifier.authenticate_request(request, authorization_header)
        except OidcIdentityError as exc:
            return self._block(
                request,
                exc.code,
                str(exc),
                policy_effect="identity_rejected",
                http_status=401,
            )
        return self.invoke(authenticated)

    def _block(
        self,
        request: Mapping[str, Any],
        code: str,
        message: str,
        policy_effect: str,
        http_status: int = 403,
        **extra: Any,
    ) -> dict[str, Any]:
        result = {
            "status": "blocked",
            "http_status": http_status,
            "reason_code": code,
            "message": message,
            "policy_effect": policy_effect,
            "receipt": None,
            **extra,
        }
        self._audit(request, result)
        return result

    def _audit(self, request: Mapping[str, Any], result: Mapping[str, Any]) -> None:
        action = request.get("action", {})
        self.audit.write(
            {
                "event": "enforcement_decision",
                "request_id": request.get("request_id", ""),
                "task_id": request.get("task_id", ""),
                "subject_id": request.get("subject", {}).get("id", ""),
                "tool": action.get("tool", ""),
                "operation": action.get("operation", ""),
                "parameters": action.get("parameters", {}),
                "result": dict(result),
            }
        )


def build_gateway(
    state_dir: Path | str,
    project_root: Path | str = PROJECT_ROOT,
    secret: bytes | None = None,
    opa_client: Any | None = None,
    registry: Mapping[tuple[str, str], Mapping[str, str]] | None = None,
    enable_local_adapters: bool = False,
    signer: TicketSigner | None = None,
    ledger: TicketLedger | None = None,
    business_adapter: Any | None = None,
) -> EnforcementGateway:
    root = Path(project_root)
    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    return EnforcementGateway(
        opa_client=opa_client or OpaClient(root),
        ticket_store=ExecutionTicketStore(
            state / "execution_tickets.sqlite",
            secret=(secret or secrets.token_bytes(32)) if signer is None else None,
            signer=signer,
            ledger=ledger,
        ),
        kernel=WasmSecurityKernel(),
        audit_logger=AuditLogger(state / "enforcement_audit.jsonl"),
        module_dir=root / "security_kernel" / "modules",
        registry=registry,
        business_adapters=(
            business_adapter
            if business_adapter is not None
            else (LocalTestBusinessAdapters(state) if enable_local_adapters else None)
        ),
    )

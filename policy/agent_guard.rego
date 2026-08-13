package agent.guard

import rego.v1

# 面向政企智能体工具调用的策略决策点（PDP）。
# 网关必须根据 effect 强制执行：allow=放行，require_approval=暂停，deny=阻断。

policy_version := "0.1.0"

subject := object.get(input, "subject", {})
action := object.get(input, "action", {})
context := object.get(input, "context", {})
environment := object.get(input, "environment", {})
approval := object.get(input, "approval", {})

request_id := object.get(input, "request_id", "")
task_id := object.get(input, "task_id", "")
request_time := object.get(input, "timestamp", "")
subject_id := object.get(subject, "id", "")
roles := object.get(subject, "roles", [])
clearance := object.get(subject, "clearance", 0)
tool_name := object.get(action, "tool", "")
operation := object.get(action, "operation", "")
resource := object.get(action, "resource", "")
parameters := object.get(action, "parameters", {})
risk_level := object.get(action, "risk_level", "critical")
data_level := object.get(action, "data_level", "secret")
destination_zone := object.get(context, "destination_zone", "unknown")
enforcement_point := object.get(context, "enforcement_point", "unknown")
business_hours := object.get(context, "business_hours", false)
repeat_count := object.get(context, "repeat_count", 0)

action_binding := {
	"task_id": task_id,
	"action": action,
}

action_digest := crypto.sha256(json.marshal(action_binding))

missing_fields contains "request_id" if request_id == ""
missing_fields contains "task_id" if task_id == ""
missing_fields contains "timestamp" if request_time == ""
missing_fields contains "subject.id" if subject_id == ""
missing_fields contains "subject.roles" if count(roles) == 0
missing_fields contains "action.tool" if tool_name == ""
missing_fields contains "action.operation" if operation == ""
missing_fields contains "action.resource" if resource == ""
missing_fields contains "action.risk_level" if object.get(action, "risk_level", "") == ""
missing_fields contains "action.data_level" if object.get(action, "data_level", "") == ""

missing_field_list := sort([field | some field in missing_fields])

tool_config := object.get(data.agent_guard.tools, tool_name, null)

trusted_tool if {
	is_object(tool_config)
	object.get(tool_config, "enabled", false)
}

has_role(wanted) if wanted in roles

role_permitted if {
	some role in roles
	some permission in data.agent_guard.permissions
	permission.role == role
	permission.tool == tool_name
	operation in permission.operations
}

data_level_value := object.get(data.agent_guard.data_levels, data_level, 99)
confidential_value := data.agent_guard.data_levels.confidential

protected_resource if {
	some prefix in data.agent_guard.protected_resource_prefixes
	startswith(lower(resource), lower(prefix))
}

dangerous_command if {
	tool_name == "shell.execute"
	command := object.get(parameters, "command", "")
	some pattern in data.agent_guard.dangerous_command_patterns
	regex.match(pattern, command)
}

sandbox_required if {
	tool_name in data.agent_guard.sandbox_required_tools
	risk_level in {"high", "critical"}
}

sandbox_approved if {
	sandbox := object.get(environment, "sandbox", {})
	object.get(sandbox, "enabled", false)
	object.get(sandbox, "profile", "") in data.agent_guard.approved_sandbox_profiles
}

network_tool if tool_name in data.agent_guard.network_tools

allowed_external_host if {
	host := lower(object.get(parameters, "host", ""))
	host in data.agent_guard.allowed_external_hosts
}

deny_reasons contains {
	"code": "D001_MISSING_FIELD",
	"message": sprintf("缺少必填字段：%s", [concat(", ", missing_field_list)]),
} if count(missing_fields) > 0

deny_reasons contains {
	"code": "D002_UNTRUSTED_TOOL",
	"message": sprintf("工具 %s 未进入可信工具清单或已被停用", [tool_name]),
} if not trusted_tool

deny_reasons contains {
	"code": "D003_ROLE_FORBIDDEN",
	"message": sprintf("当前角色无权执行 %s/%s", [tool_name, operation]),
} if {
	count(missing_fields) == 0
	trusted_tool
	not role_permitted
}

deny_reasons contains {
	"code": "D004_CLEARANCE_INSUFFICIENT",
	"message": sprintf("主体密级 %v 低于数据等级 %v", [clearance, data_level_value]),
} if clearance < data_level_value

deny_reasons contains {
	"code": "D005_PROTECTED_RESOURCE",
	"message": sprintf("资源 %s 属于受保护范围", [resource]),
} if {
	protected_resource
	not has_role("security_admin")
}

deny_reasons contains {
	"code": "D006_SENSITIVE_EXTERNAL_TRANSFER",
	"message": "机密及以上数据禁止直接发送到外部区域",
} if {
	destination_zone == "external"
	data_level_value >= confidential_value
}

deny_reasons contains {
	"code": "D007_DANGEROUS_COMMAND",
	"message": "命令命中不可批准的破坏性命令特征",
} if dangerous_command

deny_reasons contains {
	"code": "D008_SANDBOX_REQUIRED",
	"message": "高风险代码、浏览器或插件调用必须进入已批准沙箱",
} if {
	sandbox_required
	not sandbox_approved
}

deny_reasons contains {
	"code": "D009_GATEWAY_BYPASS",
	"message": "调用未经过统一网关，无法保证策略结果被强制执行",
} if enforcement_point != "gateway"

deny_reasons contains {
	"code": "D010_ANOMALOUS_REPEAT",
	"message": "同一任务重复调用次数异常，已触发任务链阻断",
} if repeat_count >= data.agent_guard.anomaly_repeat_limit

deny_reasons contains {
	"code": "D011_EGRESS_NOT_ALLOWED",
	"message": "外联目标不在允许清单内",
} if {
	destination_zone == "external"
	network_tool
	not allowed_external_host
}

approval_reasons contains {
	"code": "A001_HIGH_RISK",
	"message": "动作风险等级为高或严重",
} if risk_level in {"high", "critical"}

approval_reasons contains {
	"code": "A002_SENSITIVE_OPERATION",
	"message": sprintf("操作 %s 属于关键操作", [operation]),
} if operation in data.agent_guard.approval_operations

approval_reasons contains {
	"code": "A003_AMOUNT_THRESHOLD",
	"message": sprintf("金额超过免审批阈值 %v 元", [data.agent_guard.approval_amount_threshold]),
} if object.get(parameters, "amount", 0) > data.agent_guard.approval_amount_threshold

approval_reasons contains {
	"code": "A004_SENSITIVE_DATA",
	"message": "动作涉及机密及以上数据",
} if data_level_value >= confidential_value

approval_reasons contains {
	"code": "A005_OUT_OF_HOURS",
	"message": "非工作时段的中高风险操作需要人工确认",
} if {
	not business_hours
	risk_level != "low"
}

approval_reasons contains {
	"code": "A006_BULK_OPERATION",
	"message": "批量处理规模超过免审批上限",
} if object.get(parameters, "item_count", 0) > data.agent_guard.bulk_item_limit

approval_needed := count(approval_reasons) > 0

approval_submitted := object.get(approval, "approval_id", "") != ""

authorized_approver if {
	some role in object.get(approval, "approver_roles", [])
	role in data.agent_guard.approver_roles
}

approval_not_expired if {
	expires_at := object.get(approval, "expires_at", "")
	expires_at != ""
	request_time != ""
	time.parse_rfc3339_ns(expires_at) >= time.parse_rfc3339_ns(request_time)
}

approval_issues contains {
	"code": "D101_APPROVAL_STATUS",
	"message": "审批状态不是 approved",
} if {
	approval_submitted
	object.get(approval, "status", "") != "approved"
}

approval_issues contains {
	"code": "D102_APPROVAL_TASK_MISMATCH",
	"message": "审批凭证绑定的任务与当前任务不一致",
} if {
	approval_submitted
	object.get(approval, "task_id", "") != task_id
}

approval_issues contains {
	"code": "D103_APPROVAL_ACTION_TAMPERED",
	"message": "审批后的工具、资源或参数发生变化",
} if {
	approval_submitted
	object.get(approval, "action_digest", "") != action_digest
}

approval_issues contains {
	"code": "D104_APPROVAL_EXPIRED",
	"message": "审批凭证已过期或时间格式无效",
} if {
	approval_submitted
	not approval_not_expired
}

approval_issues contains {
	"code": "D105_SELF_APPROVAL",
	"message": "发起人不能审批自己的高风险操作",
} if {
	approval_submitted
	object.get(approval, "approver_id", "") == subject_id
}

approval_issues contains {
	"code": "D106_APPROVER_FORBIDDEN",
	"message": "审批人不具备规定的审批角色",
} if {
	approval_submitted
	not authorized_approver
}

approval_issues contains {
	"code": "D107_APPROVAL_REUSED",
	"message": "审批凭证不是一次性凭证或已经使用",
} if {
	approval_submitted
	max_uses := object.get(approval, "max_uses", 0)
	max_uses != 1
}

approval_issues contains {
	"code": "D107_APPROVAL_REUSED",
	"message": "审批凭证不是一次性凭证或已经使用",
} if {
	approval_submitted
	max_uses := object.get(approval, "max_uses", 0)
	use_count := object.get(approval, "use_count", 0)
	use_count >= max_uses
}

hard_deny if count(deny_reasons) > 0

invalid_approval if {
	approval_needed
	approval_submitted
	count(approval_issues) > 0
}

approval_valid if {
	approval_needed
	approval_submitted
	count(approval_issues) == 0
}

effect := "deny" if hard_deny

else := "deny" if invalid_approval

else := "allow" if approval_valid

else := "require_approval" if approval_needed

else := "allow"

base_risk_score := object.get(data.agent_guard.risk_scores, risk_level, 100)
external_points := 10 if destination_zone == "external"

else := 0

off_hours_points := 10 if not business_hours

else := 0

repeat_points := min([20, repeat_count * 5])
bulk_points := 15 if object.get(parameters, "item_count", 0) > data.agent_guard.bulk_item_limit

else := 0

risk_score := min([100, (((base_risk_score + external_points) + off_hours_points) + repeat_points) + bulk_points])

selected_reason_items := [item | some item in deny_reasons] if hard_deny

else := [item | some item in approval_issues] if invalid_approval

else := [{"code": "L002_VALID_APPROVAL", "message": "审批有效，允许一次性执行"}] if approval_valid

else := [item | some item in approval_reasons] if approval_needed

else := [{"code": "L001_LOW_RISK_ALLOWED", "message": "低风险动作满足最小权限规则"}]

reason_codes := sort([item.code | some item in selected_reason_items])
reasons := sort([item.message | some item in selected_reason_items])

control_set contains "gateway_enforcement"
control_set contains "least_privilege"
control_set contains "parameter_schema"
control_set contains "decision_log"
control_set contains "decision_log_redaction"
control_set contains "human_approval" if approval_needed
control_set contains "action_digest_binding" if approval_needed
control_set contains "one_time_approval" if approval_needed
control_set contains "sandbox" if sandbox_required
control_set contains "egress_allowlist" if destination_zone == "external"

required_controls := sort([control | some control in control_set])

decision := {
	"effect": effect,
	"allow": effect == "allow",
	"approval_required": approval_needed,
	"risk_score": risk_score,
	"reason_codes": reason_codes,
	"reasons": reasons,
	"required_controls": required_controls,
	"action_digest": action_digest,
	"policy_version": policy_version,
	"audit": {
		"request_id": request_id,
		"task_id": task_id,
		"subject_id": subject_id,
		"tool": tool_name,
		"operation": operation,
		"resource": resource,
		"timestamp": request_time,
		"effect": effect,
		"risk_score": risk_score,
	},
}

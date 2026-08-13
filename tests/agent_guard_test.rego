package agent.guard_test

import data.agent.guard as guard
import data.system.log as audit_mask
import rego.v1

base_input := {
	"request_id": "req-test-001",
	"task_id": "task-test-001",
	"timestamp": "2026-08-04T10:00:00Z",
	"subject": {
		"id": "user-001",
		"type": "user",
		"department": "综合办公室",
		"roles": ["office_user"],
		"clearance": 1,
		"mfa": true,
	},
	"action": {
		"tool": "database.query",
		"operation": "query",
		"resource": "db://public/notices",
		"parameters": {"limit": 20, "item_count": 20},
		"risk_level": "low",
		"data_level": "internal",
	},
	"context": {
		"source": "mcp",
		"destination_zone": "internal",
		"enforcement_point": "gateway",
		"business_hours": true,
		"repeat_count": 0,
	},
	"environment": {
		"sandbox": {"enabled": false, "profile": ""},
	},
	"approval": {},
}

payment_input := object.union(base_input, {
	"request_id": "req-payment-001",
	"task_id": "task-payment-001",
	"subject": {
		"id": "finance-001",
		"department": "财务部",
		"roles": ["finance_operator"],
		"clearance": 2,
	},
	"action": {
		"tool": "payment.transfer",
		"operation": "transfer",
		"resource": "erp://payments/supplier-A",
		"parameters": {"amount": 5000, "currency": "CNY"},
		"risk_level": "high",
		"data_level": "internal",
	},
})

shell_input := object.union(base_input, {
	"request_id": "req-shell-001",
	"task_id": "task-shell-001",
	"subject": {
		"id": "ops-001",
		"department": "运维部",
		"roles": ["ops_engineer"],
		"clearance": 3,
	},
	"action": {
		"tool": "shell.execute",
		"operation": "execute",
		"resource": "host://prod-app-01",
		"parameters": {"command": "Get-Service"},
		"risk_level": "high",
		"data_level": "internal",
	},
	"environment": {
		"sandbox": {"enabled": true, "profile": "gvisor-restricted"},
	},
})

approval_for(x) := {
	"approval_id": "approval-test-001",
	"status": "approved",
	"approver_id": "approver-001",
	"approver_roles": ["business_approver"],
	"task_id": x.task_id,
	"action_digest": crypto.sha256(json.marshal({"task_id": x.task_id, "action": x.action})),
	"expires_at": "2026-08-04T10:30:00Z",
	"max_uses": 1,
	"use_count": 0,
}

approved(x) := object.union(x, {"approval": approval_for(x)})

test_low_risk_query_is_allowed if {
	guard.decision.effect == "allow" with input as base_input
}

test_low_risk_query_does_not_need_approval if {
	not guard.decision.approval_required with input as base_input
}

test_empty_input_detects_all_required_fields if {
	fields := guard.missing_fields with input as {}
	count(fields) == 10
}

test_high_risk_payment_pauses_for_approval if {
	guard.decision.effect == "require_approval" with input as payment_input
}

test_valid_bound_approval_allows_once if {
	guard.decision.effect == "allow" with input as approved(payment_input)
}

test_untrusted_tool_is_denied if {
	x := object.union(base_input, {"action": {"tool": "unknown.tool"}})
	guard.decision.effect == "deny" with input as x
}

test_disabled_plugin_is_denied if {
	x := object.union(base_input, {"action": {"tool": "plugin.run", "operation": "execute"}})
	guard.decision.effect == "deny" with input as x
}

test_role_violation_is_denied if {
	x := object.union(base_input, {"action": payment_input.action})
	guard.decision.effect == "deny" with input as x
}

test_clearance_violation_is_denied if {
	x := object.union(base_input, {"action": {"data_level": "secret"}})
	guard.decision.effect == "deny" with input as x
}

test_protected_resource_is_denied if {
	x := object.union(base_input, {"action": {"tool": "file.read", "operation": "read", "resource": "/etc/shadow"}})
	guard.decision.effect == "deny" with input as x
}

test_sensitive_external_transfer_is_denied if {
	x := object.union(base_input, {
		"subject": {"clearance": 3},
		"action": {
			"tool": "email.send",
			"operation": "send_external",
			"resource": "mailto:partner@example.com",
			"parameters": {"host": "mail.partner.example"},
			"risk_level": "high",
			"data_level": "secret",
		},
		"context": {"destination_zone": "external"},
	})
	guard.decision.effect == "deny" with input as x
}

test_dangerous_command_cannot_be_approved if {
	dangerous := object.union(shell_input, {"action": {"parameters": {"command": "rm -rf /"}}})
	x := approved(dangerous)
	guard.decision.effect == "deny" with input as x
	"D007_DANGEROUS_COMMAND" in guard.decision.reason_codes with input as x
}

test_high_risk_shell_without_sandbox_is_denied if {
	x := object.union(shell_input, {"environment": {"sandbox": {"enabled": false, "profile": ""}}})
	guard.decision.effect == "deny" with input as x
}

test_gateway_bypass_is_denied if {
	x := object.union(base_input, {"context": {"enforcement_point": "direct"}})
	guard.decision.effect == "deny" with input as x
}

test_repeated_task_chain_is_denied if {
	x := object.union(base_input, {"context": {"repeat_count": 5}})
	guard.decision.effect == "deny" with input as x
}

test_unknown_external_host_is_denied if {
	x := object.union(base_input, {
		"subject": {"id": "ops-001", "roles": ["ops_engineer"], "clearance": 2},
		"action": {
			"tool": "api.call",
			"operation": "invoke",
			"resource": "https://evil.example/api",
			"parameters": {"host": "evil.example"},
			"risk_level": "medium",
			"data_level": "internal",
		},
		"context": {"destination_zone": "external"},
	})
	guard.decision.effect == "deny" with input as x
}

test_changed_amount_after_approval_is_denied if {
	approved_input := approved(payment_input)
	tampered := object.union(approved_input, {"action": {"parameters": {"amount": 50000, "currency": "CNY"}}})
	guard.decision.effect == "deny" with input as tampered
	"D103_APPROVAL_ACTION_TAMPERED" in guard.decision.reason_codes with input as tampered
}

test_approval_cannot_cross_task if {
	x := object.union(approved(payment_input), {"task_id": "task-payment-OTHER"})
	guard.decision.effect == "deny" with input as x
}

test_expired_approval_is_denied if {
	x := object.union(approved(payment_input), {"approval": {"expires_at": "2026-08-04T09:59:59Z"}})
	guard.decision.effect == "deny" with input as x
}

test_self_approval_is_denied if {
	x := object.union(approved(payment_input), {"approval": {"approver_id": "finance-001"}})
	guard.decision.effect == "deny" with input as x
}

test_unauthorized_approver_is_denied if {
	x := object.union(approved(payment_input), {"approval": {"approver_roles": ["office_user"]}})
	guard.decision.effect == "deny" with input as x
}

test_reused_approval_is_denied if {
	x := object.union(approved(payment_input), {"approval": {"use_count": 1}})
	guard.decision.effect == "deny" with input as x
}

test_rejected_approval_is_denied if {
	x := object.union(approved(payment_input), {"approval": {"status": "rejected"}})
	guard.decision.effect == "deny" with input as x
}

test_audit_record_contains_core_fields if {
	result := guard.decision with input as base_input
	result.audit.request_id == base_input.request_id
	result.audit.task_id == base_input.task_id
	result.audit.tool == base_input.action.tool
	result.audit.effect == "allow"
}

test_high_risk_output_requests_defence_in_depth if {
	result := guard.decision with input as payment_input
	"human_approval" in result.required_controls
	"action_digest_binding" in result.required_controls
	"one_time_approval" in result.required_controls
	"decision_log" in result.required_controls
}

test_action_digest_changes_when_parameters_change if {
	changed := object.union(payment_input, {"action": {"parameters": {"amount": 9999}}})
	first := guard.decision.action_digest with input as payment_input
	second := guard.decision.action_digest with input as changed
	first != second
}

test_decision_log_masks_password if {
	event := {"input": {"action": {"parameters": {"password": "secret"}}}}
	"/input/action/parameters/password" in audit_mask.mask with input as event
}

test_decision_log_masks_token if {
	event := {"input": {"action": {"parameters": {"token": "secret"}}}}
	"/input/action/parameters/token" in audit_mask.mask with input as event
}

test_decision_log_masks_api_key if {
	event := {"input": {"action": {"parameters": {"api_key": "secret"}}}}
	"/input/action/parameters/api_key" in audit_mask.mask with input as event
}

test_decision_log_masks_approval_digest if {
	event := {"input": {"approval": {"action_digest": "abc"}}}
	"/input/approval/action_digest" in audit_mask.mask with input as event
}

dataset_failures contains sprintf("%s:effect", [case.case_id]) if {
	some case in data.agent_guard_test_cases
	result := guard.decision with input as case.input
	result.effect != case.expected_effect
}

dataset_failures contains sprintf("%s:reason", [case.case_id]) if {
	some case in data.agent_guard_test_cases
	result := guard.decision with input as case.input
	not case.expected_reason_code in result.reason_codes
}

test_generated_dataset_all_cases if {
	count(data.agent_guard_test_cases) == 55
	count(dataset_failures) == 0
}

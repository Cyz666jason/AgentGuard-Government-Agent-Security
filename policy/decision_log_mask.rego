package system.log

import rego.v1

# OPA 决策日志脱敏：只输出审计所需字段，隐藏凭据、口令和审批摘要。

event_input := object.get(input, "input", {})
event_action := object.get(event_input, "action", {})
event_parameters := object.get(event_action, "parameters", {})
event_approval := object.get(event_input, "approval", {})

mask contains "/input/action/parameters/password" if {
	object.get(event_parameters, "password", "") != ""
}

mask contains "/input/action/parameters/token" if {
	object.get(event_parameters, "token", "") != ""
}

mask contains "/input/action/parameters/api_key" if {
	object.get(event_parameters, "api_key", "") != ""
}

mask contains "/input/approval/action_digest" if {
	object.get(event_approval, "action_digest", "") != ""
}

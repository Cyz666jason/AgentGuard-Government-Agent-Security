package envoy.authz

import rego.v1

default allow := false

http := input.attributes.request.http

allow if {
	http.method == "POST"
	startswith(http.path, "/internal/tool-adapter/")
	object.get(http.headers, "x-agentguard-ticket", "") != ""
}

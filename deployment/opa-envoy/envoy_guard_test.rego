package envoy.authz_test

import data.envoy.authz
import rego.v1

valid_input := {
	"attributes": {
		"request": {
			"http": {
				"method": "POST",
				"path": "/internal/tool-adapter/database.query",
				"headers": {"x-agentguard-ticket": "signed-ticket"},
			},
		},
	},
}

test_allows_internal_post_with_ticket if {
	authz.allow with input as valid_input
}

test_denies_missing_ticket if {
	request := {
		"attributes": {
			"request": {
				"http": {
					"method": "POST",
					"path": "/internal/tool-adapter/database.query",
					"headers": {},
				},
			},
		},
	}
	not authz.allow with input as request
}

test_denies_wrong_path if {
	request := object.union(valid_input, {
		"attributes": {"request": {"http": {
			"method": "POST",
			"path": "/public/bypass",
			"headers": {"x-agentguard-ticket": "signed-ticket"},
		}}},
	})
	not authz.allow with input as request
}

test_denies_get_method if {
	request := object.union(valid_input, {
		"attributes": {"request": {"http": {
			"method": "GET",
			"path": "/internal/tool-adapter/database.query",
			"headers": {"x-agentguard-ticket": "signed-ticket"},
		}}},
	})
	not authz.allow with input as request
}

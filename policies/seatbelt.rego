# Agent Seatbelt policy pack v1 (OPA/Rego, OPA >= 1.0 syntax).
#
# One deterministic decision function for every action class in the
# phase-1 coverage manifest. The Policy Decision Point queries
# data.seatbelt.decision with a structured description of the action;
# the result is {"decision": "allow" | "deny" | "require-approval",
# "reason": <stable machine-readable reason code>}.
#
# Default posture is deny: any action class or shape the pack does not
# explicitly allow is denied with reason "no_matching_allow_rule".
# No LLM is consulted anywhere in this path.
package seatbelt

cfg := data.seatbelt.config

# ---------------------------------------------------------------- tools

decision := {"decision": "require-approval", "reason": "approval_required"} if {
	input.class == "tool"
	input.tool == cfg.tools.approval_required[_]
}

approval_listed if {
	some t in cfg.tools.approval_required
	t == input.tool
}

tool_allowlisted if {
	some t in cfg.tools.allowlist
	t == input.tool
}

decision := {"decision": "deny", "reason": "tool_not_allowlisted"} if {
	input.class == "tool"
	not approval_listed
	not tool_allowlisted
}

decision := {"decision": "deny", "reason": "shell_command_denied"} if {
	input.class == "tool"
	input.tool == "shell.run"
	not shell_command_allowed
}

decision := {"decision": "deny", "reason": "mcp_tool_not_allowlisted"} if {
	input.class == "tool"
	input.tool == "mcp.call"
	not mcp_tool_allowed
}

decision := {"decision": "allow", "reason": "tool_allowlisted"} if {
	input.class == "tool"
	tool_allowlisted
	tool_detail_allowed
}

shell_command_allowed if {
	some prefix in cfg.tools.shell_command_prefixes
	startswith(input.command, prefix)
	not shell_command_denied
}

shell_command_denied if {
	some bad in cfg.tools.shell_deny_substrings
	contains(input.command, bad)
}

mcp_tool_allowed if {
	some t in cfg.tools.mcp_allowlist[input.mcp_server]
	t == input.mcp_tool
}

tool_detail_allowed if {
	input.tool != "shell.run"
	input.tool != "mcp.call"
}

tool_detail_allowed if {
	input.tool == "shell.run"
	shell_command_allowed
}

tool_detail_allowed if {
	input.tool == "mcp.call"
	mcp_tool_allowed
}

# ---------------------------------------------------------------- files

decision := {"decision": "deny", "reason": "file_path_denied"} if {
	input.class == "file"
	file_path_denied
}

decision := {"decision": "allow", "reason": "file_within_scope"} if {
	input.class == "file"
	not file_path_denied
	startswith(input.path, input.workspace)
}

decision := {"decision": "deny", "reason": "file_outside_scope"} if {
	input.class == "file"
	not file_path_denied
	not startswith(input.path, input.workspace)
}

file_path_denied if {
	some bad in cfg.files.deny_substrings
	contains(input.path, bad)
}

file_path_denied if {
	some suf in cfg.files.deny_suffixes
	endswith(input.path, suf)
}

# --------------------------------------------------------------- egress

egress_host_allowlisted if {
	some h in cfg.egress.hosts
	h == input.host
}

egress_method_allowlisted if {
	some m in cfg.egress.methods
	m == input.method
}

decision := {"decision": "deny", "reason": "egress_host_not_allowlisted"} if {
	input.class == "egress"
	not egress_host_allowlisted
}

decision := {"decision": "deny", "reason": "egress_method_not_allowlisted"} if {
	input.class == "egress"
	egress_host_allowlisted
	not egress_method_allowlisted
}

decision := {"decision": "allow", "reason": "egress_allowlisted"} if {
	input.class == "egress"
	egress_host_allowlisted
	egress_method_allowlisted
}

# ------------------------------------------------------------------ dns

decision := {"decision": "allow", "reason": "dns_name_allowlisted"} if {
	input.class == "dns"
	some suf in cfg.dns.suffixes
	endswith(input.qname, suf)
}

decision := {"decision": "deny", "reason": "dns_name_not_allowlisted"} if {
	input.class == "dns"
	not dns_allowed
}

dns_allowed if {
	some suf in cfg.dns.suffixes
	endswith(input.qname, suf)
}

# --------------------------------------------------------------- budget

decision := {"decision": "allow", "reason": "budget_within_cap"} if {
	input.class == "budget"
	input.used_cost + input.add_cost <= input.cap_cost
	input.used_tokens + input.add_tokens <= input.cap_tokens
}

decision := {"decision": "deny", "reason": "budget_cap_exceeded"} if {
	input.class == "budget"
	input.used_cost + input.add_cost > input.cap_cost
}

decision := {"decision": "deny", "reason": "budget_cap_exceeded"} if {
	input.class == "budget"
	input.used_tokens + input.add_tokens > input.cap_tokens
}

# ----------------------------------------------------------- credential

decision := {"decision": "deny", "reason": "credential_raw_disclosure_forbidden"} if {
	input.class == "credential"
	input.raw_read == true
}

decision := {"decision": "allow", "reason": "credential_grant_covers_action"} if {
	input.class == "credential"
	input.raw_read == false
	credential_grant_matches
}

decision := {"decision": "deny", "reason": "credential_no_grant_for_target"} if {
	input.class == "credential"
	input.raw_read == false
	not credential_grant_matches
}

credential_grant_matches if {
	some g in cfg.credentials.grants
	g.service == input.service
	input.host == g.hosts[_]
	input.method == g.methods[_]
	startswith(input.path, g.path_prefix)
}

# -------------------------------------------------------------- default

default decision := {"decision": "deny", "reason": "no_matching_allow_rule"}

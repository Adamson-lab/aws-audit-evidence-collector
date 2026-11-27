package audit.window

import rego.v1

default allow := false
default reason := "denied: evidence collection outside UTC window without active audit override"

# Emergency audit override requires an active audit ticket (>= 6 chars) and auditor role
audit_override_valid if {
	input.emergency_audit.enabled == true
	count(input.emergency_audit.audit_id) >= 6
	count(input.emergency_audit.justification) >= 10
	input.role in {"compliance-auditor", "security-lead"}
}

allow if {
	audit_override_valid
	input.role in {"compliance-auditor", "security-lead"}
}

allow if {
	not audit_override_valid
	input.role in {"compliance-auditor", "security-lead", "automated-scheduler"}
	input.utc_hour >= 4
	input.utc_hour <= 23
}

reason := "allowed via active emergency audit override" if {
	allow
	audit_override_valid
}

reason := "allowed within scheduled UTC collection window" if {
	allow
	not audit_override_valid
}

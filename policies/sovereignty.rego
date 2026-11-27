package audit.sovereignty

import rego.v1

default allow := false
default reason := "denied: bucket region violates data residency policy"

allowed_regions := {
	"fedramp": {"us-east-1", "us-west-2"},
	"gdpr": {"eu-central-1", "eu-west-1"},
	"commercial": {"us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"},
}

allow if {
	input.region in allowed_regions[input.framework]
}

reason := "allowed: target region complies with framework residency" if {
	allow
}

package control.authz

import rego.v1

# Rev. 4 §5: Action->Permission-Mapping liegt IN der Policy.
# Gate liefert actor/run/resource_version aus vertrauenswürdigen Quellen.
default allow := false

required_permission := "records.read" if {
	input.action == "demo_read"
}

required_permission := "records.write" if {
	input.action == "demo_update_record"
}

allow if {
	input.action == "demo_read"
	input.run.status == "active"
	required_permission in input.actor.permissions
	input.resource_version == input.expected_resource_version
	not input.expired
}

allow if {
	input.action == "demo_update_record"
	input.run.status == "active"
	required_permission in input.actor.permissions
	input.resource_version == input.expected_resource_version
	not input.expired
}

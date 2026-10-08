package control.invariants

import rego.v1

# Rev. 4: Gate wertet allow UND violation aus; jede violation => Deny.
violation contains "stale-state" if {
	input.expected_resource_version != input.resource_version
}

violation contains "manual-override-too-broad" if {
	input.manual_approval == true
	input.approval_scope != input.action_scope
}

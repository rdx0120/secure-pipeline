# Conftest/OPA policy for the artifact-bucket module.
#
# Runs against `terraform show -json tfplan` output, not the HCL: the plan is
# what will actually exist. HCL can compute a value at apply time that the
# source text never shows.
package main

import rego.v1

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

resources(kind) := [r |
	some r in input.resource_changes
	r.type == kind
	r.change.actions[_] in ["create", "update"]
]

# ---------------------------------------------------------------------------
# The demo that matters: an over-broad OIDC trust condition.
#
# `repo:org/*` in the `sub` claim lets ANY repository in the organisation
# assume the role -- including a fork, or a repo created by anyone with write
# access to the org. This is commonly shipped, passes every syntax check, and
# is invisible in the console unless you read the trust policy JSON.
# ---------------------------------------------------------------------------

deny contains msg if {
	some r in resources("aws_iam_role")
	policy := json.unmarshal(r.change.after.assume_role_policy)
	some stmt in policy.Statement
	some key, values in stmt.Condition.StringEquals
	endswith(key, ":sub")
	some v in values
	contains(v, "*")
	msg := sprintf(
		"OIDC trust policy on %s allows a wildcard subject %q. Any repository matching this pattern can assume the role.",
		[r.address, v],
	)
}

# A `sub` condition with no repo pin at all is worse than a wildcard.
deny contains msg if {
	some r in resources("aws_iam_role")
	policy := json.unmarshal(r.change.after.assume_role_policy)
	some stmt in policy.Statement
	stmt.Action[_] == "sts:AssumeRoleWithWebIdentity"
	not sub_condition_present(stmt)
	msg := sprintf(
		"OIDC trust policy on %s has no `:sub` condition. Every GitHub Actions run on GitHub can assume this role.",
		[r.address],
	)
}

sub_condition_present(stmt) if {
	some key, _ in stmt.Condition.StringEquals
	endswith(key, ":sub")
}

sub_condition_present(stmt) if {
	some key, _ in stmt.Condition.StringLike
	endswith(key, ":sub")
}

# ---------------------------------------------------------------------------
# bucket hygiene -- these hold SARIF and normalized findings
# ---------------------------------------------------------------------------

deny contains msg if {
	some r in resources("aws_s3_bucket")
	not public_access_blocked(r.change.after.bucket)
	msg := sprintf(
		"S3 bucket %q has no aws_s3_bucket_public_access_block. It stores scanner output.",
		[r.change.after.bucket],
	)
}

public_access_blocked(name) if {
	some b in resources("aws_s3_bucket_public_access_block")
	b.change.after.block_public_acls == true
	b.change.after.block_public_policy == true
	b.change.after.restrict_public_buckets == true
}

deny contains msg if {
	some r in resources("aws_s3_bucket_public_access_block")
	r.change.after.block_public_acls == false
	msg := sprintf("%s sets block_public_acls = false.", [r.address])
}

deny contains msg if {
	some r in resources("aws_s3_bucket")
	not encrypted(r.change.after.bucket)
	msg := sprintf("S3 bucket %q has no server-side encryption configuration.", [r.change.after.bucket])
}

encrypted(name) if {
	some e in resources("aws_s3_bucket_server_side_encryption_configuration")
	e.change.after.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm != ""
}

deny contains msg if {
	some r in resources("aws_s3_bucket_acl")
	r.change.after.acl in ["public-read", "public-read-write"]
	msg := sprintf("S3 bucket ACL %q is public.", [r.change.after.acl])
}

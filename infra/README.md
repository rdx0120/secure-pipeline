# infra

S3 artifact bucket + GitHub OIDC role for `secure-pipeline`, gated by a
Conftest/OPA policy.

## Why the OIDC `sub` condition is the interesting control

The bucket rules (block public access, encrypt, no public ACL) are table
stakes. The one worth demonstrating is the trust policy on the CI role:

```hcl
condition {
  test     = "StringEquals"
  variable = "token.actions.githubusercontent.com:sub"
  values   = ["repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"]
}
```

Written as `repo:rdx0120/*`, **any repository in the organisation can assume
this role** — including a fork, or a repo created later by anyone with write
access to the org. It passes `terraform validate`, deploys cleanly, and is
invisible in the console unless you open the trust policy JSON. Omitting the
`sub` condition entirely is worse still: every GitHub Actions run *on GitHub*
can assume it.

Both cases are the same failure class as the rest of this repo: **a control
that is present, syntactically valid, and verifies nothing.**

## Running the policy

The policy runs against `terraform show -json tfplan`, not the HCL. The plan is
what will actually exist; HCL can compute a value at apply time that the source
text never shows.

```
conftest test --policy policy/ tfplan.json
```

Fixtures in `tests/` exercise it without needing an AWS account:

| Fixture | Result |
|---|---|
| `plan-compliant.json` | 6 tests, 6 passed — exit 0 |
| `plan-violating.json` | wildcard `sub`, public ACL, no encryption, no PAB — 5 failures, exit 1 |
| `plan-no-sub.json` | no `:sub` condition at all — 1 failure, exit 1 |

## Status: written and policy-verified, NOT applied

`terraform apply` has **not** been run. This environment has no AWS credentials
(`AWS_ACCESS_KEY_ID` is a proxy placeholder, and `~/.aws/config` carries no
profile), and neither `terraform` nor `tofu` can be installed here — OpenTofu's
`go.mod` carries replace directives that make `go install` refuse it, and
`releases.hashicorp.com` is outside the network policy.

So this module is **verified against a policy, not operated**. Applying it
requires running from a machine with credentials:

```
tofu init
tofu plan -out tfplan
tofu show -json tfplan > tfplan.json
conftest test --policy policy/ tfplan.json     # gate BEFORE apply
tofu apply tfplan
```

Note the ordering: the policy gate runs against the plan, before apply. A
policy that runs after apply is an audit, not a control.

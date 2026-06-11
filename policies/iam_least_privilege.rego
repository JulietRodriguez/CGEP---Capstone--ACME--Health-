# METADATA
# title: IAM Least Privilege — No Wildcard Service Actions
# description: >
#   IAM role policies must not grant wildcard service actions such as
#   dynamodb:* or s3:*. Wildcard actions violate the principle of least
#   privilege and expand the blast radius of a compromised credential.
#   Closes GAP-07.
# custom:
#   framework: cmmc-l2
#   controls:
#     - AC.L2-3.1.5
#     - AC.L2-3.1.3
#   nist_ref: "NIST SP 800-171 Rev. 3 — 3.1.3, 3.1.5"
#   severity: HIGH
#   gap: GAP-07
#   remediation: >
#     Replace dynamodb:* and s3:* with the minimum actions the workload
#     actually uses (e.g., dynamodb:PutItem, s3:PutObject).

package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Action as a plain string (e.g. "dynamodb:*")
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] in {"create", "update"}
    policy := json.unmarshal(resource.change.after.policy)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    is_string(stmt.Action)
    endswith(stmt.Action, ":*")
    msg := sprintf(
        "[CMMC AC.L2-3.1.5 | GAP-07] IAM policy '%v' uses wildcard action '%v'. Replace with least-privilege actions.",
        [resource.address, stmt.Action],
    )
}

# Action as an array (e.g. ["dynamodb:*", "s3:GetObject"])
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] in {"create", "update"}
    policy := json.unmarshal(resource.change.after.policy)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    is_string(action)
    endswith(action, ":*")
    msg := sprintf(
        "[CMMC AC.L2-3.1.5 | GAP-07] IAM policy '%v' uses wildcard action '%v'. Replace with least-privilege actions.",
        [resource.address, action],
    )
}

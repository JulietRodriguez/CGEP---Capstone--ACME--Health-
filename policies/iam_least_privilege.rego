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

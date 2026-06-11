package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    resource.change.actions[_] in {"create", "update"}
    after := resource.change.after

    # Terraform plan JSON serializes an absent block as [] not as absent key.
    # `not after.server_side_encryption` is false for [], so we count instead.
    count(object.get(after, "server_side_encryption", [])) == 0
    msg := sprintf(
        "[CMMC SC.L2-3.13.11 | GAP-02] DynamoDB table '%v' has no server_side_encryption block. Add CMK encryption.",
        [resource.address],
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    resource.change.actions[_] in {"create", "update"}
    sse := resource.change.after.server_side_encryption[_]
    sse.enabled != true
    msg := sprintf(
        "[CMMC SC.L2-3.13.11 | GAP-02] DynamoDB table '%v' server_side_encryption.enabled must be true.",
        [resource.address],
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    resource.change.actions[_] in {"create", "update"}
    sse := resource.change.after.server_side_encryption[_]
    sse.enabled == true
    not valid_kms_key(sse.kms_key_arn)
    msg := sprintf(
        "[CMMC SC.L2-3.13.11 | GAP-02] DynamoDB table '%v' must specify a customer kms_key_arn, not the AWS-owned default.",
        [resource.address],
    )
}

valid_kms_key(arn) if {
    is_string(arn)
    count(arn) > 0
}

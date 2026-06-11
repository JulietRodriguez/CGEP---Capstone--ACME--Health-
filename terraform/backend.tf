# Remote state backend — S3 + DynamoDB lock.
#
# Bootstrap (one-time, run from local after first `make deploy`):
#
#   aws s3 mb s3://<your-state-bucket> --region us-east-1
#   aws dynamodb create-table \
#     --table-name terraform-state-lock \
#     --attribute-definitions AttributeName=LockID,AttributeType=S \
#     --key-schema AttributeName=LockID,KeyType=HASH \
#     --billing-mode PAY_PER_REQUEST
#
#   terraform init \
#     -backend-config="bucket=<your-state-bucket>" \
#     -backend-config="region=us-east-1" \
#     -backend-config="dynamodb_table=terraform-state-lock" \
#     -migrate-state
#
# In CI, set GitHub secrets TF_STATE_BUCKET and TF_LOCK_TABLE.
# The grc-gate.yml workflow passes them to terraform init.

terraform {
  backend "s3" {
    key     = "acme-health-intake/terraform.tfstate"
    encrypt = true
  }
}

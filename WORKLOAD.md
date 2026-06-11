# What the workload does

Acme Health is a fictional 50-person telehealth company. Patients submit intake forms before their first visit. The data they submit is PHI under HIPAA. Acme also wants to attest SOC 2 Type II for enterprise customers and is exploring CMMC Level 2 for federal pilots.

This starter is the simplest version of that workload that still exercises every layer of cloud you'd actually govern.

## Surface area

One endpoint. POST `/intake` with a JSON body:

```json
{
  "patient_id": "P-00042",
  "submitted_at": "2026-04-25T14:00:00Z",
  "fields": {
    "reason_for_visit": "annual physical",
    "primary_complaint": "...",
    "preferred_pharmacy_npi": "1234567890"
  },
  "attachment_b64": "<optional base64 file content>"
}
```

The Lambda writes the submission to DynamoDB. If `attachment_b64` is present, it lands in the S3 uploads bucket keyed by submission ID.

Response:

```json
{ "submission_id": "uuid-v4", "status": "received" }
```

## What's in scope for the capstone

- The VPC and its routing.
- The Lambda function (binary trust boundary between API Gateway and your data stores).
- The DynamoDB table (PHI at rest).
- The S3 uploads bucket (PHI at rest, integrity-sensitive).
- The IAM role the Lambda assumes.
- The API Gateway stage (audit log surface).

Everything you write in the capstone is directly about hardening one of these.

## What's deliberately out of scope

- A real frontend.
- Authentication / authorization at the API layer (Cognito or otherwise). A capstone extension, not a requirement.
- Multi-region failover.
- Patient data lifecycle (deletion, export). Worth mentioning in your write-up as a known gap.

You don't need to expand the workload. The cert is testing your ability to govern what's there, not your ability to build more.

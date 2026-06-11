"""
Acme Health — patient intake handler.

Accepts POST /intake with JSON body:
    {"patient_id": "...", "submitted_at": "...", "fields": {...}}

Writes the submission to DynamoDB and (optionally) uploads any attached
file content to S3. Returns 200 with the new submission ID.

Deliberately minimal. The capstone learner is expected to catch and remediate
the GRC gaps listed in GAPS.md, not the application code.
"""

import json
import os
import time
import uuid

import boto3

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")

TABLE_NAME = os.environ["INTAKE_TABLE"]
UPLOAD_BUCKET = os.environ["UPLOAD_BUCKET"]


def handler(event, context):
    body = json.loads(event.get("body") or "{}")

    submission_id = str(uuid.uuid4())
    record = {
        "submission_id": submission_id,
        "patient_id": body.get("patient_id", "unknown"),
        "submitted_at": body.get("submitted_at") or str(int(time.time())),
        "fields": body.get("fields", {}),
    }

    dynamodb.Table(TABLE_NAME).put_item(Item=record)

    if "attachment_b64" in body:
        s3.put_object(
            Bucket=UPLOAD_BUCKET,
            Key=f"uploads/{submission_id}.bin",
            Body=body["attachment_b64"].encode("utf-8"),
        )

    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"submission_id": submission_id, "status": "received"}),
    }

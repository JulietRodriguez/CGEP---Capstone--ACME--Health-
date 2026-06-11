#!/usr/bin/env bash
# Smoke test: POST a sample intake to the deployed API.
set -euo pipefail

cd "$(dirname "$0")/../terraform"
API_URL=$(terraform output -raw api_url)

echo "POST $API_URL"
curl -sS -X POST "$API_URL" \
  -H 'content-type: application/json' \
  -d '{
        "patient_id": "P-0001",
        "fields": {"reason": "smoke-test"}
      }' \
  | python3 -m json.tool

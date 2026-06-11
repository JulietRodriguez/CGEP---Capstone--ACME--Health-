#!/usr/bin/env bash
# policy-gate.sh — run OPA unit tests then Conftest against a Terraform plan.
# Mirrors what grc-gate.yml Step 2 does, usable locally.
#
# Usage:
#   scripts/policy-gate.sh                          # generates a fresh plan
#   scripts/policy-gate.sh --plan path/to/plan.json # use existing plan JSON

set -euo pipefail

PLAN_JSON=${2:-terraform/tfplan.json}
POLICIES_DIR="policies"

echo "==> OPA unit tests"
opa test ./${POLICIES_DIR} --verbose
echo ""

if [ ! -f "${PLAN_JSON}" ]; then
    echo "==> No plan file found at ${PLAN_JSON}. Generating one..."
    terraform -chdir=terraform plan -out=tfplan.binary -input=false
    terraform -chdir=terraform show -json tfplan.binary > "${PLAN_JSON}"
    echo "==> Plan written to ${PLAN_JSON}"
fi

echo "==> Conftest policy gate"
conftest test "${PLAN_JSON}" \
    --policy "${POLICIES_DIR}/" \
    --all-namespaces \
    --output stdout

echo ""
echo "==> All policy checks passed."

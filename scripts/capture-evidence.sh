#!/usr/bin/env bash
# capture-evidence.sh — build and upload a signed evidence bundle to S3.
# Called by grc-gate.yml Step 4+5, or run manually for ad-hoc snapshots.
#
# Usage:
#   scripts/capture-evidence.sh [--dry-run]
#
# Required env:
#   EVIDENCE_BUCKET  — output of `terraform output -raw evidence_bucket`
#   AWS_REGION       — defaults to us-east-1
#
# Optional:
#   GIT_SHA          — defaults to $(git rev-parse HEAD)
#   RUN_ID           — defaults to local-$(date +%s)

set -euo pipefail

DRY_RUN=${1:-}
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
GIT_SHA=${GIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo "unknown")}
RUN_ID=${RUN_ID:-local-$(date +%s)}
AWS_REGION=${AWS_REGION:-us-east-1}
BUNDLE_DIR=$(mktemp -d)
BUNDLE_NAME="evidence-bundle.tar.gz"

echo "==> Capturing evidence snapshot"
echo "    Timestamp : ${TIMESTAMP}"
echo "    Git SHA   : ${GIT_SHA}"
echo "    Run ID    : ${RUN_ID}"

# ── Collect evidence artifacts ────────────────────────────────────────
mkdir -p "${BUNDLE_DIR}/evidence"

# Terraform plan JSON (if available)
if [ -f "terraform/tfplan.json" ]; then
    cp terraform/tfplan.json "${BUNDLE_DIR}/evidence/tfplan.json"
fi

# Current infrastructure outputs
if command -v terraform &>/dev/null && [ -f "terraform/terraform.tfstate" ]; then
    terraform -chdir=terraform output -json > "${BUNDLE_DIR}/evidence/outputs.json" || true
fi

# OPA policy test results
if command -v opa &>/dev/null; then
    opa test ./policies --format json > "${BUNDLE_DIR}/evidence/opa-test-results.json" || true
fi

# Metadata envelope
cat > "${BUNDLE_DIR}/evidence/metadata.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "git_sha": "${GIT_SHA}",
  "timestamp": "${TIMESTAMP}",
  "captured_by": "$(whoami 2>/dev/null || echo unknown)",
  "host": "$(hostname 2>/dev/null || echo unknown)"
}
EOF

# ── Build and hash ────────────────────────────────────────────────────
cd "${BUNDLE_DIR}"
tar czf "${BUNDLE_NAME}" evidence/
SHA=$(sha256sum "${BUNDLE_NAME}" | awk '{print $1}')
echo "${SHA}" > "${BUNDLE_NAME}.sha256"
echo "==> Bundle SHA-256: ${SHA}"

# ── Sign with Cosign (keyless) ────────────────────────────────────────
if command -v cosign &>/dev/null; then
    cosign sign-blob --yes "${BUNDLE_NAME}" --bundle "${BUNDLE_NAME}.cosign.bundle"
    echo "==> Bundle signed (Cosign keyless)"
else
    echo "WARN: cosign not found — bundle not signed. Install: https://docs.sigstore.dev/cosign/installation/"
fi

# ── Upload to vault ───────────────────────────────────────────────────
if [ -z "${DRY_RUN}" ]; then
    if [ -z "${EVIDENCE_BUCKET:-}" ]; then
        EVIDENCE_BUCKET=$(terraform -chdir="$(dirname "$0")/../terraform" output -raw evidence_bucket 2>/dev/null)
    fi
    PREFIX="runs/${TIMESTAMP}-${RUN_ID}"
    aws s3 cp "${BUNDLE_NAME}" "s3://${EVIDENCE_BUCKET}/${PREFIX}/${BUNDLE_NAME}" --region "${AWS_REGION}"
    aws s3 cp "${BUNDLE_NAME}.sha256" "s3://${EVIDENCE_BUCKET}/${PREFIX}/${BUNDLE_NAME}.sha256" --region "${AWS_REGION}"
    [ -f "${BUNDLE_NAME}.cosign.bundle" ] && \
        aws s3 cp "${BUNDLE_NAME}.cosign.bundle" "s3://${EVIDENCE_BUCKET}/${PREFIX}/${BUNDLE_NAME}.cosign.bundle" --region "${AWS_REGION}"
    echo "==> Uploaded to s3://${EVIDENCE_BUCKET}/${PREFIX}/"
else
    echo "==> [DRY-RUN] Would upload to s3://${EVIDENCE_BUCKET:-<EVIDENCE_BUCKET>}/runs/${TIMESTAMP}-${RUN_ID}/"
fi

rm -rf "${BUNDLE_DIR}"
echo "==> Done."

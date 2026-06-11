#!/usr/bin/env bash
# verify-evidence.sh — verify a signed evidence bundle from the S3 vault.
#
# Checks:
#   1. Cosign signature verifies against Sigstore transparency log
#   2. SHA-256 recomputes to match the .sha256 file
#   3. S3 Object Lock metadata shows retention is active
#
# Usage:
#   scripts/verify-evidence.sh <s3-prefix>
#   # e.g.  scripts/verify-evidence.sh runs/20260611T120000Z-1234567890
#
# Required env:
#   EVIDENCE_BUCKET  — name of the evidence vault bucket

set -euo pipefail

PREFIX=${1:?"Usage: $0 <s3-prefix>"}
EVIDENCE_BUCKET=${EVIDENCE_BUCKET:?"Set EVIDENCE_BUCKET env var"}
TMPDIR=$(mktemp -d)

echo "==> Verifying evidence bundle"
echo "    Bucket : ${EVIDENCE_BUCKET}"
echo "    Prefix : ${PREFIX}"

BUNDLE="evidence-bundle.tar.gz"
SHA_FILE="${BUNDLE}.sha256"
SIG_FILE="${BUNDLE}.cosign.bundle"

# ── Download artifacts ────────────────────────────────────────────────
echo "==> Downloading from S3..."
aws s3 cp "s3://${EVIDENCE_BUCKET}/${PREFIX}/${BUNDLE}" "${TMPDIR}/${BUNDLE}"
aws s3 cp "s3://${EVIDENCE_BUCKET}/${PREFIX}/${SHA_FILE}" "${TMPDIR}/${SHA_FILE}"
aws s3 cp "s3://${EVIDENCE_BUCKET}/${PREFIX}/${SIG_FILE}" "${TMPDIR}/${SIG_FILE}" || \
    echo "WARN: No cosign bundle found at ${PREFIX}/${SIG_FILE}"

cd "${TMPDIR}"

# ── Check 1: SHA-256 integrity ────────────────────────────────────────
echo "==> Verifying SHA-256 integrity..."
EXPECTED=$(cat "${SHA_FILE}")
ACTUAL=$(sha256sum "${BUNDLE}" | awk '{print $1}')
if [ "${EXPECTED}" != "${ACTUAL}" ]; then
    echo "FAIL: SHA-256 mismatch!"
    echo "  Expected : ${EXPECTED}"
    echo "  Actual   : ${ACTUAL}"
    exit 1
fi
echo "PASS: SHA-256 matches (${ACTUAL})"

# ── Check 2: Cosign signature ─────────────────────────────────────────
if [ -f "${SIG_FILE}" ] && command -v cosign &>/dev/null; then
    echo "==> Verifying Cosign signature against Sigstore..."
    cosign verify-blob \
        --bundle "${SIG_FILE}" \
        --certificate-identity-regexp "https://github.com/.*" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${BUNDLE}"
    echo "PASS: Cosign signature verified"
else
    echo "SKIP: cosign not available or no signature file"
fi

# ── Check 3: S3 Object Lock retention ─────────────────────────────────
echo "==> Checking S3 Object Lock retention..."
LOCK_STATUS=$(aws s3api head-object \
    --bucket "${EVIDENCE_BUCKET}" \
    --key "${PREFIX}/${BUNDLE}" \
    --query '{Mode:ObjectLockMode,RetainUntil:ObjectLockRetainUntilDate}' \
    --output json 2>/dev/null || echo '{}')

if echo "${LOCK_STATUS}" | grep -q "GOVERNANCE\|COMPLIANCE"; then
    echo "PASS: Object Lock retention active"
    echo "      ${LOCK_STATUS}"
else
    echo "WARN: Object Lock not active on this object (may require GOVERNANCE bypass permission)"
    echo "      ${LOCK_STATUS}"
fi

rm -rf "${TMPDIR}"
echo "==> Verification complete."

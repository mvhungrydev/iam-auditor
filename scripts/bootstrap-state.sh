#!/usr/bin/env bash
# IAM Auditor — Bootstrap Terraform Remote State
#
# Creates the S3 bucket used to store Terraform state.
# Run this ONCE before the first `terraform init`.
# Safe to re-run — all steps are idempotent.
#
# Prerequisites: AWS CLI configured with credentials that have S3 + STS permissions.

set -euo pipefail

REGION="us-east-1"

echo "==> Checking prerequisites..."
command -v aws >/dev/null 2>&1 || { echo "ERROR: AWS CLI not found. Install with: brew install awscli"; exit 1; }

echo "==> Verifying AWS credentials..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "    Account ID: ${ACCOUNT_ID}"

BUCKET="iam-auditor-tf-state-${ACCOUNT_ID}"
echo "    State bucket: ${BUCKET}"

# ── S3 Bucket ──────────────────────────────────────────────────────────────────

echo "==> Creating S3 state bucket (skips if already exists)..."
if aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  echo "    Bucket already exists — skipping create."
else
  aws s3api create-bucket \
    --bucket "${BUCKET}" \
    --region "${REGION}"
  echo "    Bucket created."
fi

echo "==> Enabling versioning..."
aws s3api put-bucket-versioning \
  --bucket "${BUCKET}" \
  --versioning-configuration Status=Enabled

echo "==> Enabling AES-256 encryption..."
aws s3api put-bucket-encryption \
  --bucket "${BUCKET}" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

echo "==> Blocking public access..."
aws s3api put-public-access-block \
  --bucket "${BUCKET}" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# ── Verify ─────────────────────────────────────────────────────────────────────

echo "==> Verifying bucket exists..."
aws s3 ls | grep "${BUCKET}" && echo "    OK — bucket confirmed."

echo ""
echo "Bootstrap complete."
echo ""
echo "Next step — initialize Terraform:"
echo "  cd infra/envs/dev && terraform init"
echo ""

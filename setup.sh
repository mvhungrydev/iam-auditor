#!/usr/bin/env bash
# IAM Auditor — Local Development Setup
# Run this once after cloning the repo to get your dev environment ready.
#
# Prerequisites: Python 3.12, Docker, Terraform >= 1.6, AWS CLI

set -euo pipefail

echo "==> Checking prerequisites..."

command -v python3.12 >/dev/null 2>&1 || { echo "ERROR: Python 3.12 not found. Install with: brew install python@3.12"; exit 1; }
command -v docker     >/dev/null 2>&1 || { echo "ERROR: Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"; exit 1; }
command -v terraform  >/dev/null 2>&1 || { echo "ERROR: Terraform not found. Install with: brew install terraform"; exit 1; }
command -v aws        >/dev/null 2>&1 || { echo "ERROR: AWS CLI not found. Install with: brew install awscli"; exit 1; }

echo "==> Creating Python 3.12 virtual environment..."
python3.12 -m venv .venv

echo "==> Installing dependencies..."
.venv/bin/pip install --upgrade pip --quiet
.venv/bin/pip install -r requirements-dev.txt --quiet

echo "==> Verifying test suite runs..."
.venv/bin/pytest tests/ -q --tb=short

echo ""
echo "Setup complete."
echo ""
echo "Activate your environment with:"
echo "  source .venv/bin/activate"
echo ""
echo "Run tests:"
echo "  pytest tests/"
echo ""
echo "Build the Lambda container locally:"
echo "  docker build -t iam-auditor-lambda src/lambda/"

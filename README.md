# IAM Auditor

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.6-purple)
![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange)
![License](https://img.shields.io/badge/License-MIT-green)

Automated weekly IAM security auditing for AWS accounts — delivered as a serverless Lambda container with Terraform infrastructure and a GitHub Actions CI/CD pipeline.

---

## What Is This?

AWS IAM sprawl is one of the leading causes of cloud security incidents. As accounts grow, IAM users, roles, and policies accumulate — many becoming unused, overly permissive, or misconfigured. Without automated oversight, unused access keys and roles remain active indefinitely, wildcard policies violate least privilege, and root account usage goes undetected.

**IAM Auditor** runs automatically every Monday at 08:00 UTC. It queries three IAM data sources — Access Analyzer, the Credential Report, and the Last Accessed API — applies 10 detection rules across two severity tiers, writes every finding to DynamoDB for historical tracking, and delivers a summary report to your inbox via SNS.

This is a portfolio project demonstrating AWS DevOps and security engineering skills: TDD with moto, containerized Lambda, Terraform modules, and OIDC-based CI/CD — all within the AWS Free Tier.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                         AWS Account                           │
│                                                               │
│  ┌──────────────┐    ┌─────────────────────────────────────┐  │
│  │  EventBridge │    │              VPC                    │  │
│  │  (weekly     │    │                                     │  │
│  │   cron)      │    │  ┌──────────────────────────────┐   │  │
│  └──────┬───────┘    │  │       Private Subnet         │   │  │
│         │ trigger    │  │                              │   │  │
│         ▼            │  │  ┌────────────────────────┐  │   │  │
│  ┌──────────────┐    │  │  │   Lambda (Container)   │  │   │  │
│  │   Lambda     │◄───┼──┼──│   handler.py           │  │   │  │
│  │   Invoke     │    │  │  │   (ECR image)          │  │   │  │
│  └──────────────┘    │  │  └─────────┬─────────────┘   │   │  │
│                      │  │            │                 │   │  │
│                      │  └────────────┼─────────────────┘   │  │
│                      │               │                     │  │
│                      │    ┌──────────▼──────────────────┐  │  │
│                      │    │     Gateway VPC Endpoints   │  │  │
│                      │    │   (S3 + DynamoDB — free)    │  │  │
│                      │    └──────────┬──────────────────┘  │  │
│                      └──────────────┼──────────────────────┘  │
│                                     │                         │
│         ┌───────────────────────────┼──────────────────────┐  │
│         │                           │ AWS APIs             │  │
│         │  ┌──────────────────┐     │                      │  │
│         │  │  IAM Access      │◄────┤                      │  │
│         │  │  Analyzer API    │     │                      │  │
│         │  └──────────────────┘     │                      │  │
│         │  ┌──────────────────┐     │                      │  │
│         │  │  IAM Credential  │◄────┤                      │  │
│         │  │  Report API      │     │                      │  │
│         │  └──────────────────┘     │                      │  │
│         │  ┌──────────────────┐     │                      │  │
│         │  │  IAM Last        │◄────┘                      │  │
│         │  │  Accessed API    │                            │  │
│         │  └──────────────────┘                            │  │
│         └──────────────────────────────────────────────────┘  │
│                                                               │
│         ┌─────────────────────────────────────────────────┐   │
│         │              Outputs                            │   │
│         │  ┌──────────────┐    ┌────────────────────────┐ │   │
│         │  │  DynamoDB    │    │  SNS → Email           │ │   │
│         │  │  (findings)  │    │  (weekly summary)      │ │   │
│         │  └──────────────┘    └────────────────────────┘ │   │
│         └─────────────────────────────────────────────────┘   │
│                                                               │
│         ┌─────────────────────────────────────────────────┐   │
│         │              Config                             │   │
│         │  ┌──────────────────────────────────────────┐   │   │
│         │  │  SSM Parameter Store (runtime config)    │   │   │
│         │  └──────────────────────────────────────────┘   │   │
│         └─────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

**Data flow:** EventBridge fires every Monday 08:00 UTC → Lambda starts from ECR image → reads config from SSM → queries IAM APIs in parallel → applies detection rules → writes findings to DynamoDB via Gateway VPC Endpoint → publishes summary email to SNS.

---

## Detection Rules

| Rule | Description | Severity | Source |
|------|-------------|----------|--------|
| R01 | External access detected by IAM Access Analyzer | CRITICAL | [access_analyzer.py](src/lambda/auditors/access_analyzer.py) |
| R02 | Root account access key exists | CRITICAL | [credential_report.py](src/lambda/auditors/credential_report.py) |
| R03 | IAM user with no MFA enabled | HIGH | [credential_report.py](src/lambda/auditors/credential_report.py) |
| R04 | IAM user with inline policy containing wildcard action | HIGH | [policy_scanner.py](src/lambda/auditors/policy_scanner.py) |
| R09 | IAM role with inline policy containing wildcard action | HIGH | [policy_scanner.py](src/lambda/auditors/policy_scanner.py) |
| R10 | IAM role with customer-managed policy containing wildcard action | HIGH | [policy_scanner.py](src/lambda/auditors/policy_scanner.py) |
| R05 | Console password unused for 90+ days | MEDIUM | [credential_report.py](src/lambda/auditors/credential_report.py) |
| R06 | Access key unused for 90+ days | MEDIUM | [credential_report.py](src/lambda/auditors/credential_report.py) |
| R07 | IAM role with no service activity for 90+ days | MEDIUM | [last_accessed.py](src/lambda/auditors/last_accessed.py) |
| R08 | Access key not rotated in 90+ days | MEDIUM | [credential_report.py](src/lambda/auditors/credential_report.py) |

Sensitive services for wildcard policy detection: `s3`, `iam`, `ec2`, `lambda`.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Python 3.12, AWS Lambda (container image) |
| Container | Docker, Amazon ECR |
| Infrastructure | Terraform >= 1.6, AWS VPC, EventBridge, DynamoDB, SNS, SSM |
| Testing | pytest, moto (AWS mocking), pytest-cov |
| Security scanning | checkov (IaC), bandit (Python), Trivy (container) |
| Local AWS | LocalStack, tflocal, awslocal |
| CI/CD | GitHub Actions, OIDC (no stored credentials) |

---

## Prerequisites

| Tool | Install |
|------|---------|
| Python 3.12 | `brew install python@3.12` |
| Docker Desktop | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| Terraform >= 1.6 | `brew install terraform` |
| AWS CLI | `brew install awscli` |
| checkov | `pip install checkov` |
| pipx (for LocalStack) | `brew install pipx && pipx ensurepath` |

---

## Setup — Local Dev

```bash
git clone https://github.com/<your-github-username>/iam-auditor.git
cd iam-auditor

# Creates .venv, installs all dependencies, and runs the test suite
./setup.sh

# Activate the virtual environment
source .venv/bin/activate
```

### Run Tests

```bash
# Full test suite
pytest tests/

# With coverage report
pytest --cov=src/lambda --cov-report=term-missing

# Single auditor
pytest tests/unit/test_credential_report.py -v
pytest tests/unit/test_policy_scanner.py -v
pytest tests/unit/test_access_analyzer.py -v
pytest tests/unit/test_last_accessed.py -v
pytest tests/unit/test_handler.py -v
```

All tests run entirely with [moto](https://docs.getmoto.org/) — no AWS account or credentials needed.

---

## Docker — Local Container Test

Build and smoke-test the Lambda container locally using the Lambda Runtime Interface Emulator (RIE):

```bash
# Build the image
docker build -t iam-auditor-lambda src/lambda/

# Run with RIE
docker run -p 9000:8080 \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=testing \
  -e AWS_SECRET_ACCESS_KEY=testing \
  iam-auditor-lambda:latest

# Invoke in a second terminal
curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{}'
```

### Container Security Scan

```bash
brew install trivy
trivy image --severity CRITICAL,HIGH --ignore-unfixed iam-auditor-lambda
```

---

## Terraform — Local Validation

Validate all Terraform configuration locally without touching AWS (no credentials needed):

```bash
cd infra/envs/dev

# Download providers without connecting to the S3 backend
terraform init -backend=false

# Check syntax and configuration
terraform validate

# Enforce consistent formatting
terraform fmt -recursive ../../

# IaC security scan
checkov -d ../../ --framework terraform

# Python security scan
bandit -r ../../../src/lambda/ -ll -ii
```

---

## LocalStack — Full Local Deploy

Test `terraform apply` locally without deploying to real AWS:

```bash
# Install (macOS — one-time)
brew install pipx && pipx ensurepath
pipx install localstack
pipx install terraform-local   # provides tflocal
pipx install awscli-local      # provides awslocal

# Start LocalStack (requires Docker running)
localstack start

# In a second terminal — deploy to LocalStack
cd infra/envs/dev
cp terraform.tfvars.example terraform.tfvars   # fill in values
tflocal init
tflocal apply
```

---

## Configuration

Copy the example file and fill in your values:

```bash
cp infra/envs/dev/terraform.tfvars.example infra/envs/dev/terraform.tfvars
```

> `terraform.tfvars` is gitignored and must never be committed. See [`infra/envs/dev/terraform.tfvars.example`](infra/envs/dev/terraform.tfvars.example) for the committed template.

| Variable | Description | Default |
|----------|-------------|---------|
| `alert_email` | SNS subscription — you will receive a confirmation email after first apply | required |
| `github_org` | Your GitHub username or org — scopes the OIDC trust policy | required |
| `aws_region` | Deployment region | `us-east-1` |
| `project_name` | Resource name prefix | `iam-auditor` |
| `unused_days_threshold` | Days of inactivity before R06/R07 fire | `90` |
| `ecr_image_tag` | Lambda image tag (CI/CD overrides with Git SHA) | `latest` |
| `github_repo` | GitHub repository name | `iam-auditor` |
| `create_demo_data` | Creates intentionally misconfigured IAM resources for testing | `true` (dev) / `false` (prod) |

---

## AWS Deployment (Dev)

### 1. Bootstrap Remote State (one-time)

Before running `terraform init`, the S3 bucket and DynamoDB lock table must exist:

```bash
# Replace <account_id> with your 12-digit AWS account ID
aws s3 mb s3://iam-auditor-tf-state-<account_id> --region us-east-1

aws dynamodb create-table \
  --table-name iam-auditor-tf-state-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1

# Enable versioning on the bucket
aws s3api put-bucket-versioning \
  --bucket iam-auditor-tf-state-<account_id> \
  --versioning-configuration Status=Enabled
```

### 2. Apply Infrastructure

```bash
cd infra/envs/dev
terraform init
terraform plan
terraform apply
```

> After the first apply, check your email and click the SNS subscription confirmation link — reports will not be delivered until confirmed.

### 3. Invoke Lambda Manually

```bash
aws lambda invoke \
  --function-name iam-auditor \
  --region us-east-1 \
  response.json
cat response.json
```

---

## CI/CD (GitHub Actions)

The pipeline uses GitHub OIDC for AWS authentication — no AWS credentials are stored as GitHub secrets.

**Triggers:**
- Push to `dev` → runs checks + deploys to dev
- Push to `main` → runs checks + deploys to prod

**Gates (must pass before any deploy):**
- `checkov` IaC security scan
- `bandit` Python security scan
- `pytest` full test suite

See [`docs/05-cicd-pipeline-spec.md`](docs/05-cicd-pipeline-spec.md) for the full workflow design, OIDC trust setup, and branch protection rules.

---

## Demo Data

Setting `create_demo_data = true` in `terraform.tfvars` creates five intentionally misconfigured IAM resources that trigger rules R03, R06, R07, R09, and R10. This lets you verify the auditor produces real findings after deploying to a fresh account.

To remove demo resources: set `create_demo_data = false` and run `terraform apply`.

---

## Project Documentation

| Document | Description |
|----------|-------------|
| [01 — Business Requirements](docs/01-business-requirements.md) | Problem statement, goals, functional/non-functional requirements, severity definitions |
| [02 — Value Proposition](docs/02-value-proposition.md) | Why not existing tools, what this project demonstrates |
| [03 — Technical Design](docs/03-technical-design.md) | Architecture, data flow, IAM policy design, detection rule logic |
| [04 — Infrastructure Spec](docs/04-infrastructure-spec.md) | Terraform module structure, variable schemas, resource layout |
| [05 — CI/CD Pipeline Spec](docs/05-cicd-pipeline-spec.md) | GitHub Actions workflow, OIDC auth setup, branch protection rules |
| [06 — Development Plan](docs/06-development-plan.md) | Sequenced stories and tasks (phases 1–6) |
| [07 — Future Enhancements](docs/07-future-enhancements.md) | Roadmap and planned improvements |
| [08 — Pytest Guide](docs/08-pytest-guide.md) | Test infrastructure, moto fixtures, TDD workflow, coverage gates |
| [AWS CLI Query Guide](docs/awscli-query-guide.md) | `--query` JMESPath examples for every project resource against LocalStack |

---

## AWS API Reference

Real-world AWS API call patterns used in this project:

| Auditor | API Sample |
|---------|-----------|
| Access Analyzer | [docs/aws-api-samples/access_analyzer.md](docs/aws-api-samples/access_analyzer.md) |
| Credential Report | [docs/aws-api-samples/credential_report.md](docs/aws-api-samples/credential_report.md) |
| Handler (orchestration) | [docs/aws-api-samples/handler.md](docs/aws-api-samples/handler.md) |
| Last Accessed | [docs/aws-api-samples/last_accessed.md](docs/aws-api-samples/last_accessed.md) |
| Policy Scanner | [docs/aws-api-samples/policy_scanner.md](docs/aws-api-samples/policy_scanner.md) |

---

## Free Tier

This project is designed to run entirely within the AWS Free Tier:

| Service | Free Tier |
|---------|-----------|
| Lambda | 1M requests/month — always free |
| DynamoDB | 25 GB storage — always free |
| SNS | 1M publishes/month — always free |
| SSM Parameter Store | Standard tier — always free |
| EventBridge | 14M events/month — always free |
| CloudWatch Logs | 5 GB/month free |
| ECR | 500 MB free (first 12 months) |
| VPC + Gateway Endpoints | Always free |

---

## License

MIT

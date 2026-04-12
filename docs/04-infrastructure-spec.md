# Infrastructure Specification
## Project: IAM Auditor

**Version:** 1.0
**Date:** 2026-03-21
**IaC Tool:** Terraform >= 1.6

---

## 1. Terraform Module Structure

```
infra/
├── modules/                    ← reusable modules — all logic lives here
│   ├── ecr/                    ← ECR repository + lifecycle policy
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── iam/                    ← Lambda execution role + policy
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── lambda/                 ← Lambda function (container), CloudWatch log group, EventBridge rule
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── dynamodb/               ← DynamoDB table + TTL config
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── sns/                    ← SNS topic + email subscription
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── ssm/                    ← SSM Parameter Store parameters
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── envs/                       ← environment-specific entrypoints
    ├── dev/                    ← development environment
    │   ├── main.tf             ← calls modules with dev values
    │   ├── variables.tf
    │   ├── terraform.tfvars    ← dev variable values (not committed)
    │   ├── outputs.tf
    │   ├── versions.tf         ← required_providers + Terraform version
    │   └── backend.tf          ← dev state backend (S3 bucket + DynamoDB lock)
    └── prod/                   ← production environment
        ├── main.tf             ← calls same modules with prod values
        ├── variables.tf
        ├── terraform.tfvars    ← prod variable values (not committed)
        ├── outputs.tf
        ├── versions.tf
        └── backend.tf          ← prod state backend (separate S3 bucket)
```

**How it works:** All Terraform logic lives in `modules/`. Each `envs/<env>/main.tf` calls the same modules, passing environment-specific variable values. Separate `backend.tf` per environment means isolated state — a plan or apply in `envs/dev/` cannot affect `envs/prod/`. To target a different AWS account per environment, set a different `role_arn` in the provider block within each env's `main.tf`.

**For this project (single account):** Only `envs/dev/` is deployed. The `envs/prod/` directory exists as the upgrade path — no changes to modules required when promoting.

---

## 2. Resource Inventory

| Resource | Type | Module | Notes |
|----------|------|--------|-------|
| ECR Repository | `aws_ecr_repository` | ecr | `iam-auditor-lambda` |
| ECR Lifecycle Policy | `aws_ecr_lifecycle_policy` | ecr | Keep last 3 images |
| Lambda Execution Role | `aws_iam_role` | iam | Least-privilege policy |
| Lambda IAM Policy | `aws_iam_policy` | iam | See Technical Design doc |
| Lambda Function | `aws_lambda_function` | lambda | Container image from ECR |
| EventBridge Rule | `aws_cloudwatch_event_rule` | lambda | cron(0 8 ? * MON *) |
| EventBridge Target | `aws_cloudwatch_event_target` | lambda | Target = Lambda ARN |
| Lambda Permission | `aws_lambda_permission` | lambda | Allow EventBridge invoke |
| DynamoDB Table | `aws_dynamodb_table` | dynamodb | PAY_PER_REQUEST billing |
| SNS Topic | `aws_sns_topic` | sns | `iam-auditor-alerts` |
| SNS Email Subscription | `aws_sns_topic_subscription` | sns | Protocol = email |
| SSM Parameter (SNS ARN) | `aws_ssm_parameter` | ssm | `/iam-auditor/sns-topic-arn` |
| SSM Parameter (Table) | `aws_ssm_parameter` | ssm | `/iam-auditor/dynamodb-table-name` |
| SSM Parameter (Threshold) | `aws_ssm_parameter` | ssm | `/iam-auditor/unused-days-threshold` |
| CloudWatch Log Group | `aws_cloudwatch_log_group` | lambda | Retention: 7 days |
| Demo IAM user (no MFA) | `aws_iam_user` | demo-data | Triggers R03 — dev only |
| Demo IAM user (stale key) | `aws_iam_user` + `aws_iam_access_key` | demo-data | Triggers R06 — dev only |
| Demo IAM role (inline wildcard) | `aws_iam_role` + inline policy | demo-data | Triggers R09 — dev only |
| Demo IAM role (managed wildcard) | `aws_iam_role` + `aws_iam_policy` | demo-data | Triggers R10 — dev only |
| Demo IAM role (unused) | `aws_iam_role` | demo-data | Triggers R07 — dev only |
| Terraform State Bucket | S3 bucket | **bootstrapped** (not Terraform-managed) | `iam-auditor-tf-state-<account_id>` — versioning + AES-256 + public access blocked |

---

## 3. DynamoDB Schema

**Table Name:** `iam-audit-findings`
**Billing Mode:** PAY_PER_REQUEST (no provisioned capacity cost, fits free tier)

### Key Schema
| Key | Type | Role |
|-----|------|------|
| `run_id` | String (S) | Partition Key |
| `finding_id` | String (S) | Sort Key |

### Attributes
| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `run_id` | S | Unique per Lambda execution | `run_20260321_080000` |
| `finding_id` | S | Unique per finding within a run | `R01_arn:aws:s3:::bucket` |
| `severity` | S | CRITICAL / HIGH / MEDIUM | `CRITICAL` |
| `rule_id` | S | Detection rule identifier | `R01` |
| `resource_arn` | S | Affected AWS resource | `arn:aws:s3:::my-bucket` |
| `detail` | S | Human-readable finding detail | `External access via policy` |
| `data_source` | S | Which API produced this finding | `access_analyzer` |
| `created_at` | S | ISO 8601 timestamp | `2026-03-21T08:00:00Z` |
| `expires_at` | N | Unix epoch — DynamoDB TTL | `1750000000` (30 days out) |

### TTL Configuration
- Attribute: `expires_at`
- Retention: 30 days from `created_at`
- Purpose: automatically purge old findings to stay within free tier (25GB)

### Access Patterns
| Pattern | Key Condition |
|---------|--------------|
| All findings for a run | `run_id = "run_20260321_080000"` |
| Specific finding | `run_id = "run_20260321_080000" AND finding_id = "R01_..."` |

---

## 4. SSM Parameter Store Layout

| Parameter Path | Type | Value | Description |
|---------------|------|-------|-------------|
| `/iam-auditor/sns-topic-arn` | String | `arn:aws:sns:...` | SNS topic ARN for alerts |
| `/iam-auditor/dynamodb-table-name` | String | `iam-audit-findings` | DynamoDB table name |
| `/iam-auditor/unused-days-threshold` | String | `90` | Days before unused resource is flagged |

**Notes:**
- All parameters use **Standard tier** (free — up to 10,000 parameters)
- No SecureString needed — no secrets stored, only config values
- Lambda reads these at runtime via `ssm:GetParameter`
- Managed by Terraform `aws_ssm_parameter` resources

---

## 5. ECR Repository Configuration

**Repository Name:** `iam-auditor-lambda`
**Image Tag Mutability:** MUTABLE (allows `latest` tag to be overwritten on each deploy)
**Encryption:** AES-256 (default, no extra cost)

### Lifecycle Policy
Keep only the 3 most recent images to stay within the 500MB free tier:

```json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Keep last 3 images",
      "selection": {
        "tagStatus": "any",
        "countType": "imageCountMoreThan",
        "countNumber": 3
      },
      "action": {
        "type": "expire"
      }
    }
  ]
}
```

---

## 6. Key Terraform Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `aws_region` | string | `us-east-1` | Deployment region |
| `project_name` | string | `iam-auditor` | Used for resource naming |
| `alert_email` | string | — | SNS subscription email (required) |
| `unused_days_threshold` | number | `90` | Days before unused resources flagged |
| `lambda_timeout` | number | `60` | Lambda timeout in seconds |
| `lambda_memory_mb` | number | `256` | Lambda memory allocation |
| `log_retention_days` | number | `7` | CloudWatch log retention |
| `ecr_image_tag` | string | `latest` | Image tag Terraform deploys |

---

## 7. Terraform State

### Why Remote State Is Required

GitHub Actions runners are **ephemeral** — the runner VM is destroyed at the end of every workflow run. If Terraform used local state, the `terraform.tfstate` file would be wiped after every pipeline execution. On the next run, Terraform would see no prior state and attempt to re-create every resource from scratch, producing duplicate resources, errors, and drift.

Remote state in S3 solves this: the state file persists between runs, Terraform knows what already exists, and `plan`/`apply` only shows real changes.

The DynamoDB lock table solves a second problem: concurrent `apply` operations (e.g., two developers or two simultaneous pipeline runs) can corrupt state if they both write at the same time. DynamoDB provides a distributed mutex — only one `terraform apply` can hold the lock at a time.

---

### State Resources

| Resource | AWS Service | Name | Notes |
|----------|-------------|------|-------|
| State file storage | S3 | `iam-auditor-tf-state-<account_id>` | Versioning + AES-256 encryption + public access blocked |
| State lock file | S3 (native) | `dev/terraform.tfstate.tflock` | Written alongside the state file — no DynamoDB needed (Terraform 1.10+ `use_lockfile = true`) |

> **Important:** The S3 bucket is **not managed by Terraform**. It must exist before `terraform init` can run. This is the Terraform bootstrapping paradox: Terraform needs a backend to store state, but it cannot create that backend using itself. It is created once with AWS CLI (see bootstrap commands below) and never destroyed — deleting it would orphan all Terraform state.
>
> **Note on DynamoDB locking:** Terraform 1.10+ introduced native S3 locking via `use_lockfile = true`, which stores a `.tflock` file in S3 alongside the state file. This replaces the older `dynamodb_table` parameter (now deprecated). No DynamoDB table is required for state locking.

---

### Bootstrap Commands (one-time manual, run before first `terraform init`)

```bash
# Capture your AWS account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Account ID: ${ACCOUNT_ID}"

# 1. Create the S3 state bucket (name must be globally unique — account ID ensures this)
aws s3api create-bucket \
  --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
  --region us-east-1

# 2. Enable versioning — allows recovery if state is accidentally overwritten or corrupted
aws s3api put-bucket-versioning \
  --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
  --versioning-configuration Status=Enabled

# 3. Enable AES-256 server-side encryption — state files contain resource ARNs and config values
aws s3api put-bucket-encryption \
  --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# 4. Block all public access — state files must never be publicly readable
aws s3api put-public-access-block \
  --bucket iam-auditor-tf-state-${ACCOUNT_ID} \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 5. Verify the bucket exists before proceeding
aws s3 ls | grep iam-auditor-tf-state
```

Expected output:
```
2026-xx-xx xx:xx:xx  iam-auditor-tf-state-<account_id>
```

> **Note:** No DynamoDB table is needed. Terraform 1.10+ uses `use_lockfile = true` in the S3 backend, which stores a `.tflock` file in S3 for state locking. This is simpler and cheaper than the older `dynamodb_table` approach.

---

### `infra/envs/dev/backend.tf`

```hcl
terraform {
  backend "s3" {
    bucket       = "iam-auditor-tf-state-<your_account_id>"  # replace with actual account ID
    key          = "dev/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true   # Terraform 1.10+ native S3 locking — no DynamoDB table needed
    encrypt      = true
  }
}
```

### `infra/envs/prod/backend.tf`

```hcl
terraform {
  backend "s3" {
    bucket       = "iam-auditor-tf-state-<your_account_id>"  # same bucket, different key
    key          = "prod/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true   # Terraform 1.10+ native S3 locking — no DynamoDB table needed
    encrypt      = true
  }
}
```

> **Note:** Both files are safe to commit — they contain no secrets. The bucket name uses your account ID, which is not sensitive (it appears in all resource ARNs anyway). Replace `<your_account_id>` with your actual 12-digit AWS account ID.

---

### Why S3 Key Separation Matters

Both environments share the same S3 bucket but use **separate state keys**. This means:

| Environment | S3 Key | Lock File | Isolated From |
|-------------|--------|-----------|---------------|
| dev | `dev/terraform.tfstate` | `dev/terraform.tfstate.tflock` | Prod state, prod resources |
| prod | `prod/terraform.tfstate` | `prod/terraform.tfstate.tflock` | Dev state, dev resources |

Running `terraform apply` in `envs/dev/` reads and writes only `dev/terraform.tfstate`. It has no knowledge of prod resources. A failed dev apply cannot affect prod infrastructure. This is the core benefit of the `envs/` directory pattern combined with per-environment backend keys.

The S3 lock file also scopes per key — a dev apply and a prod apply can run simultaneously without conflict because they write different `.tflock` files (`dev/terraform.tfstate.tflock` vs `prod/terraform.tfstate.tflock`).

---

### CI/CD State Access — Required IAM Permissions

When GitHub Actions calls `terraform init` and `terraform apply`, it uses the OIDC role. That role needs the following permissions on the state resources. These are already included in `infra/modules/iam/main.tf`:

```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::iam-auditor-tf-state-<account_id>",
    "arn:aws:s3:::iam-auditor-tf-state-<account_id>/*"
  ]
}
```

| Permission | When Used | Why |
|------------|-----------|-----|
| `s3:GetObject` | `terraform init`, `plan`, `apply` | Download current state file before computing diff |
| `s3:PutObject` | `terraform apply` | Write updated state file and `.tflock` file after resources change |
| `s3:DeleteObject` | Lock release, `terraform state rm` | Remove `.tflock` file after `apply` completes or fails |
| `s3:ListBucket` | `terraform init` | Verify the bucket exists and the key path is accessible |

> **No DynamoDB permissions needed for state locking.** Terraform 1.10+ `use_lockfile = true` stores the lock as a `.tflock` file in S3 alongside the state file. No DynamoDB table is required.

---

## 9. Module Outputs Reference

These are the outputs each module exposes. Used when wiring modules together in `envs/dev/main.tf`.

### ecr

| Output | Description | Consumer |
|--------|-------------|----------|
| `repository_url` | Full ECR image URL | CI/CD image push; Lambda `image_uri` |
| `repository_arn` | ECR repository ARN | Lambda execution role IAM policy |

### iam

| Output | Description | Consumer |
|--------|-------------|----------|
| `lambda_role_arn` | Lambda execution role ARN | Lambda module (`role_arn`) |
| `cicd_role_arn` | GitHub Actions OIDC role ARN | CI/CD pipeline spec reference |

### dynamodb

| Output | Description | Consumer |
|--------|-------------|----------|
| `table_name` | DynamoDB table name | SSM module (stored as parameter value) |
| `table_arn` | DynamoDB table ARN | Lambda execution role IAM policy scoping |

### sns

| Output | Description | Consumer |
|--------|-------------|----------|
| `topic_arn` | SNS topic ARN | SSM module (stored as parameter value) |

### ssm

| Output | Description | Consumer |
|--------|-------------|----------|
| `parameter_arns` | Map of all SSM parameter ARNs | Lambda execution role IAM policy scoping |

### lambda

| Output | Description | Consumer |
|--------|-------------|----------|
| `function_arn` | Lambda function ARN | EventBridge target; general reference |
| `function_name` | Lambda function name | CloudWatch log group naming; CLI invocations |

### demo-data

| Output | Description | Consumer |
|--------|-------------|----------|
| `demo_user_arns` | ARNs of demo IAM users (null if disabled) | Dev validation / reference only |
| `demo_role_arns` | ARNs of demo IAM roles (null if disabled) | Dev validation / reference only |

---

## 8. Tagging Strategy

All resources tagged consistently for cost tracking and identification:

```hcl
default_tags = {
  Project     = "iam-auditor"
  Environment = "prod"
  ManagedBy   = "terraform"
  Owner       = "devops"
}
```

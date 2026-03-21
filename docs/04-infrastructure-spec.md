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
│   ├── vpc/                    ← VPC, subnets, route tables, Gateway endpoints
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── ecr/                    ← ECR repository + lifecycle policy
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── iam/                    ← Lambda execution role + policy
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── lambda/                 ← Lambda function (container), security group
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
| VPC | `aws_vpc` | vpc | CIDR 10.0.0.0/16 |
| Public Subnet | `aws_subnet` | vpc | 10.0.1.0/24, us-east-1a |
| Private Subnet | `aws_subnet` | vpc | 10.0.2.0/24, us-east-1a |
| Internet Gateway | `aws_internet_gateway` | vpc | Attached to VPC |
| Public Route Table | `aws_route_table` | vpc | Routes 0.0.0.0/0 → IGW |
| Private Route Table | `aws_route_table` | vpc | No default route (no NAT) |
| S3 Gateway Endpoint | `aws_vpc_endpoint` | vpc | type=Gateway, free |
| DynamoDB Gateway Endpoint | `aws_vpc_endpoint` | vpc | type=Gateway, free |
| ECR Repository | `aws_ecr_repository` | ecr | `iam-auditor-lambda` |
| ECR Lifecycle Policy | `aws_ecr_lifecycle_policy` | ecr | Keep last 3 images |
| Lambda Execution Role | `aws_iam_role` | iam | Least-privilege policy |
| Lambda IAM Policy | `aws_iam_policy` | iam | See Technical Design doc |
| Lambda Security Group | `aws_security_group` | lambda | No inbound, HTTPS egress |
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
| `expires_at` | N | Unix epoch — DynamoDB TTL | `1750000000` (90 days out) |

### TTL Configuration
- Attribute: `expires_at`
- Retention: 90 days from `created_at`
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

- **Backend:** Local (default) for development
- **Recommended for production:** S3 backend with DynamoDB state locking
  ```hcl
  terraform {
    backend "s3" {
      bucket         = "my-tf-state-bucket"
      key            = "iam-auditor/terraform.tfstate"
      region         = "us-east-1"
      dynamodb_table = "terraform-state-lock"
      encrypt        = true
    }
  }
  ```
- For this portfolio project: local state is acceptable; document the upgrade path

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

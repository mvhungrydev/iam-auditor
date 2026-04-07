# -----------------------------------------------------------------------------
# VPC
# Creates the VPC, public + private subnets, IGW, route tables, and Gateway
# Endpoints for S3 and DynamoDB (free, keeps Lambda traffic off the internet).
# -----------------------------------------------------------------------------
module "vpc" {
  source       = "../../modules/vpc"
  project_name = var.project_name
  # All CIDR and AZ variables use module defaults (10.0.0.0/16, us-east-1a).
  # Override here if you need a different network layout.
}

# -----------------------------------------------------------------------------
# ECR
# Creates the container image repository. Must be applied first (via
# -target=module.ecr) before the Docker image can be pushed in Story 5.2.
# -----------------------------------------------------------------------------
module "ecr" {
  source       = "../../modules/ecr"
  project_name = var.project_name
}

# -----------------------------------------------------------------------------
# IAM
# Creates the Lambda execution role (least-privilege, 9 statements) and the
# GitHub Actions OIDC CI/CD role. The OIDC trust policy is scoped to this
# specific repo + branch so no other GitHub repo can assume it.
# -----------------------------------------------------------------------------
module "iam" {
  source       = "../../modules/iam"
  project_name = var.project_name
  github_org   = var.github_org
  github_repo  = var.github_repo
}

# -----------------------------------------------------------------------------
# DynamoDB
# Creates the findings table (run_id PK, finding_id SK, TTL on expires_at).
# PAY_PER_REQUEST billing — no capacity to manage, fits free tier.
# -----------------------------------------------------------------------------
module "dynamodb" {
  source       = "../../modules/dynamodb"
  project_name = var.project_name
}

# -----------------------------------------------------------------------------
# SNS
# Creates the alert topic and email subscription. The subscriber must click the
# confirmation link in their inbox after the first terraform apply — alerts will
# not be delivered until confirmed.
# -----------------------------------------------------------------------------
module "sns" {
  source       = "../../modules/sns"
  project_name = var.project_name
  alert_email  = var.alert_email
}

# -----------------------------------------------------------------------------
# SSM Parameter Store
# Stores three runtime config values so Lambda reads them at invocation time
# rather than having them baked into the container image.
#
# Dependency order:
#   sns.topic_arn      → /iam-auditor/sns-topic-arn
#   dynamodb.table_name → /iam-auditor/dynamodb-table-name
#   var.unused_days_threshold → /iam-auditor/unused-days-threshold
# -----------------------------------------------------------------------------
module "ssm" {
  source                = "../../modules/ssm"
  sns_topic_arn         = module.sns.topic_arn
  dynamodb_table_name   = module.dynamodb.table_name
  unused_days_threshold = var.unused_days_threshold

  depends_on = [module.sns, module.dynamodb]
}

# -----------------------------------------------------------------------------
# Lambda
# Creates the Lambda function (container image from ECR), the CloudWatch log
# group, and the EventBridge rule that fires every Monday at 08:00 UTC.
#
# Lambda is not placed in the VPC — it only calls public AWS APIs (SSM, IAM,
# DynamoDB, SNS, Access Analyzer). VPC placement would require Interface
# Endpoints (~$18/month) with no security benefit for this workload.
#
# image_uri is constructed from the ECR repository URL + the image tag variable.
# In local dev: ecr_image_tag = "latest"
# In CI/CD: ecr_image_tag = git SHA (set via -var="ecr_image_tag=${{ github.sha }}")
# -----------------------------------------------------------------------------
module "lambda" {
  source          = "../../modules/lambda"
  lambda_role_arn = module.iam.lambda_role_arn
  image_uri       = "${module.ecr.repository_url}:${var.ecr_image_tag}"
  project_name    = var.project_name
  depends_on      = [module.iam, module.ecr]
}

# -----------------------------------------------------------------------------
# Demo Data
# Creates intentionally misconfigured IAM resources to give the Lambda real
# findings to detect during the Phase 5 demo. Controlled by create_demo_data.
#
# Set create_demo_data = true  → creates 5 demo resources (R03, R06, R07, R09, R10)
# Set create_demo_data = false → destroys them (run terraform apply to clean up)
#
# Never enable this in prod — the module guard prevents it but good practice
# to leave it false in prod's terraform.tfvars.
# -----------------------------------------------------------------------------
module "demo_data" {
  source           = "../../modules/demo-data"
  project_name     = var.project_name
  create_demo_data = var.create_demo_data
}

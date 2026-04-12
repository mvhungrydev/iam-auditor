# Prod entrypoint — calls the same modules as dev with prod-appropriate values.
# This environment is a placeholder and is not deployed for this portfolio project.
# No changes to modules are required to promote from dev to prod.

module "vpc" {
  source       = "../../modules/vpc"
  project_name = var.project_name
}

module "ecr" {
  source       = "../../modules/ecr"
  project_name = var.project_name
}

module "iam" {
  source       = "../../modules/iam"
  project_name = var.project_name
  account_id   = var.account_id
  github_org   = var.github_org
  github_repo  = var.github_repo
}

module "dynamodb" {
  source       = "../../modules/dynamodb"
  project_name = var.project_name
}

module "sns" {
  source       = "../../modules/sns"
  project_name = var.project_name
  alert_email  = var.alert_email
}

module "ssm" {
  source                = "../../modules/ssm"
  sns_topic_arn         = module.sns.topic_arn
  dynamodb_table_name   = module.dynamodb.table_name
  unused_days_threshold = var.unused_days_threshold

  depends_on = [module.sns, module.dynamodb]
}

module "lambda" {
  source          = "../../modules/lambda"
  lambda_role_arn = module.iam.lambda_role_arn
  image_uri       = "${module.ecr.repository_url}:${var.ecr_image_tag}"
  project_name    = var.project_name

  depends_on = [module.iam, module.ecr]
}

# Demo data is disabled in prod — create_demo_data defaults to false in prod variables.tf.
module "demo_data" {
  source           = "../../modules/demo-data"
  project_name     = var.project_name
  create_demo_data = var.create_demo_data
}

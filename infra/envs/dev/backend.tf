terraform {
  backend "s3" {
    # Replace <your_account_id> with your 12-digit AWS account ID after running Story 5.0 bootstrap.
    # This file is safe to commit — it contains no secrets.
    # The S3 bucket and DynamoDB lock table must already exist before running terraform init.
    # See docs/04-infrastructure-spec.md §7 for bootstrap commands.
    bucket         = "iam-auditor-tf-state-<your_account_id>"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "iam-auditor-tf-state-lock"
    encrypt        = true
  }
}

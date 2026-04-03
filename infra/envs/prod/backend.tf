terraform {
  backend "s3" {
    # Same bucket as dev — isolated by the key path (prod/terraform.tfstate vs dev/terraform.tfstate).
    # Replace <your_account_id> with your 12-digit AWS account ID.
    # See docs/04-infrastructure-spec.md §7 for bootstrap commands and rationale.
    bucket         = "iam-auditor-tf-state-<your_account_id>"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "iam-auditor-tf-state-lock"
    encrypt        = true
  }
}

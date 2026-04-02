resource "aws_dynamodb_table" "this" {
  name         = "iam-audit-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "run_id"
  range_key    = "finding_id"

  attribute {
    name = "run_id"
    type = "S"
  }

  attribute {
    name = "finding_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = { Name = "${var.project_name}-findings-table" }
}

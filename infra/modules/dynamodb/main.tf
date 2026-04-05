#checkov:skip=CKV_AWS_28:PITR not enabled — PAY_PER_REQUEST billing + 30-day TTL is sufficient for a free tier portfolio project; PITR incurs additional cost
#checkov:skip=CKV_AWS_119:KMS CMK not used — AWS-managed encryption is sufficient for a free tier portfolio project; KMS would incur additional cost
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

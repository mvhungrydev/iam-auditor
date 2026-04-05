#checkov:skip=CKV_AWS_26:SNS KMS encryption not enabled — audit alert messages contain no sensitive data (only finding summaries); KMS would incur additional cost
resource "aws_sns_topic" "this" {
  name = "${var.project_name}-alerts"

  tags = { Name = "${var.project_name}-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.this.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

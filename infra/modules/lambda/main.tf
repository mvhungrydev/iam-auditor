resource "aws_cloudwatch_log_group" "lambda" {
  #checkov:skip=CKV_AWS_338:Log retention set to 7 days intentionally — extended retention would incur CloudWatch storage costs; 7 days is sufficient for a free tier portfolio project
  #checkov:skip=CKV_AWS_158:CloudWatch log group KMS encryption not enabled — Lambda logs contain no sensitive data; KMS would incur additional cost
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = 7
}

resource "aws_lambda_function" "this" {
  #checkov:skip=CKV_AWS_116:DLQ not required — weekly EventBridge-triggered Lambda has no downstream dependencies that need dead-letter handling
  #checkov:skip=CKV_AWS_50:X-Ray tracing not enabled — scheduled weekly Lambda has no latency SLO or distributed tracing requirement
  #checkov:skip=CKV_AWS_272:Code signing not applicable — Lambda uses container image package type (package_type = Image); code signing only applies to zip-based functions
  #checkov:skip=CKV_AWS_115:Concurrent execution limit not set — Lambda runs once per week via EventBridge; no concurrency risk for this workload
  #checkov:skip=CKV_AWS_117:Lambda not placed in VPC — function only calls public AWS APIs (SSM, IAM, DynamoDB, SNS, Access Analyzer); VPC placement would require Interface Endpoints (~$18/month) with no security benefit for this workload
  function_name = var.project_name
  role          = var.lambda_role_arn
  package_type  = "Image"
  image_uri     = var.image_uri
  timeout       = 300
  memory_size   = 256

  depends_on = [aws_cloudwatch_log_group.lambda]
}

resource "aws_cloudwatch_event_rule" "weekly" {
  name                = "${var.project_name}-weekly"
  description         = "Trigger IAM auditor every Monday at 08:00 UTC"
  schedule_expression = "cron(0 8 ? * MON *)"
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.weekly.name
  target_id = "${var.project_name}-lambda"
  arn       = aws_lambda_function.this.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly.arn
}

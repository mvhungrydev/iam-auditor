output "demo_user_arns" {
  value = [
    try(aws_iam_user.no_mfa[0].arn, null),
    try(aws_iam_user.stale_key[0].arn, null),
  ]
  description = "ARNs of demo IAM users — null when create_demo_data = false"
}

output "demo_role_arns" {
  value = [
    try(aws_iam_role.wildcard_inline[0].arn, null),
    try(aws_iam_role.wildcard_managed[0].arn, null),
    try(aws_iam_role.unused[0].arn, null),
  ]
  description = "ARNs of demo IAM roles — null when create_demo_data = false"
}

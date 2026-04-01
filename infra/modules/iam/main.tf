# ── Lambda execution role ─────────────────────────────────────────────────────

resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Name = "${var.project_name}-lambda-role" }
}

resource "aws_iam_policy" "lambda" {
  name        = "${var.project_name}-lambda-policy"
  description = "Least-privilege policy for the IAM Auditor Lambda execution role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMReadRequiresWildcard"
        Effect = "Allow"
        Action = [
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "iam:ListRoles",
          "iam:ListUsers",
          "iam:GetServiceLastAccessedDetails"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMReadScopedToUsersRolesAndPolicies"
        Effect = "Allow"
        Action = [
          "iam:ListUserPolicies",
          "iam:GetUserPolicy",
          "iam:ListAttachedUserPolicies",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ]
        Resource = [
          "arn:aws:iam::*:user/*",
          "arn:aws:iam::*:role/*",
          "arn:aws:iam::*:policy/*"
        ]
      },
      {
        Sid      = "AccessAnalyzerRequiresWildcard"
        Effect   = "Allow"
        Action   = "access-analyzer:ListAnalyzers"
        Resource = "*"
      },
      {
        Sid      = "AccessAnalyzerScopedToAnalyzer"
        Effect   = "Allow"
        Action   = "access-analyzer:ListFindings"
        Resource = "arn:aws:access-analyzer:*:*:analyzer/*"
      },
      {
        Sid      = "DynamoDBWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:BatchWriteItem"]
        Resource = "arn:aws:dynamodb:*:*:table/iam-audit-findings"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:*:*:iam-auditor-alerts"
      },
      {
        Sid      = "SSMRead"
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = "arn:aws:ssm:*:*:parameter/iam-auditor/*"
      },
      {
        Sid    = "VPCNetworking"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/iam-auditor*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda.arn
}

# ── GitHub Actions OIDC role ──────────────────────────────────────────────────

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = { Name = "${var.project_name}-github-oidc" }
}

resource "aws_iam_role" "cicd" {
  name = "github-actions-${var.project_name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/dev"
        }
      }
    }]
  })

  tags = { Name = "github-actions-${var.project_name}" }
}

resource "aws_iam_policy" "cicd" {
  name        = "github-actions-${var.project_name}-policy"
  description = "Permissions for GitHub Actions to deploy the IAM Auditor"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "ECRPush"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer"
        ]
        Resource = "arn:aws:ecr:*:*:repository/${var.project_name}-lambda"
      },
      {
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "arn:aws:lambda:*:*:function:${var.project_name}*"
      },
      {
        Sid    = "TerraformManage"
        Effect = "Allow"
        Action = [
          "ec2:*", "iam:*", "lambda:*", "dynamodb:*",
          "sns:*", "ssm:*", "logs:*", "events:*",
          "ecr:*", "access-analyzer:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cicd" {
  role       = aws_iam_role.cicd.name
  policy_arn = aws_iam_policy.cicd.arn
}

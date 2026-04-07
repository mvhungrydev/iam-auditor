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
  #checkov:skip=CKV_AWS_290:Some IAM actions genuinely require Resource="*" — iam:GenerateCredentialReport, iam:ListRoles cannot be scoped to specific resources per AWS documentation
  #checkov:skip=CKV_AWS_355:Wildcard resources required for IAM read actions that do not support resource-level permissions
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
  #checkov:skip=CKV_AWS_288:CI/CD role requires broad Terraform provisioning permissions — scoped to project resources per design in docs/03-technical-design.md
  #checkov:skip=CKV_AWS_290:CI/CD role requires broad Terraform provisioning permissions — Terraform actions cannot be scoped below Resource="*" for many AWS control-plane operations
  #checkov:skip=CKV_AWS_287:CI/CD role requires broad Terraform provisioning permissions — credential-exposure actions required for Terraform to manage IAM resources during deploy
  #checkov:skip=CKV_AWS_289:CI/CD role requires broad Terraform provisioning permissions — permissions management actions required for Terraform to create/update IAM roles and policies
  #checkov:skip=CKV_AWS_355:CI/CD role requires broad Terraform provisioning permissions — wildcard resources required for Terraform control-plane operations
  #checkov:skip=CKV_AWS_286:CI/CD role requires broad Terraform provisioning permissions — privilege escalation checks not applicable to a deployment role with documented scope
  #checkov:skip=CKV2_AWS_40:CI/CD role requires full IAM privileges for Terraform to manage IAM resources during deploy — intentional and documented in docs/03-technical-design.md
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

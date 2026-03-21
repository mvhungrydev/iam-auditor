# Technical Design Document

## Project: IAM Auditor

**Version:** 1.0
**Date:** 2026-03-21

---

## 1. Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│                         AWS Account                           │
│                                                               │
│  ┌──────────────┐    ┌─────────────────────────────────────┐  │
│  │  EventBridge │    │              VPC                    │  │
│  │  (weekly     │    │                                     │  │
│  │   cron)      │    │  ┌──────────────────────────────┐   │  │
│  └──────┬───────┘    │  │       Private Subnet         │   │  │
│         │ trigger    │  │                              │   │  │
│         ▼            │  │  ┌────────────────────────┐  │   │  │
│  ┌──────────────┐    │  │  │   Lambda (Container)   │  │   │  │
│  │   Lambda     │◄───┼──┼──│   handler.py           │  │   │  │
│  │   Invoke     │    │  │  │   (ECR image)          │  │   │  │
│  └──────────────┘    │  │  └─────────┬─────────────┘   │   │  │
│                      │  │            │                 │   │  │
│                      │  └────────────┼─────────────────┘   │  │
│                      │               │                     │  │
│                      │    ┌──────────▼──────────────────┐  │  │
│                      │    │     Gateway VPC Endpoints   │  │  │
│                      │    │   (S3 + DynamoDB — free)    │  │  │
│                      │    └──────────┬──────────────────┘  │  │
│                      └──────────────┼──────────────────────┘  │
│                                     │                         │
│         ┌───────────────────────────┼──────────────────────┐  │
│         │                           │ AWS APIs             │  │
│         │  ┌──────────────────┐     │                      │  │
│         │  │  IAM Access      │◄────┤                      │  │
│         │  │  Analyzer API    │     │                      │  │
│         │  └──────────────────┘     │                      │  │
│         │  ┌──────────────────┐     │                      │  │
│         │  │  IAM Credential  │◄────┤                      │  │
│         │  │  Report API      │     │                      │  │
│         │  └──────────────────┘     │                      │  │
│         │  ┌──────────────────┐     │                      │  │
│         │  │  IAM Last        │◄────┘                      │  │
│         │  │  Accessed API    │                            │  │
│         │  └──────────────────┘                            │  │
│         └──────────────────────────────────────────────── ─┘  │
│                                                               │
│         ┌─────────────────────────────────────────────────┐   │
│         │              Outputs                            │   │
│         │  ┌──────────────┐    ┌────────────────────────┐ │   │
│         │  │  DynamoDB    │    │  SNS → Email           │ │   │
│         │  │  (findings)  │    │  (weekly summary)      │ │   │
│         │  └──────────────┘    └────────────────────────┘ │   │
│         └─────────────────────────────────────────────────┘   │
│                                                               │
│         ┌─────────────────────────────────────────────────┐   │
│         │              Config                             │   │
│         │  ┌──────────────────────────────────────────┐   │   │
│         │  │  SSM Parameter Store (runtime config)    │   │   │
│         │  └──────────────────────────────────────────┘   │   │
│         └─────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow

```
Step 1:  EventBridge cron fires every Monday 08:00 UTC
              │
Step 2:  Lambda container starts (ECR image pull from private subnet
         via ECR API — no public internet needed for Lambda invoke)
              │
Step 3:  Lambda reads config from SSM Parameter Store
         - /iam-auditor/sns-topic-arn
         - /iam-auditor/dynamodb-table-name
         - /iam-auditor/unused-days-threshold
              │
Step 4:  Lambda calls three IAM data sources in parallel:
         ├── IAM Access Analyzer: list_findings() → external access findings
         ├── IAM Credential Report: generate_credential_report() +
         │   get_credential_report() → CSV of all users
         └── IAM Last Accessed: generate_service_last_accessed_details()
                                 per role → unused role detection
              │
Step 5:  Lambda applies severity rules to raw data:
         - CRITICAL: root access key exists, Access Analyzer external finding
         - HIGH: user without MFA, inline policy with * on sensitive service
         - MEDIUM: access key unused 90+ days, role unused 90+ days
              │
Step 6:  Lambda writes each finding to DynamoDB
         (via Gateway VPC Endpoint — traffic stays within AWS network)
              │
Step 7:  Lambda builds summary email (finding counts by severity)
         and publishes to SNS topic → subscriber receives email
              │
Step 8:  Lambda logs execution summary to CloudWatch Logs
```

---

## 3. Component Breakdown

| Component             | Purpose                          | Free Tier                 |
| --------------------- | -------------------------------- | ------------------------- |
| EventBridge           | Weekly cron trigger              | 14M events/mo free        |
| Lambda (container)    | Audit logic entry point          | 1M req/mo always free     |
| ECR                   | Stores Lambda container image    | 500MB free (12 mo)        |
| IAM Access Analyzer   | Detects external access findings | Always free               |
| IAM Credential Report | User hygiene data source         | Always free               |
| IAM Last Accessed API | Role activity data source        | Always free               |
| DynamoDB              | Persistent findings store        | 25GB always free          |
| SNS                   | Email delivery of weekly report  | 1M publishes always free  |
| SSM Parameter Store   | Runtime config and secrets       | Standard tier always free |
| VPC + Private Subnet  | Network isolation for Lambda     | Always free               |
| Gateway VPC Endpoints | Private access to DynamoDB + S3  | Always free               |
| CloudWatch Logs       | Lambda execution logs            | 5GB/mo free               |

---

## 4. Lambda Container Specification

### Base Image

```
public.ecr.aws/lambda/python:3.12
```

Using the AWS-maintained Lambda base image ensures compatibility with the Lambda runtime interface and includes the Runtime Interface Client (RIC) pre-installed.

### Directory Structure

```
src/lambda/
├── Dockerfile
├── handler.py          ← entry point
├── requirements.txt
└── auditors/
    ├── __init__.py
    ├── access_analyzer.py
    ├── credential_report.py
    └── last_accessed.py
```

### Dockerfile

```dockerfile
FROM public.ecr.aws/lambda/python:3.12

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY handler.py .
COPY auditors/ auditors/

# Entry point: module.function
CMD ["handler.lambda_handler"]
```

### Entry Point

- **Module:** `handler`
- **Function:** `lambda_handler`
- **Signature:** `def lambda_handler(event, context)`
- The `event` payload from EventBridge is ignored (no input needed — auditor is stateless per run)

### Dependencies (requirements.txt)

```
boto3>=1.34.0
```

No third-party libraries needed — all logic uses the AWS SDK (boto3) which is available in the Lambda base image. Listing it explicitly pins the version for reproducibility.

---

## 5. VPC Layout

```
VPC: 10.0.0.0/16
│
├── Public Subnet: 10.0.1.0/24  (AZ: us-east-1a)
│   └── (reserved for future use — no resources deployed here for this project)
│
└── Private Subnet: 10.0.2.0/24  (AZ: us-east-1a)
    └── Lambda function (VPC-attached)
        └── Security Group: iam-auditor-lambda-sg
            ├── Inbound:  NONE (Lambda is invoked by EventBridge, not network)
            └── Outbound: HTTPS (443) to 0.0.0.0/0
                         (needed for IAM + SSM API calls — these are
                          AWS-managed endpoints not reachable via Gateway endpoints)

Gateway VPC Endpoints (attached to private subnet route table):
├── com.amazonaws.us-east-1.s3        → free, routes S3 traffic privately
└── com.amazonaws.us-east-1.dynamodb  → free, routes DynamoDB traffic privately
```

**Note on IAM/SSM API calls:** IAM and SSM APIs are global/regional endpoints not reachable via Gateway VPC Endpoints. The Lambda security group allows HTTPS egress so these API calls can route through the VPC's internet-less path via AWS PrivateLink defaults. No NAT Gateway is needed — Lambda in a VPC with HTTPS egress can reach AWS service endpoints directly.

---

## 6. IAM Permissions (Least Privilege)

Lambda execution role policy — only the minimum actions required.

> **Note on `"Resource": "*"`:** Some IAM and Access Analyzer read actions do not support resource-level permissions — AWS requires `*` for those specific actions. Every wildcard below is explicitly justified. Where scoping is possible, specific ARN patterns are used.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadRequiresWildcard",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:GetServiceLastAccessedDetails"
      ],
      "Resource": "*",
      "_comment": "AWS does not support resource-level permissions for these actions"
    },
    {
      "Sid": "IAMReadScopedToUsersAndRoles",
      "Effect": "Allow",
      "Action": [
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:GenerateServiceLastAccessedDetails"
      ],
      "Resource": [
        "arn:aws:iam::*:user/*",
        "arn:aws:iam::*:role/*"
      ]
    },
    {
      "Sid": "AccessAnalyzerRequiresWildcard",
      "Effect": "Allow",
      "Action": "access-analyzer:ListAnalyzers",
      "Resource": "*",
      "_comment": "AWS does not support resource-level permissions for ListAnalyzers"
    },
    {
      "Sid": "AccessAnalyzerScopedToAnalyzer",
      "Effect": "Allow",
      "Action": "access-analyzer:ListFindings",
      "Resource": "arn:aws:access-analyzer:*:*:analyzer/*"
    },
    {
      "Sid": "DynamoDBWrite",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem", "dynamodb:BatchWriteItem"],
      "Resource": "arn:aws:dynamodb:*:*:table/iam-audit-findings"
    },
    {
      "Sid": "SNSPublish",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:*:*:iam-auditor-alerts"
    },
    {
      "Sid": "SSMRead",
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:*:*:parameter/iam-auditor/*"
    },
    {
      "Sid": "VPCNetworking",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/iam-auditor*"
    }
  ]
}
```

---

## 7. Detection Rules

| Rule ID | Data Source         | Condition                                                    | Severity |
| ------- | ------------------- | ------------------------------------------------------------ | -------- |
| R01     | IAM Access Analyzer | Any active external access finding                           | CRITICAL |
| R02     | Credential Report   | Root account access key exists                               | CRITICAL |
| R03     | Credential Report   | User has no MFA enabled                                      | HIGH     |
| R04     | IAM Policy Scan     | Inline policy contains `*` action on S3, IAM, EC2, or Lambda | HIGH     |
| R05     | Credential Report   | Access key not used in 90+ days                              | MEDIUM   |
| R06     | Credential Report   | Access key not rotated in 90+ days                           | MEDIUM   |
| R07     | Last Accessed API   | Role has no service activity in 90+ days                     | MEDIUM   |
| R08     | Credential Report   | User password not used in 90+ days                           | MEDIUM   |

---

## 8. Output: SNS Email Format

```
Subject: [IAM Auditor] Weekly Report — 2026-03-21

AWS IAM Audit Summary
=====================
Run ID:    run_20260321_080000
Account:   123456789012
Region:    us-east-1
Timestamp: 2026-03-21 08:00:00 UTC

FINDINGS BY SEVERITY
--------------------
CRITICAL : 2
HIGH     : 3
MEDIUM   : 7
TOTAL    : 12

CRITICAL FINDINGS
-----------------
[R01] External access found on S3 bucket policy via IAM Access Analyzer
      Resource: arn:aws:s3:::my-sensitive-bucket
      Detail:   Principal 987654321098 has s3:GetObject access

[R02] Root account access key exists
      Resource: root
      Detail:   Access key last used: 2026-01-15

Full findings stored in DynamoDB table: iam-audit-findings
Query by run_id: run_20260321_080000
```

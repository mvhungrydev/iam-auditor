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
│  ┌──────────────┐                                             │
│  │  EventBridge │                                             │
│  │  (weekly     │                                             │
│  │   cron)      │                                             │
│  └──────┬───────┘                                             │
│         │ trigger                                             │
│         ▼                                                     │
│  ┌──────────────────────────────────────────────────────┐     │
│  │          Lambda (Container — ECR image)              │     │
│  │          handler.py                                  │     │
│  └───┬──────────────────────────────────────────────────┘     │
│      │ calls public AWS APIs                                   │
│      │                                                        │
│  ┌───▼──────────────────────────────────────────────────┐     │
│  │                    AWS APIs                          │     │
│  │  IAM Access Analyzer  │  IAM Credential Report       │     │
│  │  IAM Last Accessed    │  SSM Parameter Store         │     │
│  └───────────────────────────────────────────────────── ┘     │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐   │
│  │              Outputs                                   │   │
│  │  ┌──────────────┐    ┌────────────────────────┐        │   │
│  │  │  DynamoDB    │    │  SNS → Email           │        │   │
│  │  │  (findings)  │    │  (weekly summary)      │        │   │
│  │  └──────────────┘    └────────────────────────┘        │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐   │
│  │              Config                                    │   │
│  │  ┌──────────────────────────────────────────┐          │   │
│  │  │  SSM Parameter Store (runtime config)    │          │   │
│  │  └──────────────────────────────────────────┘          │   │
│  └────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow

```
Step 1:  EventBridge cron fires every Monday 08:00 UTC
              │
Step 2:  Lambda container starts (ECR image pull via public ECR API)
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

## 5. IAM Permissions (Least Privilege)

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
      "Sid": "IAMReadScopedToUsersRolesAndPolicies",
      "Effect": "Allow",
      "Action": [
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": [
        "arn:aws:iam::*:user/*",
        "arn:aws:iam::*:role/*",
        "arn:aws:iam::*:policy/*"
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

## 6. Detection Rules

| Rule ID | Data Source | Condition | Severity | Remediation |
| ------- | ------------------- | -------------------------------------------------------| R01 | IAM Access Analyzer | Any active external access finding | CRITICAL | Remove the external principal from the resource policy |
------ | -------- | --------------------------------------------------------------------------- |
| R02 | Credential Report | Root account access key exists | CRITICAL | Delete the root access key immediately; use IAM users or roles instead |
| R03 | Credential Report | User has no MFA enabled | HIGH | Enable MFA on the user or remove console access |
| R04 | IAM Policy Scan | Inline policy contains `*` action on S3, IAM, EC2, or Lambda | HIGH | Replace wildcard actions with least-privilege permissions |
| R05 | Credential Report | Access key not used in 90+ days | MEDIUM | Deactivate or delete the unused access key |
| R06 | Credential Report | Access key not rotated in 90+ days | MEDIUM | Rotate the key: create a new key, update applications, delete the old key |
| R07 | Last Accessed API | Role has no service activity in 90+ days | MEDIUM | Delete or deactivate the unused role |
| R08 | Credential Report | User password not used in 90+ days | MEDIUM | Remove the console login profile or deactivate the user |
| R09 | IAM Policy Scan | Role inline policy contains `*` action on S3, IAM, EC2, or Lambda | HIGH | Replace wildcard actions with least-privilege permissions |
| R10 | IAM Policy Scan | Customer-managed policy attached to role contains `*` action on S3, IAM, EC2, or Lambda | HIGH | Remove the wildcard or detach the policy and replace with a scoped one |

### Why these severities?

**CRITICAL** — Immediate, unacceptable risk requiring same-day action:

- **R01**: A resource policy is actively granting access to an external party right now. Your data may already be exposed.
- **R02**: The root account has unlimited power and cannot be restricted by IAM policies. A leaked root key means total account compromise.

**HIGH** — Significant risk that increases attack surface:

- **R03**: A user without MFA can be taken over with just a stolen password. Console access without MFA is a single point of failure.
- **R04**: Wildcard actions on sensitive services (S3, IAM, EC2, Lambda) violate least-privilege and can allow privilege escalation.
- **R09**: Same risk as R04 but on roles. A role with `iam:*` can be assumed by any trusted principal and used to escalate privileges across the account.
- **R10**: Same risk as R09 but via an attached managed policy. The effective permissions are identical whether the wildcard is inline or managed. Managed policies are often overlooked because they are separate IAM objects, not visually embedded on the role.

**MEDIUM** — Hygiene issues that increase blast radius if another control fails:

- **R05**: An access key that has never been used is unnecessary credential exposure. If leaked, there is no usage baseline to detect abuse.
- **R06**: Long-lived keys that are never rotated give attackers an extended window if the key is ever compromised.
- **R07**: Unused roles are dead attack surface. If their trust policy is misconfigured, they can be assumed without being noticed.
- **R08**: A stale console password suggests an abandoned account — a forgotten user is often one with forgotten permissions.

---

## 7. Output: SNS Email Format

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

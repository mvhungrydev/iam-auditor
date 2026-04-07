# Value Proposition
## Project: IAM Auditor

**Version:** 1.0
**Date:** 2026-03-21

---

## 1. Why Not Just Use the AWS Console?

The AWS IAM console provides visibility into individual resources but is not designed for automated, repeatable auditing:

| Limitation | Impact |
|-----------|--------|
| Manual process — must be initiated every time | Audits get skipped; no consistency |
| No historical record | Cannot track posture improvement or regression over time |
| No automated alerting | Issues go unnoticed until the next manual review |
| Not auditable | No evidence of when audits were performed or who reviewed findings |
| Does not scale | Reviewing hundreds of roles and policies manually takes hours |

---

## 2. Why Not AWS Security Hub?

AWS Security Hub aggregates security findings across services and supports IAM standards. However:

| Factor | Detail |
|--------|--------|
| Cost | $0.0010 per finding after a 30-day free trial. At enterprise scale, thousands of findings per month = real cost |
| Overkill for a single account | Security Hub is designed for multi-account, multi-region environments |
| No custom rules | Cannot encode organization-specific IAM policies (e.g. naming standards, approved trust relationships) |
| Dependency on AWS Config | Full coverage requires AWS Config enabled — $0.003 per configuration item recorded |

**The IAM Auditor achieves the same core outcome at $0/month using native free APIs.**

---

## 3. Why Not AWS Trusted Advisor?

Trusted Advisor includes IAM checks (exposed access keys, MFA on root, etc.) but:

| Limitation | Detail |
|-----------|--------|
| Full checks require paid support | Business or Enterprise support plan ($100+/month) unlocks all security checks |
| Free tier is limited | Only 7 core checks available on free plan — misses most IAM scenarios |
| No custom logic | Cannot add checks specific to your account's policies or standards |
| No programmatic integration | Hard to feed findings into downstream systems (DynamoDB, SNS pipelines) |

---

## 4. What This Project Builds on Top of Native Tools

Rather than re-implementing what AWS already provides, the IAM Auditor **orchestrates and operationalizes** three free native AWS APIs:

```
IAM Access Analyzer API  →  External access findings (already computed by AWS)
IAM Credential Report    →  User hygiene: MFA, key age, last activity
IAM Last Accessed API    →  Role activity: unused roles aged out
```

**The value added:**

| Capability | How |
|-----------|-----|
| Single aggregated report | Combines 3 separate data sources into one finding set |
| Custom severity logic | Business rules applied to findings (e.g. 90-day threshold is configurable) |
| Automated delivery | EventBridge → Lambda → SNS email, zero manual steps |
| Historical trending | DynamoDB stores every run — visualize posture over time |
| Version-controlled rules | Detection logic in Git — reviewable, auditable, changeable via PR |
| Reproducible infrastructure | `terraform apply` rebuilds everything from scratch |

---

## 5. Portfolio Value

This project directly demonstrates the skills listed in the target job description:

| Job Requirement | How This Project Demonstrates It |
|----------------|----------------------------------|
| Terraform / IaC | Full infrastructure provisioned via Terraform modules |
| CI/CD (GitHub Actions) | Security-gated pipeline: gitleaks, bandit, checkov, trivy |
| AWS Lambda | Container-based Lambda with Python handler entry point |
| IAM & secrets management | Least-privilege IAM role, SSM Parameter Store for all config |
| Python scripting | Boto3-based handler calling multiple AWS APIs |
| CloudWatch / monitoring | Lambda execution metrics, EventBridge scheduling |
| Container technologies | Lambda deployed as Docker container via ECR |
| VPC networking | VPC with public/private subnets and Gateway VPC Endpoints (S3, DynamoDB) |
| Security best practices | OIDC auth in CI/CD, no long-lived keys, least-privilege IAM |

---

## 6. Interview Talking Points

- "I built the orchestration layer on top of IAM Access Analyzer, Credential Report, and Last Accessed APIs — rather than reinventing detection logic, I operationalized what AWS already computes for free."
- "The Lambda runs as a container image deployed via a security-gated CI/CD pipeline — every deploy is scanned with Bandit, Trivy, Checkov, and Gitleaks before it reaches production."
- "All infrastructure is Terraform-managed. A new engineer can run `terraform apply` against a blank AWS account and have the full system running in under 5 minutes."
- "No long-lived AWS credentials anywhere — CI/CD authenticates via GitHub OIDC to an IAM role, and the Lambda uses an IAM execution role. Zero stored secrets."

# Business Requirements Document
## Project: IAM Auditor
**Version:** 1.0
**Date:** 2026-03-21
**Author:** Portfolio Project — AWS DevOps Engineer

---

## 1. Problem Statement

AWS Identity and Access Management (IAM) sprawl is one of the leading causes of cloud security incidents. As AWS accounts grow, IAM users, roles, and policies accumulate — many becoming unused, overly permissive, or misconfigured. Without automated oversight:

- Unused access keys and roles remain active indefinitely, creating attack surface
- Policies with wildcard (`*`) permissions violate the principle of least privilege
- Root account usage goes undetected
- Users without MFA are exposed to credential-based attacks
- Security teams have no consistent, repeatable view of IAM posture over time

Manual auditing via the AWS console is slow, error-prone, inconsistent, and produces no audit trail.

---

## 2. Goals

| # | Goal |
|---|------|
| G1 | Automatically audit the AWS account's IAM posture on a weekly schedule |
| G2 | Deliver actionable findings via email (SNS) with severity levels |
| G3 | Store all findings in DynamoDB for historical trend analysis |
| G4 | Require zero manual effort after initial deployment |
| G5 | Operate entirely within the AWS Free Tier |
| G6 | Serve as a portfolio artifact demonstrating DevOps and security engineering skills |

---

## 3. Stakeholders

| Role | Responsibility |
|------|---------------|
| DevOps Engineer | Builds, deploys, and maintains the auditor |
| Security / Compliance Team | Consumes weekly findings report, drives remediation |
| AWS Account Owner | Subscribes to SNS topic, receives critical alerts |

---

## 4. Scope

### In Scope
- IAM users: MFA status, access key age, last activity
- IAM roles: last activity, trust policy analysis
- IAM policies: inline policies with wildcard actions on sensitive services
- Root account: access key existence, recent usage
- IAM Access Analyzer: external access findings

### Out of Scope
- Cross-account auditing
- AWS Organizations / Service Control Policies
- Automated remediation (detection and reporting only)
- Real-time alerting (weekly batch only)
- Third-party identity providers (Okta, Azure AD)

---

## 5. Functional Requirements

| ID | Requirement |
|----|-------------|
| FR1 | System SHALL run automatically every Monday at 08:00 UTC |
| FR2 | System SHALL query IAM Access Analyzer for external access findings |
| FR3 | System SHALL generate and parse the IAM Credential Report |
| FR4 | System SHALL query IAM Last Accessed data for all roles |
| FR5 | System SHALL assign severity (CRITICAL / HIGH / MEDIUM) to each finding |
| FR6 | System SHALL write all findings to DynamoDB with a 90-day TTL |
| FR7 | System SHALL publish a summary report to an SNS email subscription |
| FR8 | System SHALL be triggerable manually (on-demand invocation) |

---

## 6. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR1 | All AWS resources MUST remain within the AWS Free Tier |
| NFR2 | Lambda execution MUST complete within 60 seconds |
| NFR3 | No credentials SHALL be hardcoded — all config via SSM Parameter Store |
| NFR4 | All infrastructure MUST be defined as code (Terraform) |
| NFR5 | All deployments MUST pass security scan gates in CI/CD before reaching production |
| NFR6 | Lambda MUST run as a container image (not a zip deployment) |
| NFR7 | IAM role for Lambda MUST follow least-privilege (no `iam:*`) |

---

## 7. Severity Definitions

| Severity | Description | Examples |
|----------|-------------|---------|
| CRITICAL | Immediate risk, requires urgent attention | Root access key exists, IAM Access Analyzer external finding |
| HIGH | Significant risk, remediate within 1 week | User with no MFA, inline policy with `*` on sensitive service |
| MEDIUM | Elevated risk, remediate within 30 days | Access key unused 90+ days, role with no activity 90+ days |

---

## 8. Success Criteria

- [ ] Weekly SNS email received with zero manual intervention
- [ ] All findings queryable in DynamoDB by severity and date
- [ ] Full deployment reproducible from a clean AWS account via `terraform apply`
- [ ] CI/CD pipeline blocks deploy on any HIGH or CRITICAL security scan finding
- [ ] Zero hardcoded credentials in codebase or container image

# AWS API Samples — Credential Report Auditor

Two API calls. The first starts an async report generation job; the
second fetches the result as a CSV.

---

## 1. iam:GenerateCredentialReport

Tells AWS to build the credential report for the account. AWS compiles
it in the background — on a real account this may take several seconds.
The auditor polls this call until `State == COMPLETE`.

**Request**
```python
iam.generate_credential_report()
```

**Response — report still generating**
```json
{
  "State": "STARTED",
  "Description": "No report exists. Starting a new report generation task"
}
```

**Response — report ready**
```json
{
  "State": "COMPLETE",
  "Description": "No report exists. Starting a new report generation task"
}
```

**What the auditor uses:** `State` — loop until `COMPLETE`.

---

## 2. iam:GetCredentialReport

Fetches the completed CSV report. `Content` is returned as a `bytes`
object by boto3 — the auditor decodes it to a UTF-8 string and parses
it with `csv.DictReader`.

**Request**
```python
iam.get_credential_report()
```

**Response**
```json
{
  "Content": "<bytes — decoded CSV shown below>",
  "ReportFormat": "text/csv",
  "GeneratedTime": "2026-03-25T08:00:00+00:00"
}
```

**Decoded CSV content**
```
user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service
<root_account>,arn:aws:iam::123456789012:root,2023-01-01T00:00:00+00:00,not_supported,2026-03-01T10:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A
alice,arn:aws:iam::123456789012:user/alice,2024-06-01T00:00:00+00:00,true,2026-03-20T09:00:00+00:00,2025-01-01T00:00:00+00:00,N/A,false,true,2024-06-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A
bob,arn:aws:iam::123456789012:user/bob,2023-09-15T00:00:00+00:00,true,N/A,2023-09-15T00:00:00+00:00,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A
```

**Key columns and their values**

| Column | Possible values | Notes |
|---|---|---|
| `user` | string or `<root_account>` | Root row is identified by `<root_account>` |
| `password_enabled` | `true`, `false`, `not_supported` | `not_supported` on the root row |
| `password_last_used` | ISO 8601 date or `N/A` | `N/A` = password never used |
| `mfa_active` | `true`, `false` | |
| `access_key_1_active` | `true`, `false` | |
| `access_key_1_last_rotated` | ISO 8601 date or `N/A` | `N/A` = key never existed |
| `access_key_1_last_used_date` | ISO 8601 date or `N/A` | `N/A` = key never used |
| `access_key_2_active` | `true`, `false` | |

---

## Rule Logic

| Rule | Condition | Severity |
|---|---|---|
| R02 | `user == "<root_account>"` AND `access_key_1_active == "true"` or `access_key_2_active == "true"` | CRITICAL |
| R03 | `password_enabled == "true"` AND `mfa_active == "false"` | HIGH |
| R05 | `access_key_1_active == "true"` AND `access_key_1_last_used_date` is `N/A` or > `unused_days` ago | MEDIUM |
| R06 | `access_key_1_active == "true"` AND `access_key_1_last_rotated` > `unused_days` ago | MEDIUM |
| R08 | `password_enabled == "true"` AND `password_last_used` is `N/A` or > `unused_days` ago | MEDIUM |

The root row (`<root_account>`) is checked for R02 only — it is skipped
for all other rules via an early `continue`.

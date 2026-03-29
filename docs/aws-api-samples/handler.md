# AWS API Samples — Handler

Five API calls, in order of execution.

---

## 1. ssm:GetParameter — SNS topic ARN

**Request**
```python
ssm.get_parameter(Name="/iam-auditor/sns-topic-arn")
```

**Response**
```json
{
  "Parameter": {
    "Name": "/iam-auditor/sns-topic-arn",
    "Value": "arn:aws:sns:us-east-1:123456789012:iam-auditor-alerts",
    "Type": "String"
  }
}
```

**What the handler uses:** `Parameter.Value` — the SNS topic ARN to publish to.

---

## 2. ssm:GetParameter — DynamoDB table name

**Request**
```python
ssm.get_parameter(Name="/iam-auditor/dynamodb-table-name")
```

**Response**
```json
{
  "Parameter": {
    "Name": "/iam-auditor/dynamodb-table-name",
    "Value": "iam-audit-findings",
    "Type": "String"
  }
}
```

**What the handler uses:** `Parameter.Value` — the table to write findings to.

---

## 3. ssm:GetParameter — unused days threshold

**Request**
```python
ssm.get_parameter(Name="/iam-auditor/unused-days-threshold")
```

**Response**
```json
{
  "Parameter": {
    "Name": "/iam-auditor/unused-days-threshold",
    "Value": "90",
    "Type": "String"
  }
}
```

**What the handler uses:** `Parameter.Value` — converted to `int` before passing
to `credential_report.run` and `last_accessed.run`.

---

## 4. dynamodb:PutItem — write each finding

Called once per finding. The handler iterates the combined findings list and
calls `put_item` for each one.

**Request**
```python
table.put_item(Item={
    "run_id": "3f1e7b2a-...",
    "finding_id": "9c4d8e1f-...",
    "rule_id": "R03",
    "severity": "HIGH",
    "resource_arn": "arn:aws:iam::123456789012:user/no-mfa-user",
    "detail": "User 'no-mfa-user' has a console password but no MFA device registered.",
    "data_source": "credential_report",
    "created_at": "2026-03-28T12:00:00+00:00",
    "expires_at": 1758081600
})
```

**Response:** empty dict `{}` on success.

**What the handler uses:** nothing — a failed `put_item` raises an exception.

---

## 5. sns:Publish — weekly report summary

Called once per run after all findings are written.

**Request**
```python
sns.publish(
    TopicArn="arn:aws:sns:us-east-1:123456789012:iam-auditor-alerts",
    Subject="[IAM Auditor] Weekly Report — 2026-03-28",
    Message="Run ID: 3f1e7b2a-...\nTotal: 4\nCritical: 1\nHigh: 2\nMedium: 1"
)
```

**Response**
```json
{
  "MessageId": "a1b2c3d4-1234-5678-abcd-example11111"
}
```

**What the handler uses:** nothing — a failed `publish` raises an exception.
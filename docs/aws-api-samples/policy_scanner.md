# AWS API Samples — Policy Scanner Auditor

Nine API calls across three rule groups. Each group has its own API
chain. All list calls are paginated.

---

## Rule R04 — User Inline Policies

### 1. iam:ListUsers (paginated)

**Request**
```python
iam.list_users()
# paginated via get_paginator("list_users")
```

**Response**
```json
{
  "Users": [
    {
      "UserName": "alice",
      "UserId": "AIDAEXAMPLEID",
      "Arn": "arn:aws:iam::123456789012:user/alice",
      "Path": "/",
      "CreateDate": "2024-06-01T00:00:00+00:00"
    }
  ],
  "IsTruncated": false
}
```

**What the auditor uses:** `User.UserName`, `User.Arn`

---

### 2. iam:ListUserPolicies

Returns the names of inline policies attached directly to the user.
Returns an empty list if the user has no inline policies — auditor
skips the user in that case.

**Request**
```python
iam.list_user_policies(UserName="alice")
```

**Response — user has inline policies**
```json
{
  "PolicyNames": ["DangerousPolicy", "ReadOnlyPolicy"],
  "IsTruncated": false
}
```

**Response — user has no inline policies**
```json
{
  "PolicyNames": [],
  "IsTruncated": false
}
```

**What the auditor uses:** `PolicyNames` — iterates each name.

---

### 3. iam:GetUserPolicy

Fetches the full JSON document for one inline policy. boto3 returns
`PolicyDocument` as a parsed dict.

**Request**
```python
iam.get_user_policy(UserName="alice", PolicyName="DangerousPolicy")
```

**Response — wildcard action (triggers R04)**
```json
{
  "UserName": "alice",
  "PolicyName": "DangerousPolicy",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
}
```

**Response — service wildcard (triggers R04)**
```json
{
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "*"
      }
    ]
  }
}
```

**Response — scoped action (no finding)**
```json
{
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::my-bucket/*"
      }
    ]
  }
}
```

**Response — Deny wildcard (no finding)**
```json
{
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
}
```

**What the auditor uses:** `PolicyDocument.Statement[*].Effect` and
`PolicyDocument.Statement[*].Action`

---

## Rule R09 — Role Inline Policies

Same API chain as R04, but targeting roles instead of users.

### 4. iam:ListRoles (paginated)

Same response shape as in last_accessed.md. **What the auditor uses:**
`Role.RoleName`, `Role.Arn`

---

### 5. iam:ListRolePolicies

**Request**
```python
iam.list_role_policies(RoleName="my-role")
```

**Response**
```json
{
  "PolicyNames": ["DangerousRolePolicy"],
  "IsTruncated": false
}
```

---

### 6. iam:GetRolePolicy

**Request**
```python
iam.get_role_policy(RoleName="my-role", PolicyName="DangerousRolePolicy")
```

**Response**
```json
{
  "RoleName": "my-role",
  "PolicyName": "DangerousRolePolicy",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "iam:*",
        "Resource": "*"
      }
    ]
  }
}
```

**What the auditor uses:** Same as R04 — `Statement[*].Effect` and
`Statement[*].Action`

---

## Rule R10 — Customer-Managed Policies Attached to Roles

Managed policies are standalone IAM objects with their own ARN and
version history. They require a two-step fetch: first get the active
version ID, then fetch the versioned document.

### 7. iam:ListAttachedRolePolicies

Returns managed policies attached to a role. Includes both
AWS-managed and customer-managed policies — the auditor skips any ARN
starting with `arn:aws:iam::aws:`.

**Request**
```python
iam.list_attached_role_policies(RoleName="my-role")
```

**Response**
```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "AmazonS3ReadOnlyAccess",
      "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    },
    {
      "PolicyName": "DangerousManagedPolicy",
      "PolicyArn": "arn:aws:iam::123456789012:policy/DangerousManagedPolicy"
    }
  ],
  "IsTruncated": false
}
```

**What the auditor uses:** `PolicyArn` (skip if starts with
`arn:aws:iam::aws:`), `PolicyName`

---

### 8. iam:GetPolicy

Fetches metadata for a managed policy — specifically `DefaultVersionId`,
which identifies the currently active version.

**Request**
```python
iam.get_policy(PolicyArn="arn:aws:iam::123456789012:policy/DangerousManagedPolicy")
```

**Response**
```json
{
  "Policy": {
    "PolicyName": "DangerousManagedPolicy",
    "PolicyId": "ANPAEXAMPLEID",
    "Arn": "arn:aws:iam::123456789012:policy/DangerousManagedPolicy",
    "DefaultVersionId": "v1",
    "AttachmentCount": 1,
    "CreateDate": "2024-01-01T00:00:00+00:00",
    "UpdateDate": "2024-01-01T00:00:00+00:00"
  }
}
```

**What the auditor uses:** `Policy.DefaultVersionId`

---

### 9. iam:GetPolicyVersion

Fetches the actual policy document for the active version.

**Request**
```python
iam.get_policy_version(
    PolicyArn="arn:aws:iam::123456789012:policy/DangerousManagedPolicy",
    VersionId="v1"
)
```

**Response — wildcard action (triggers R10)**
```json
{
  "PolicyVersion": {
    "Document": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "s3:*",
          "Resource": "*"
        }
      ]
    },
    "VersionId": "v1",
    "IsDefaultVersion": true,
    "CreateDate": "2024-01-01T00:00:00+00:00"
  }
}
```

**What the auditor uses:** `PolicyVersion.Document` — same
`Statement[*].Effect` / `Statement[*].Action` check as R04 and R09.

---

## Wildcard Detection Logic

The auditor uses `_is_wildcard_action(action)` to flag two forms:

| Action value | Flagged? | Reason |
|---|---|---|
| `"*"` | Yes | Full wildcard — every action on every service |
| `"s3:*"` | Yes | Service wildcard on a sensitive service |
| `"iam:*"` | Yes | Service wildcard on a sensitive service |
| `"ec2:*"` | Yes | Service wildcard on a sensitive service |
| `"lambda:*"` | Yes | Service wildcard on a sensitive service |
| `"s3:GetObject"` | No | Scoped action |
| `"ec2:DescribeInstances"` | No | Scoped action |
| `"sqs:*"` | No | SQS is not in SENSITIVE_SERVICES |

Sensitive services: `s3`, `iam`, `ec2`, `lambda`

`Effect: Deny` statements are never flagged — a Deny wildcard restricts
access, it does not grant it.

---

## Rule Summary

| Rule | Principal | Policy type | Severity |
|---|---|---|---|
| R04 | IAM user | Inline | HIGH |
| R09 | IAM role | Inline | HIGH |
| R10 | IAM role | Customer-managed (attached) | HIGH |

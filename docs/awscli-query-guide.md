# AWS CLI Query Guide

## Project: IAM Auditor — LocalStack Examples

This guide shows how to use `--query` (JMESPath) with the AWS CLI against your LocalStack-deployed
IAM Auditor resources. Each example shows:

1. The raw command (no `--query`) and its full JSON response
2. The problem with the raw output
3. The shaped command with `--query` and its clean output
4. An explanation of what the query expression does

All commands use `awslocal` — the LocalStack-aware wrapper for the AWS CLI.
Swap `awslocal` for `aws` when running against real AWS.

**Prerequisites:** LocalStack running (`localstack start`) and infrastructure deployed (`tflocal apply`).

---

## Table of Contents

1. [EC2 — VPCs](#1-ec2--vpcs)
2. [EC2 — Subnets](#2-ec2--subnets)
3. [EC2 — Security Groups](#3-ec2--security-groups)
4. [IAM — Roles](#4-iam--roles)
5. [IAM — Users (Demo Data)](#5-iam--users-demo-data)
6. [IAM — Policies](#6-iam--policies)
7. [Lambda — Functions](#7-lambda--functions)
8. [DynamoDB — Tables](#8-dynamodb--tables)
9. [SNS — Topics and Subscriptions](#9-sns--topics-and-subscriptions)
10. [SSM — Parameter Store](#10-ssm--parameter-store)
11. [ECR — Repositories](#11-ecr--repositories)
12. [Combining Filters and Queries](#12-combining-filters-and-queries)

---

## 1. EC2 — VPCs

### Raw Command

```bash
awslocal ec2 describe-vpcs
```

### Raw Output

```json
{
    "Vpcs": [
        {
            "CidrBlock": "172.31.0.0/16",
            "DhcpOptionsId": "dopt-a1b2c3d4",
            "State": "available",
            "VpcId": "vpc-11111111",
            "OwnerId": "000000000000",
            "InstanceTenancy": "default",
            "IsDefault": true,
            "Tags": []
        },
        {
            "CidrBlock": "10.0.0.0/16",
            "DhcpOptionsId": "dopt-b2c3d4e5",
            "State": "available",
            "VpcId": "vpc-22222222",
            "OwnerId": "000000000000",
            "InstanceTenancy": "default",
            "IsDefault": false,
            "Tags": [
                { "Key": "Name",        "Value": "iam-auditor-vpc" },
                { "Key": "Project",     "Value": "iam-auditor" },
                { "Key": "Environment", "Value": "dev" },
                { "Key": "ManagedBy",   "Value": "terraform" }
            ]
        }
    ]
}
```

**Problem:** Two VPCs returned (default + yours). Full objects with fields you don't need.

---

### Query 1 — All CIDR blocks

```bash
awslocal ec2 describe-vpcs \
  --query 'Vpcs[*].CidrBlock'
```

**Output:**
```json
[
    "172.31.0.0/16",
    "10.0.0.0/16"
]
```

**Expression breakdown:**
- `Vpcs[*]` — iterate over every VPC in the array
- `.CidrBlock` — pluck that one field from each

---

### Query 2 — Only your project VPC (filter by tag)

```bash
awslocal ec2 describe-vpcs \
  --query 'Vpcs[?Tags[?Key==`Name` && Value==`iam-auditor-vpc`]].{ID:VpcId, CIDR:CidrBlock}'
```

**Output:**
```json
[
    {
        "ID": "vpc-22222222",
        "CIDR": "10.0.0.0/16"
    }
]
```

**Expression breakdown:**
- `[?Tags[?Key==`Name` && Value==`iam-auditor-vpc`]]` — filter to VPCs where a tag matches
- `.{ID:VpcId, CIDR:CidrBlock}` — reshape: rename `VpcId` → `ID`, `CidrBlock` → `CIDR`

---

### Query 3 — Skip the default VPC

```bash
awslocal ec2 describe-vpcs \
  --query 'Vpcs[?IsDefault==`false`].{ID:VpcId, CIDR:CidrBlock, Name:Tags[?Key==`Name`].Value|[0]}'
```

**Output:**
```json
[
    {
        "ID": "vpc-22222222",
        "CIDR": "10.0.0.0/16",
        "Name": "iam-auditor-vpc"
    }
]
```

**Expression breakdown:**
- `[?IsDefault==`false`]` — filter out the default VPC
- `Tags[?Key==`Name`].Value|[0]` — find the tag where Key is "Name", get its Value, pipe to `[0]` to unwrap the single-item array into a string

---

## 2. EC2 — Subnets

### Raw Command

```bash
awslocal ec2 describe-subnets
```

### Raw Output (truncated)

```json
{
    "Subnets": [
        {
            "AvailabilityZone": "us-east-1a",
            "AvailabilityZoneId": "use1-az1",
            "AvailableIpAddressCount": 251,
            "CidrBlock": "10.0.1.0/24",
            "DefaultForAz": false,
            "MapPublicIpOnLaunch": false,
            "State": "available",
            "SubnetId": "subnet-aaaaaaaa",
            "VpcId": "vpc-22222222",
            "OwnerId": "000000000000",
            "AssignIpv6AddressOnCreation": false,
            "Ipv6CidrBlockAssociationSet": [],
            "Tags": [
                { "Key": "Name",        "Value": "iam-auditor-public-subnet" },
                { "Key": "Project",     "Value": "iam-auditor" },
                { "Key": "Environment", "Value": "dev" },
                { "Key": "ManagedBy",   "Value": "terraform" }
            ],
            "SubnetArn": "arn:aws:ec2:us-east-1:000000000000:subnet/subnet-aaaaaaaa"
        },
        {
            "AvailabilityZone": "us-east-1a",
            "CidrBlock": "10.0.2.0/24",
            "DefaultForAz": false,
            "State": "available",
            "SubnetId": "subnet-bbbbbbbb",
            "VpcId": "vpc-22222222",
            "Tags": [
                { "Key": "Name",        "Value": "iam-auditor-private-subnet" },
                { "Key": "Project",     "Value": "iam-auditor" },
                { "Key": "Environment", "Value": "dev" },
                { "Key": "ManagedBy",   "Value": "terraform" }
            ]
        }
    ]
}
```

**Problem:** Every subnet returned with ~15 fields each. You just want ID, CIDR, and name.

---

### Query — Subnet summary table

```bash
awslocal ec2 describe-subnets \
  --query 'Subnets[*].{Name:Tags[?Key==`Name`].Value|[0], ID:SubnetId, CIDR:CidrBlock}' \
  --output table
```

**Output:**
```
---------------------------------------------------------------
|                      DescribeSubnets                        |
+------------------------+-------------------+----------------+
|          CIDR          |        ID         |      Name      |
+------------------------+-------------------+----------------+
|  10.0.1.0/24           |  subnet-aaaaaaaa  |  iam-auditor-public-subnet  |
|  10.0.2.0/24           |  subnet-bbbbbbbb  |  iam-auditor-private-subnet |
+------------------------+-------------------+----------------+
```

**Expression breakdown:**
- `Subnets[*]` — iterate all subnets
- `{Name:..., ID:SubnetId, CIDR:CidrBlock}` — build a new object with renamed keys
- `--output table` — render as an ASCII table instead of JSON

---

## 3. EC2 — Security Groups

### Raw Command

```bash
awslocal ec2 describe-security-groups
```

### Raw Output (truncated)

```json
{
    "SecurityGroups": [
        {
            "Description": "Lambda security group — no inbound, HTTPS egress only",
            "GroupName": "iam-auditor-lambda-sg",
            "IpPermissions": [],
            "OwnerId": "000000000000",
            "GroupId": "sg-cccccccc",
            "IpPermissionsEgress": [
                {
                    "FromPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        { "CidrIp": "0.0.0.0/0", "Description": "HTTPS egress for AWS API calls" }
                    ],
                    "ToPort": 443
                }
            ],
            "VpcId": "vpc-22222222",
            "Tags": [
                { "Key": "Name", "Value": "iam-auditor-lambda-sg" }
            ]
        }
    ]
}
```

---

### Query — Security group ID and description

```bash
awslocal ec2 describe-security-groups \
  --query 'SecurityGroups[*].{Name:GroupName, ID:GroupId, Description:Description}' \
  --output table
```

**Output:**
```
---------------------------------------------------------------------------
|                       DescribeSecurityGroups                            |
+-------------------------------------------+-------------+--------------+
|                Description                |     ID      |     Name     |
+-------------------------------------------+-------------+--------------+
|  Lambda security group — no inbound...    | sg-cccccccc | iam-auditor-lambda-sg |
+-------------------------------------------+-------------+--------------+
```

---

### Query — Verify no inbound rules on Lambda SG

```bash
awslocal ec2 describe-security-groups \
  --query 'SecurityGroups[?GroupName==`iam-auditor-lambda-sg`].{Inbound:IpPermissions, Outbound:IpPermissionsEgress}'
```

**Output:**
```json
[
    {
        "Inbound": [],
        "Outbound": [
            {
                "FromPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [{ "CidrIp": "0.0.0.0/0" }],
                "ToPort": 443
            }
        ]
    }
]
```

**Why this matters:** Confirms the Lambda security group has zero inbound rules (correct) and only port 443 outbound (correct). Quick security posture check.

---

## 4. IAM — Roles

### Raw Command

```bash
awslocal iam list-roles
```

### Raw Output (truncated to two roles)

```json
{
    "Roles": [
        {
            "Path": "/",
            "RoleName": "iam-auditor-lambda-role",
            "RoleId": "AROA000000000000000001",
            "Arn": "arn:aws:iam::000000000000:role/iam-auditor-lambda-role",
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{ "Effect": "Allow", "Principal": { "Service": "lambda.amazonaws.com" }, "Action": "sts:AssumeRole" }]
            },
            "Description": "",
            "MaxSessionDuration": 3600,
            "Tags": [{ "Key": "Name", "Value": "iam-auditor-lambda-role" }]
        },
        {
            "Path": "/",
            "RoleName": "demo-wildcard-inline-role",
            "RoleId": "AROA000000000000000002",
            "Arn": "arn:aws:iam::000000000000:role/demo-wildcard-inline-role",
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "AssumeRolePolicyDocument": { "..." : "..." },
            "Tags": [{ "Key": "demo", "Value": "true" }]
        },
        {
            "Path": "/",
            "RoleName": "demo-wildcard-managed-role",
            "RoleId": "AROA000000000000000003",
            "Arn": "arn:aws:iam::000000000000:role/demo-wildcard-managed-role",
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "AssumeRolePolicyDocument": { "..." : "..." },
            "Tags": [{ "Key": "demo", "Value": "true" }]
        },
        {
            "Path": "/",
            "RoleName": "demo-unused-role",
            "RoleId": "AROA000000000000000004",
            "Arn": "arn:aws:iam::000000000000:role/demo-unused-role",
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "AssumeRolePolicyDocument": { "..." : "..." },
            "Tags": [{ "Key": "demo", "Value": "true" }]
        }
    ],
    "IsTruncated": false
}
```

**Problem:** Full policy documents embedded, many fields, hard to scan.

---

### Query 1 — All role names and ARNs

```bash
awslocal iam list-roles \
  --query 'Roles[*].{Name:RoleName, ARN:Arn}' \
  --output table
```

**Output:**
```
-----------------------------------------------------------------------
|                            ListRoles                                |
+------------------------------+--------------------------------------+
|             ARN              |               Name                   |
+------------------------------+--------------------------------------+
|  arn:aws:iam::000000000000:role/iam-auditor-lambda-role   | iam-auditor-lambda-role     |
|  arn:aws:iam::000000000000:role/iam-auditor-cicd-role     | iam-auditor-cicd-role       |
|  arn:aws:iam::000000000000:role/demo-wildcard-inline-role | demo-wildcard-inline-role   |
|  arn:aws:iam::000000000000:role/demo-wildcard-managed-role| demo-wildcard-managed-role  |
|  arn:aws:iam::000000000000:role/demo-unused-role          | demo-unused-role            |
+------------------------------+--------------------------------------+
```

---

### Query 2 — Only demo roles (filter by tag)

```bash
awslocal iam list-roles \
  --query 'Roles[?Tags[?Key==`demo` && Value==`true`]].RoleName' \
  --output text
```

**Output:**
```
demo-wildcard-inline-role
demo-wildcard-managed-role
demo-unused-role
```

**Expression breakdown:**
- `[?Tags[?Key==`demo` && Value==`true`]]` — filter to roles where the `demo=true` tag exists
- `.RoleName` — return only the name string
- `--output text` — plain text, one per line (great for shell scripts)

---

### Query 3 — Get a specific role's ARN (for use in other commands)

```bash
awslocal iam list-roles \
  --query 'Roles[?RoleName==`iam-auditor-lambda-role`].Arn|[0]' \
  --output text
```

**Output:**
```
arn:aws:iam::000000000000:role/iam-auditor-lambda-role
```

**Expression breakdown:**
- `[?RoleName==`iam-auditor-lambda-role`]` — filter to the exact role
- `.Arn` — get the ARN field
- `|[0]` — pipe the single-item array to get a plain string (not `["arn:..."]`)
- `--output text` — no quotes around the result

---

## 5. IAM — Users (Demo Data)

### Raw Command

```bash
awslocal iam list-users
```

### Raw Output

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "demo-no-mfa-user",
            "UserId": "AIDA000000000000000001",
            "Arn": "arn:aws:iam::000000000000:user/demo-no-mfa-user",
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "PasswordLastUsed": "2026-01-01T00:00:00+00:00",
            "Tags": [
                { "Key": "Name", "Value": "demo-no-mfa-user" },
                { "Key": "demo", "Value": "true" }
            ]
        },
        {
            "Path": "/",
            "UserName": "demo-stale-key-user",
            "UserId": "AIDA000000000000000002",
            "Arn": "arn:aws:iam::000000000000:user/demo-stale-key-user",
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "Tags": [
                { "Key": "Name", "Value": "demo-stale-key-user" },
                { "Key": "demo", "Value": "true" }
            ]
        }
    ],
    "IsTruncated": false
}
```

---

### Query 1 — User names and creation dates

```bash
awslocal iam list-users \
  --query 'Users[*].{User:UserName, Created:CreateDate}' \
  --output table
```

**Output:**
```
----------------------------------------------------------
|                        ListUsers                       |
+----------------------------+---------------------------+
|          Created           |           User            |
+----------------------------+---------------------------+
|  2026-04-04T10:00:00+00:00 |  demo-no-mfa-user         |
|  2026-04-04T10:00:00+00:00 |  demo-stale-key-user      |
+----------------------------+---------------------------+
```

---

### Query 2 — Users who have never logged in (no PasswordLastUsed)

```bash
awslocal iam list-users \
  --query 'Users[?!PasswordLastUsed].UserName' \
  --output text
```

**Output:**
```
demo-stale-key-user
```

**Expression breakdown:**
- `[?!PasswordLastUsed]` — filter to users where `PasswordLastUsed` is null/missing
- The `!` is a boolean negation — `null` is falsy, so `!null` is `true`

**Why this matters:** This is exactly what rule R05 (unused console password) checks for.

---

### Query 3 — List access keys for a user

```bash
awslocal iam list-access-keys \
  --user-name demo-stale-key-user \
  --query 'AccessKeyMetadata[*].{Key:AccessKeyId, Status:Status, Created:CreateDate}'
```

**Output:**
```json
[
    {
        "Key": "AKIA000000000000DEMO1",
        "Status": "Active",
        "Created": "2026-04-04T10:00:00+00:00"
    }
]
```

**Why this matters:** This is what rule R06/R08 checks — active keys that haven't been used or rotated.

---

## 6. IAM — Policies

### Raw Command

```bash
awslocal iam list-policies --scope Local
```

> `--scope Local` returns only customer-managed policies (not the hundreds of AWS-managed ones).

### Raw Output

```json
{
    "Policies": [
        {
            "PolicyName": "iam-auditor-lambda-policy",
            "PolicyId": "ANPA000000000000000001",
            "Arn": "arn:aws:iam::000000000000:policy/iam-auditor-lambda-policy",
            "Path": "/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 1,
            "PermissionsBoundaryUsageCount": 0,
            "IsAttachable": true,
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "UpdateDate": "2026-04-04T10:00:00+00:00",
            "Tags": []
        },
        {
            "PolicyName": "demo-wildcard-iam-policy",
            "PolicyId": "ANPA000000000000000002",
            "Arn": "arn:aws:iam::000000000000:policy/demo-wildcard-iam-policy",
            "Path": "/",
            "DefaultVersionId": "v1",
            "AttachmentCount": 1,
            "IsAttachable": true,
            "CreateDate": "2026-04-04T10:00:00+00:00",
            "UpdateDate": "2026-04-04T10:00:00+00:00",
            "Tags": [{ "Key": "demo", "Value": "true" }]
        }
    ],
    "IsTruncated": false
}
```

---

### Query — Policy names, ARNs, and attachment count

```bash
awslocal iam list-policies --scope Local \
  --query 'Policies[*].{Name:PolicyName, ARN:Arn, Attachments:AttachmentCount}' \
  --output table
```

**Output:**
```
---------------------------------------------------------------------------------------------
|                                       ListPolicies                                        |
+---------------------------------------------------+------------------+-------------------+
|                        ARN                        |   Attachments    |       Name        |
+---------------------------------------------------+------------------+-------------------+
|  arn:aws:iam::000000000000:policy/iam-auditor-... |  1               |  iam-auditor-lambda-policy  |
|  arn:aws:iam::000000000000:policy/demo-wildcard.. |  1               |  demo-wildcard-iam-policy   |
+---------------------------------------------------+------------------+-------------------+
```

---

### Query — Read the actual policy document (what does demo-wildcard-iam-policy allow?)

```bash
awslocal iam get-policy-version \
  --policy-arn arn:aws:iam::000000000000:policy/demo-wildcard-iam-policy \
  --version-id v1 \
  --query 'PolicyVersion.Document.Statement[*].{Effect:Effect, Action:Action, Resource:Resource}'
```

**Output:**
```json
[
    {
        "Effect": "Allow",
        "Action": "iam:*",
        "Resource": "*"
    }
]
```

**Why this matters:** This is what rule R10 flags — a customer-managed policy with a wildcard action (`iam:*`) attached to a role.

---

## 7. Lambda — Functions

### Raw Command

```bash
awslocal lambda list-functions
```

### Raw Output (truncated)

```json
{
    "Functions": [
        {
            "FunctionName": "iam-auditor",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:iam-auditor",
            "Runtime": "",
            "Role": "arn:aws:iam::000000000000:role/iam-auditor-lambda-role",
            "Handler": "handler.lambda_handler",
            "CodeSize": 0,
            "Description": "",
            "Timeout": 300,
            "MemorySize": 256,
            "LastModified": "2026-04-04T10:00:00.000+0000",
            "CodeSha256": "abc123",
            "Version": "$LATEST",
            "VpcConfig": {
                "SubnetIds": ["subnet-bbbbbbbb"],
                "SecurityGroupIds": ["sg-cccccccc"],
                "VpcId": "vpc-22222222"
            },
            "PackageType": "Image",
            "Architectures": ["x86_64"],
            "EphemeralStorage": { "Size": 512 }
        }
    ]
}
```

---

### Query 1 — Function name, timeout, memory

```bash
awslocal lambda list-functions \
  --query 'Functions[*].{Name:FunctionName, Timeout:Timeout, MemoryMB:MemorySize, Package:PackageType}' \
  --output table
```

**Output:**
```
---------------------------------------------------------------
|                       ListFunctions                         |
+--------------+----------+---------+------------------------+
|     Name     | MemoryMB | Package |        Timeout         |
+--------------+----------+---------+------------------------+
|  iam-auditor |  256     |  Image  |  300                   |
+--------------+----------+---------+------------------------+
```

---

### Query 2 — Verify VPC config (is it in the private subnet?)

```bash
awslocal lambda get-function-configuration \
  --function-name iam-auditor \
  --query '{Subnets:VpcConfig.SubnetIds, SecurityGroups:VpcConfig.SecurityGroupIds, VPC:VpcConfig.VpcId}'
```

**Output:**
```json
{
    "Subnets": ["subnet-bbbbbbbb"],
    "SecurityGroups": ["sg-cccccccc"],
    "VPC": "vpc-22222222"
}
```

**Why this matters:** Confirms the Lambda is deployed inside the VPC private subnet, not exposed to the internet.

---

### Query 3 — Invoke Lambda and capture the result

```bash
awslocal lambda invoke \
  --function-name iam-auditor \
  --payload '{}' \
  response.json && cat response.json
```

**Output (`response.json`):**
```json
{
    "run_id": "20260404-100000",
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2
}
```

> Note: `lambda invoke` does not use `--query` — the response body goes to the output file. Use `cat` or `jq` to read it.

---

## 8. DynamoDB — Tables

### Raw Command

```bash
awslocal dynamodb describe-table --table-name iam-audit-findings
```

### Raw Output (truncated)

```json
{
    "Table": {
        "AttributeDefinitions": [
            { "AttributeName": "run_id",     "AttributeType": "S" },
            { "AttributeName": "finding_id", "AttributeType": "S" }
        ],
        "TableName": "iam-audit-findings",
        "KeySchema": [
            { "AttributeName": "run_id",     "KeyType": "HASH"  },
            { "AttributeName": "finding_id", "KeyType": "RANGE" }
        ],
        "TableStatus": "ACTIVE",
        "CreationDateTime": "2026-04-04T10:00:00+00:00",
        "ProvisionedThroughput": {
            "NumberOfDecreasesToday": 0,
            "ReadCapacityUnits": 0,
            "WriteCapacityUnits": 0
        },
        "TableSizeBytes": 0,
        "ItemCount": 0,
        "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/iam-audit-findings",
        "BillingModeSummary": {
            "BillingMode": "PAY_PER_REQUEST",
            "LastUpdateToPayPerRequestDateTime": "2026-04-04T10:00:00+00:00"
        },
        "TimeToLiveDescription": {
            "TimeToLiveStatus": "ENABLED",
            "AttributeName": "expires_at"
        }
    }
}
```

---

### Query 1 — Key schema, billing mode, TTL status

```bash
awslocal dynamodb describe-table \
  --table-name iam-audit-findings \
  --query 'Table.{Status:TableStatus, Billing:BillingModeSummary.BillingMode, TTL:TimeToLiveDescription.TimeToLiveStatus, Keys:KeySchema[*].AttributeName}'
```

**Output:**
```json
{
    "Status": "ACTIVE",
    "Billing": "PAY_PER_REQUEST",
    "TTL": "ENABLED",
    "Keys": ["run_id", "finding_id"]
}
```

---

### Query 2 — Scan findings after a Lambda run

```bash
awslocal dynamodb scan \
  --table-name iam-audit-findings \
  --query 'Items[*].{RunID:run_id.S, FindingID:finding_id.S, Severity:severity.S, Rule:rule_id.S}'
```

**Output:**
```json
[
    { "RunID": "20260404-100000", "FindingID": "R02-root",         "Severity": "CRITICAL", "Rule": "R02" },
    { "RunID": "20260404-100000", "FindingID": "R03-demo-no-mfa",  "Severity": "HIGH",     "Rule": "R03" },
    { "RunID": "20260404-100000", "FindingID": "R09-demo-role",    "Severity": "HIGH",     "Rule": "R09" },
    { "RunID": "20260404-100000", "FindingID": "R06-demo-key",     "Severity": "MEDIUM",   "Rule": "R06" },
    { "RunID": "20260404-100000", "FindingID": "R07-demo-unused",  "Severity": "MEDIUM",   "Rule": "R07" }
]
```

**Note:** DynamoDB items have typed values (`S` for string, `N` for number). You access the value with `.S` or `.N` after the attribute name.

---

### Query 3 — Count findings by severity

```bash
awslocal dynamodb scan \
  --table-name iam-audit-findings \
  --query 'length(Items[?severity.S==`CRITICAL`])'
```

**Output:**
```
1
```

**Expression breakdown:**
- `Items[?severity.S==`CRITICAL`]` — filter items where the severity attribute equals CRITICAL
- `length(...)` — JMESPath built-in function that returns the count

---

## 9. SNS — Topics and Subscriptions

### Raw Command

```bash
awslocal sns list-topics
```

### Raw Output

```json
{
    "Topics": [
        {
            "TopicArn": "arn:aws:sns:us-east-1:000000000000:iam-auditor-alerts"
        }
    ]
}
```

---

### Query — Extract just the topic ARN as a plain string

```bash
awslocal sns list-topics \
  --query 'Topics[0].TopicArn' \
  --output text
```

**Output:**
```
arn:aws:sns:us-east-1:000000000000:iam-auditor-alerts
```

**Why `[0]` not `[*]`:** You only have one topic, so `[0]` gets the first (and only) item as a string rather than a single-item array.

---

### Query — Check subscription status

```bash
awslocal sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:000000000000:iam-auditor-alerts \
  --query 'Subscriptions[*].{Endpoint:Endpoint, Protocol:Protocol, Status:SubscriptionArn}' \
  --output table
```

**Output:**
```
-----------------------------------------------------------------------
|                    ListSubscriptionsByTopic                         |
+-----------------------+-----------+---------------------------------+
|       Endpoint        | Protocol  |            Status               |
+-----------------------+-----------+---------------------------------+
|  your@email.com       |  email    |  PendingConfirmation            |
+-----------------------+-----------+---------------------------------+
```

**Why this matters:** After `terraform apply`, the subscription starts as `PendingConfirmation`. You must click the confirmation link in your email before SNS will deliver audit reports.

---

## 10. SSM — Parameter Store

### Raw Command

```bash
awslocal ssm get-parameters-by-path --path /iam-auditor
```

### Raw Output

```json
{
    "Parameters": [
        {
            "Name": "/iam-auditor/sns-topic-arn",
            "Type": "String",
            "Value": "arn:aws:sns:us-east-1:000000000000:iam-auditor-alerts",
            "Version": 1,
            "LastModifiedDate": "2026-04-04T10:00:00+00:00",
            "ARN": "arn:aws:ssm:us-east-1:000000000000:parameter/iam-auditor/sns-topic-arn",
            "DataType": "text"
        },
        {
            "Name": "/iam-auditor/dynamodb-table-name",
            "Type": "String",
            "Value": "iam-audit-findings",
            "Version": 1,
            "LastModifiedDate": "2026-04-04T10:00:00+00:00",
            "ARN": "arn:aws:ssm:us-east-1:000000000000:parameter/iam-auditor/dynamodb-table-name",
            "DataType": "text"
        },
        {
            "Name": "/iam-auditor/unused-days-threshold",
            "Type": "String",
            "Value": "90",
            "Version": 1,
            "LastModifiedDate": "2026-04-04T10:00:00+00:00",
            "ARN": "arn:aws:ssm:us-east-1:000000000000:parameter/iam-auditor/unused-days-threshold",
            "DataType": "text"
        }
    ]
}
```

---

### Query 1 — Name/value pairs as a clean table

```bash
awslocal ssm get-parameters-by-path \
  --path /iam-auditor \
  --query 'Parameters[*].{Name:Name, Value:Value}' \
  --output table
```

**Output:**
```
-----------------------------------------------------------------------------------------------
|                                    GetParametersByPath                                      |
+--------------------------------------------+------------------------------------------------+
|                   Name                     |                    Value                       |
+--------------------------------------------+------------------------------------------------+
|  /iam-auditor/dynamodb-table-name          |  iam-audit-findings                            |
|  /iam-auditor/sns-topic-arn                |  arn:aws:sns:us-east-1:000000000000:iam-...    |
|  /iam-auditor/unused-days-threshold        |  90                                            |
+--------------------------------------------+------------------------------------------------+
```

---

### Query 2 — Get a single parameter value (plain text — good for scripts)

```bash
awslocal ssm get-parameter \
  --name /iam-auditor/unused-days-threshold \
  --query 'Parameter.Value' \
  --output text
```

**Output:**
```
90
```

**Use case:** Capture in a shell variable:
```bash
THRESHOLD=$(awslocal ssm get-parameter \
  --name /iam-auditor/unused-days-threshold \
  --query 'Parameter.Value' \
  --output text)
echo "Threshold is $THRESHOLD days"
```

---

## 11. ECR — Repositories

### Raw Command

```bash
awslocal ecr describe-repositories
```

### Raw Output

```json
{
    "repositories": [
        {
            "repositoryArn": "arn:aws:ecr:us-east-1:000000000000:repository/iam-auditor",
            "registryId": "000000000000",
            "repositoryName": "iam-auditor",
            "repositoryUri": "000000000000.dkr.ecr.us-east-1.amazonaws.com/iam-auditor",
            "createdAt": "2026-04-04T10:00:00+00:00",
            "imageTagMutability": "MUTABLE",
            "imageScanningConfiguration": { "scanOnPush": false },
            "encryptionConfiguration": { "encryptionType": "AES256" }
        }
    ]
}
```

---

### Query — Get the repository URI (used in docker push commands)

```bash
awslocal ecr describe-repositories \
  --query 'repositories[0].repositoryUri' \
  --output text
```

**Output:**
```
000000000000.dkr.ecr.us-east-1.amazonaws.com/iam-auditor
```

**Use case:** Capture for docker tag/push:
```bash
REPO_URI=$(awslocal ecr describe-repositories \
  --query 'repositories[0].repositoryUri' \
  --output text)

docker tag iam-auditor-lambda:latest $REPO_URI:latest
docker push $REPO_URI:latest
```

---

### Query — List all images in the repository

```bash
awslocal ecr list-images \
  --repository-name iam-auditor \
  --query 'imageIds[*].{Tag:imageTag, Digest:imageDigest}'
```

**Output:**
```json
[
    {
        "Tag": "latest",
        "Digest": "sha256:abc123def456..."
    }
]
```

---

## 12. Combining Filters and Queries

These examples show `--filters` (server-side) combined with `--query` (client-side shaping).

### Find your project's private subnet ID in one command

```bash
awslocal ec2 describe-subnets \
  --filters Name=tag:Name,Values=iam-auditor-private-subnet \
  --query 'Subnets[0].SubnetId' \
  --output text
```

**Output:**
```
subnet-bbbbbbbb
```

**Pattern:** `--filters` narrows down which resources AWS returns (efficient — less data transferred). `--query` then shapes the result. Always filter server-side first when you know what you're looking for.

---

### Find all demo IAM resources in one shot

```bash
awslocal iam list-roles \
  --query 'Roles[?Tags[?Key==`demo` && Value==`true`]].{Role:RoleName, ARN:Arn}' \
  --output table
```

**Output:**
```
------------------------------------------------------------------------------------
|                                   ListRoles                                      |
+------------------------------+---------------------------------------------------+
|             ARN              |                    Role                           |
+------------------------------+---------------------------------------------------+
|  arn:aws:iam::...            |  demo-wildcard-inline-role                        |
|  arn:aws:iam::...            |  demo-wildcard-managed-role                       |
|  arn:aws:iam::...            |  demo-unused-role                                 |
+------------------------------+---------------------------------------------------+
```

---

### Capture a value and use it in the next command (chaining)

```bash
# Step 1 — get the topic ARN
TOPIC_ARN=$(awslocal sns list-topics \
  --query 'Topics[0].TopicArn' \
  --output text)

# Step 2 — use it to check subscriptions
awslocal sns list-subscriptions-by-topic \
  --topic-arn $TOPIC_ARN \
  --query 'Subscriptions[*].{Email:Endpoint, Status:SubscriptionArn}' \
  --output table
```

This pattern — query to capture a value, use it in the next command — is the foundation of automation scripts and CI/CD pipeline steps.

---

## Quick Reference

| Pattern | Expression |
|---------|------------|
| All items, one field | `Resource[*].FieldName` |
| Multiple fields, renamed | `Resource[*].{NewName:FieldName, ...}` |
| Filter by field value | `Resource[?FieldName==\`value\`]` |
| Filter by tag | `Resource[?Tags[?Key==\`Name\` && Value==\`my-value\`]]` |
| First item only | `Resource[0].FieldName` |
| Unwrap single-item array | `expression\|[0]` |
| Get a tag value | `Tags[?Key==\`Name\`].Value\|[0]` |
| Count matching items | `length(Resource[?Field==\`value\`])` |
| Nested field | `Resource[*].Parent.Child` |
| Plain string output | add `--output text` |
| Table output | add `--output table` |

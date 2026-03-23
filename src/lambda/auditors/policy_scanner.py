import uuid
from datetime import datetime, timezone, timedelta


# The set of AWS services where wildcard actions are considered HIGH risk.
# These services have high blast radius: IAM can escalate privileges, S3/EC2/Lambda
# can expose or destroy data and infrastructure.
SENSITIVE_SERVICES = {"s3", "iam", "ec2", "lambda"}


def _is_wildcard_action(action):
    """Return True if the action string is a dangerous wildcard.

    Two forms are flagged:
      - "*"      → full wildcard (every action on every service)
      - "s3:*"   → service-level wildcard (every action on one service)

    Only the services in SENSITIVE_SERVICES are flagged for service-level wildcards.
    Specific actions like "s3:GetObject" or "ec2:DescribeInstances" return False.
    """
    # Full wildcard — grants everything in the entire AWS account
    if action == "*":
        return True

    # Service-level wildcard — "s3:*", "iam:*", "ec2:*", "lambda:*"
    # Split on ":" to get [service, operation]. Only flag sensitive services.
    parts = action.split(":")
    if len(parts) == 2:
        service, operation = parts
        return service in SENSITIVE_SERVICES and operation == "*"

    return False


def _finding(run_id, rule_id, severity, arn, detail):
    """Build a finding dict matching the DynamoDB schema."""
    now = datetime.now(timezone.utc)
    return {
        "run_id": run_id,
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "severity": severity,
        "resource_arn": arn,
        "detail": detail,
        "data_source": "policy_scanner",
        "created_at": now.isoformat(),
        # expires_at is a Unix timestamp — DynamoDB TTL requires an integer epoch second
        "expires_at": int((now + timedelta(days=90)).timestamp()),
    }


# %%
"""
# Interactive development — replicate the boto3_session fixture manually

import os, sys, json, uuid
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
import boto3
from moto import mock_aws
mock = mock_aws()
mock.start()



session = boto3.Session(region_name="us-east-1")
iam = session.client("iam")

iam.create_user(UserName="wildcard-user")
policy_doc = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
})

iam.put_user_policy(
    UserName="wildcard-user",
    PolicyName="DangerousPolicy",
    PolicyDocument=policy_doc,
)

response = iam.list_user_policies(UserName="wildcard-user")
print(response["PolicyNames"])

policy = iam.get_user_policy(UserName="wildcard-user", PolicyName="DangerousPolicy")
print(policy["PolicyDocument"])



statements = policy["PolicyDocument"]["Statement"]

for statement in statements:
    effect = statement.get("Effect")
    actions = statement.get("Action", [])

    # Action can be a string or a list — normalize to a list
    if isinstance(actions, str):
        actions = [actions]

    print(f"Effect: {effect}")
    print(f"Actions: {actions}")

    if effect == "Allow":
        for action in actions:
            if action == "*" or (len(action.split(":")) == 2 and action.split(":")[1] == "*"):
                print(f"R04 triggered by action: {action}")

run_id = "run_test_123"
run(session, run_id)
"""
# %%


def run(session, run_id):
    """Scan all IAM users for inline policies with wildcard actions — returns R04 findings.

    R04 is triggered when an inline policy has:
      Effect = Allow  AND  Action contains "*" or a service wildcard like "s3:*"

    Only sensitive services are flagged (s3, iam, ec2, lambda).
    Effect=Deny wildcards are NOT flagged — Deny restricts access, it doesn't grant it.

    Inline policies are embedded directly on a user (not shared managed policies).
    They are easy to overlook because they don't appear in the IAM managed policy list.
    """
    iam = session.client("iam")
    findings = []

    # Paginate through all IAM users in the account.
    # get_paginator handles "IsTruncated" + "Marker" automatically so we never miss users.
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            user_arn = user["Arn"]
            print(f"Scanning user: {username}")

            # list_user_policies returns only inline policy names (not managed policies).
            # A user with no inline policies returns an empty list — we skip them.
            policy_names = iam.list_user_policies(UserName=username)["PolicyNames"]
            if not policy_names:
                print(f"  No inline policies found for user '{username}'")
                continue

            for policy_name in policy_names:
                # Fetch the full policy document JSON for this inline policy.
                # PolicyDocument is returned as a dict (moto) or URL-encoded string (real AWS) —
                # boto3 always decodes it to a dict for us.
                policy_doc = iam.get_user_policy(
                    UserName=username, PolicyName=policy_name
                )["PolicyDocument"]
                print(f"Scanning inline policy: {policy_name} for user '{username}'")

                # A policy document has a list of Statements. Each Statement has Effect + Action.
                for statement in policy_doc.get("Statement", []):
                    # Only Allow statements grant permissions — Deny statements restrict them.
                    # We never flag a Deny wildcard.
                    if statement.get("Effect") != "Allow":
                        print(
                            f"    Skipping non-Allow statement with Effect='{statement.get('Effect')}'"
                        )
                        continue

                    # Action can be a single string ("s3:*") or a list (["iam:*", "ec2:Describe*"]).
                    # Normalize to a list so we can iterate uniformly.
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    # Collect whichever actions triggered the rule (for the finding detail).
                    offending = [a for a in actions if _is_wildcard_action(a)]
                    print(f"Finding: {offending}")

                    if offending:
                        findings.append(
                            _finding(
                                run_id,
                                "R04",
                                "HIGH",
                                user_arn,
                                f"User '{username}' inline policy '{policy_name}' "
                                f"grants wildcard action(s): {', '.join(offending)}",
                            )
                        )
                        # One finding per policy is enough — stop checking statements
                        # for this policy once we've found a violation.
                        break

    return findings

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
        "expires_at": int((now + timedelta(days=30)).timestamp()),
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

# --- R04: user with wildcard inline policy ---
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
    if isinstance(actions, str):
        actions = [actions]
    print(f"Effect: {effect}")
    print(f"Actions: {actions}")
    if effect == "Allow":
        for action in actions:
            if action == "*" or (len(action.split(":")) == 2 and action.split(":")[1] == "*"):
                print(f"R04 triggered by action: {action}")

# --- R09: role with wildcard inline policy ---
trust_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
})
iam.create_role(RoleName="wildcard-role", AssumeRolePolicyDocument=trust_policy)
role_policy_doc = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
})
iam.put_role_policy(RoleName="wildcard-role", PolicyName="DangerousRolePolicy", PolicyDocument=role_policy_doc)
response = iam.list_role_policies(RoleName="wildcard-role")
print(response["PolicyNames"])
role_policy = iam.get_role_policy(RoleName="wildcard-role", PolicyName="DangerousRolePolicy")
print(role_policy["PolicyDocument"])

# --- R10: role with wildcard customer-managed attached policy ---
# create_policy creates a standalone managed policy with its own ARN.
# attach_role_policy links it to the role — list_attached_role_policies will then return it.
managed_policy_doc = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
})
managed_response = iam.create_policy(PolicyName="DangerousManagedPolicy", PolicyDocument=managed_policy_doc)
managed_policy_arn = managed_response["Policy"]["Arn"]
print(f"Created managed policy ARN: {managed_policy_arn}")
iam.attach_role_policy(RoleName="wildcard-role", PolicyArn=managed_policy_arn)
attached = iam.list_attached_role_policies(RoleName="wildcard-role")
print(attached["AttachedPolicies"])
# Fetch the document via versioned API
default_version = iam.get_policy(PolicyArn=managed_policy_arn)["Policy"]["DefaultVersionId"]
doc = iam.get_policy_version(PolicyArn=managed_policy_arn, VersionId=default_version)["PolicyVersion"]["Document"]
print(doc)

# Run the full auditor — should return R04, R09, and R10 findings
run_id = "run_test_123"
findings = run(session, run_id)
for f in findings:
    print(f["rule_id"], f["resource_arn"], f["detail"])
"""
# %%


def run(session, run_id):
    """Scan IAM users and roles for inline and attached wildcard policies.

    Returns:
      R04 — user inline policy with wildcard action (HIGH)
      R09 — role inline policy with wildcard action (HIGH)
      R10 — customer-managed policy attached to role with wildcard action (HIGH)

    A finding is raised when a policy has:
      Effect = Allow  AND  Action contains "*" or a service wildcard like "s3:*"

    Only sensitive services are flagged (s3, iam, ec2, lambda).
    Effect=Deny wildcards are NOT flagged — Deny restricts access, it doesn't grant it.
    AWS-managed policies (ARN starts with arn:aws:iam::aws:) are skipped for R10.
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

    # R09: Same wildcard detection applied to IAM roles.
    # A role with iam:* or s3:* carries identical privilege escalation risk as a user with R04.
    # API chain mirrors users: list_roles → list_role_policies → get_role_policy.
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            rolename = role["RoleName"]
            role_arn = role["Arn"]
            print(f"Scanning role: {rolename}")

            policy_names = iam.list_role_policies(RoleName=rolename)["PolicyNames"]
            if not policy_names:
                print(f"  No inline policies found for role '{rolename}'")
                continue

            for policy_name in policy_names:
                policy_doc = iam.get_role_policy(
                    RoleName=rolename, PolicyName=policy_name
                )["PolicyDocument"]
                print(f"Scanning inline policy: {policy_name} for role '{rolename}'")

                for statement in policy_doc.get("Statement", []):
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    offending = [a for a in actions if _is_wildcard_action(a)]
                    print(f"Finding: {offending}")

                    if offending:
                        findings.append(
                            _finding(
                                run_id,
                                "R09",
                                "HIGH",
                                role_arn,
                                f"Role '{rolename}' inline policy '{policy_name}' "
                                f"grants wildcard action(s): {', '.join(offending)}",
                            )
                        )
                        break

    # R10: Customer-managed policies attached to roles with wildcard actions.
    # Unlike inline policies (R09), managed policies are standalone IAM objects
    # with their own ARN and version history. They require a different API chain
    # to retrieve the active policy document.
    #
    # AWS-managed ARNs:       arn:aws:iam::aws:policy/AdministratorAccess
    # Customer-managed ARNs:  arn:aws:iam::123456789012:policy/MyPolicy
    # We skip AWS-managed — flagging AdministratorAccess on every admin role is noise.
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            rolename = role["RoleName"]
            role_arn = role["Arn"]
            print(f"R10: Scanning attached managed policies for role: {rolename}")

            # list_attached_role_policies returns managed policies only — not inline.
            # Each entry has PolicyName and PolicyArn.
            attached = iam.list_attached_role_policies(RoleName=rolename)[
                "AttachedPolicies"
            ]
            if not attached:
                continue

            for policy_meta in attached:
                policy_arn = policy_meta["PolicyArn"]
                policy_name = policy_meta["PolicyName"]

                # Skip AWS-managed policies — controlled by AWS, not the customer.
                if policy_arn.startswith("arn:aws:iam::aws:"):
                    print(f"  Skipping AWS-managed policy: {policy_arn}")
                    continue

                # Managed policies are versioned. DefaultVersionId is the active version.
                default_version_id = iam.get_policy(PolicyArn=policy_arn)[
                    "Policy"
                ]["DefaultVersionId"]

                # get_policy_version returns the full document — same structure as inline.
                policy_doc = iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=default_version_id
                )["PolicyVersion"]["Document"]

                print(f"  Scanning: {policy_name} (v{default_version_id}) on role '{rolename}'")

                for statement in policy_doc.get("Statement", []):
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    offending = [a for a in actions if _is_wildcard_action(a)]
                    print(f"  Finding: {offending}")

                    if offending:
                        findings.append(
                            _finding(
                                run_id,
                                "R10",
                                "HIGH",
                                role_arn,
                                f"Role '{rolename}' has customer-managed policy "
                                f"'{policy_name}' ({policy_arn}) attached, which "
                                f"grants wildcard action(s): {', '.join(offending)}",
                            )
                        )
                        break

    return findings

import os
import sys
import json
import pytest

# %%
# Add src/lambda to the module search path so we can import the auditors package.
# Works in both pytest (uses __file__) and the VS Code Interactive Window (uses cwd).
try:
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src/lambda")
    )
except NameError:
    sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))

# policy_scanner is the module we are testing.
# It detects IAM users with inline policies that grant wildcard actions (R04).
from auditors import policy_scanner

# A fixed run ID used across all tests to simulate a Lambda execution.
RUN_ID = "run_test_123"

# %%
"""
local development:
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


"""
# %%


def put_inline_policy(iam, username, policy_name, effect, action):
    """Helper: attach an inline policy directly to an existing IAM user.

    An inline policy is embedded on a single user (not reusable like managed policies).
    They are easy to overlook — they don't appear in the IAM managed policy list.

    Args:
        iam:         the boto3 IAM client
        username:    the IAM user to attach the policy to
        policy_name: a name for the inline policy
        effect:      "Allow" or "Deny" — controls whether the statement grants or restricts
        action:      a string ("s3:*") or list (["iam:*", "ec2:Describe*"]) of IAM actions
    """
    # Every IAM policy document is JSON with a Version and a list of Statements.
    # Each Statement has Effect, Action, and Resource at minimum.
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": action, "Resource": "*"}],
        }
    )
    # put_user_policy attaches (or replaces) an inline policy directly on the user.
    iam.put_user_policy(
        UserName=username,
        PolicyName=policy_name,
        PolicyDocument=policy_doc,
    )


def test_r04_full_wildcard(boto3_session):
    """R04: Inline policy with Action: '*' — HIGH finding expected.

    A full wildcard grants every action across every AWS service.
    The user can create users, delete S3 buckets, terminate EC2 instances —
    no restrictions at all. This is the most dangerous form of over-permission.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="wildcard-user")
    # Attach an inline policy that allows everything
    put_inline_policy(iam, "wildcard-user", "DangerousPolicy", "Allow", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 1
    assert r04[0]["severity"] == "HIGH"


def test_r04_service_wildcard(boto3_session):
    """R04: Inline policy with Action: 's3:*' — HIGH finding expected.

    A service-level wildcard grants all operations on one service.
    's3:*' allows listing, reading, writing, and deleting every object and bucket.
    R04 flags wildcards on: s3, iam, ec2, and lambda.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="s3-wildcard-user")
    put_inline_policy(iam, "s3-wildcard-user", "S3WildcardPolicy", "Allow", "s3:*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 1
    assert r04[0]["severity"] == "HIGH"


def test_r04_mixed_actions(boto3_session):
    """R04: Inline policy with Action: ['iam:*', 'ec2:DescribeInstances'] — HIGH finding expected.

    Action can be a string or a list. Even one wildcard in a mixed list triggers R04.
    'iam:*' alone is dangerous — an attacker could create new admin users or
    attach policies to escalate their own privileges.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="mixed-action-user")
    # Action is a list — the auditor must handle both string and list formats
    put_inline_policy(
        iam,
        "mixed-action-user",
        "MixedPolicy",
        "Allow",
        ["iam:*", "ec2:DescribeInstances"],
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 1
    assert r04[0]["severity"] == "HIGH"


def test_no_finding_specific_action(boto3_session):
    """A scoped inline policy with no wildcard should produce no findings.

    's3:GetObject' only allows reading objects — a least-privilege action.
    This is correct security hygiene. Verifies we don't produce false positives.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="scoped-user")
    put_inline_policy(iam, "scoped-user", "ScopedPolicy", "Allow", "s3:GetObject")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    # No findings expected — scoped actions are not a violation
    assert findings == []


def test_no_finding_no_policies(boto3_session):
    """A user with no inline policies at all should produce no findings.

    Many IAM users get permissions via managed policies or IAM groups, not inline
    policies. These users should never trigger R04 regardless of their effective
    permissions — R04 only inspects inline policies.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="no-policy-user")
    # No put_user_policy call — this user has zero inline policies
    findings = policy_scanner.run(boto3_session, RUN_ID)
    assert findings == []


def test_only_flagged_user_returned(boto3_session):
    """Multiple users — only the one with a wildcard policy should produce a finding.

    Verifies the auditor doesn't accidentally flag all users when iterating.
    'clean-user' has a scoped policy and should be skipped.
    'dirty-user' has a wildcard and should produce exactly 1 R04 finding.
    The finding's resource_arn must identify 'dirty-user', not 'clean-user'.
    """
    iam = boto3_session.client("iam")
    # User 1: compliant — specific action only
    iam.create_user(UserName="clean-user")
    put_inline_policy(iam, "clean-user", "CleanPolicy", "Allow", "s3:GetObject")
    # User 2: non-compliant — full wildcard
    iam.create_user(UserName="dirty-user")
    put_inline_policy(iam, "dirty-user", "DirtyPolicy", "Allow", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 1
    # The ARN in the finding must point to dirty-user, not clean-user
    assert "dirty-user" in r04[0]["resource_arn"]


def test_deny_wildcard_not_flagged(boto3_session):
    """Effect=Deny with a wildcard action should NOT produce a finding.

    Deny statements restrict what a user can do — they are the opposite of a risk.
    A policy that says 'Deny *' is locking the user out of everything.
    R04 only evaluates Effect=Allow statements, which grant permissions.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="deny-wildcard-user")
    # Effect is Deny — even though Action is '*', this restricts rather than grants
    put_inline_policy(iam, "deny-wildcard-user", "DenyPolicy", "Deny", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    assert findings == []


def test_two_wildcard_policies_same_user(boto3_session):
    """R04: A user with two separate inline policies both containing wildcards
    should produce 2 findings — one per policy.

    Verifies the policy loop doesn't stop after the first violation.
    The break only exits the statement loop inside one policy, not the policy loop.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="two-policy-user")
    put_inline_policy(iam, "two-policy-user", "S3WildcardPolicy", "Allow", "s3:*")
    put_inline_policy(iam, "two-policy-user", "IAMWildcardPolicy", "Allow", "iam:*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 2

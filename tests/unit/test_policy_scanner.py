import sys
import os, sys
import json
import pytest

# Add src/lambda to the module search path so we can import the auditors package.
try:
    # Running as a .py file — use the file's location to build the path
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src/lambda")
    )
except NameError:
    # Running in REPL or VS Code Interactive Window — use working directory
    sys.path.insert(0, os.path.join(os.getcwd(), "src/lambda"))

# A fixed run ID used across all tests to simulate a Lambda execution.
RUN_ID = "run_test_123"


def put_inline_policy(iam, username, policy_name, effect, action):
    """Helper: attach an inline policy to an existing IAM user.
    Accepts a string or list for action — matches what real IAM policies support.
    """
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": action, "Resource": "*"}],
        }
    )
    iam.put_user_policy(
        UserName=username,
        PolicyName=policy_name,
        PolicyDocument=policy_doc,
    )


def test_r04_full_wildcard(boto3_session):
    """R04: Inline policy with Action: * — HIGH finding expected.
    A full wildcard grants access to every action in every AWS service.
    This is the most dangerous form of over-permission.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="wildcard-user")
    put_inline_policy(iam, "wildcard-user", "DangerousPolicy", "Allow", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 1
    assert r04[0]["severity"] == "HIGH"


def test_r04_service_wildcard(boto3_session):
    """R04: Inline policy with Action: s3:* — HIGH finding expected.
    A service-level wildcard grants all operations on a single service.
    Still dangerous — e.g. s3:* allows deleting all buckets.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="s3-wildcard-user")
    put_inline_policy(iam, "s3-wildcard-user", "S3WildcardPolicy", "Allow", "s3:*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 1
    assert r04[0]["severity"] == "HIGH"


def test_r04_mixed_actions(boto3_session):
    """R04: Inline policy with Action: ["iam:*", "ec2:DescribeInstances"] — HIGH finding expected.
    A mixed list containing even one wildcard action should trigger R04.
    The specific actions in the list don't make the wildcard safe.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="mixed-action-user")
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
    s3:GetObject is a specific, least-privilege action — this is correct hygiene.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="scoped-user")
    put_inline_policy(iam, "scoped-user", "ScopedPolicy", "Allow", "s3:GetObject")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    assert findings == []


def test_no_finding_no_policies(boto3_session):
    """A user with no inline policies at all should produce no findings."""
    iam = boto3_session.client("iam")
    iam.create_user(UserName="no-policy-user")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    assert findings == []


def test_only_flagged_user_returned(boto3_session):
    """Multiple users — only the one with a wildcard policy should produce a finding.
    Verifies we don't accidentally flag all users when only one is non-compliant.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="clean-user")
    put_inline_policy(iam, "clean-user", "CleanPolicy", "Allow", "s3:GetObject")
    iam.create_user(UserName="dirty-user")
    put_inline_policy(iam, "dirty-user", "DirtyPolicy", "Allow", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r04 = [f for f in findings if f["rule_id"] == "R04"]
    assert len(r04) == 1
    assert "dirty-user" in r04[0]["resource_arn"]


def test_deny_wildcard_not_flagged(boto3_session):
    """Effect=Deny with a wildcard action should NOT produce a finding.
    Deny statements restrict access — they are the opposite of a risk.
    Only Allow statements are evaluated for R04.
    """
    iam = boto3_session.client("iam")
    iam.create_user(UserName="deny-wildcard-user")
    put_inline_policy(iam, "deny-wildcard-user", "DenyPolicy", "Deny", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    assert findings == []

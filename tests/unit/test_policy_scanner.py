import os
import sys
import json
import pytest
import botocore
from unittest.mock import patch

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
# %% Setup — run once
import os
import sys
import json
import pytest
import botocore
from unittest.mock import patch
import os, sys, json, boto3, botocore
from moto import mock_aws
from unittest.mock import patch

def find_project_root(marker="pytest.ini"):
    path = os.getcwd()
    while path != os.path.dirname(path):
        if os.path.exists(os.path.join(path, marker)):
            return path
        path = os.path.dirname(path)
    raise FileNotFoundError(f"Could not find project root containing {marker}")
sys.path.insert(0, os.path.join(find_project_root(), "src/lambda"))

from auditors import policy_scanner

RUN_ID = "run_test_123"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

def run_test(test_fn):
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        test_fn(session)
        print(f"{test_fn.__name__}")

# %% R04
run_test(test_r04_full_wildcard)
# %%
run_test(test_r04_service_wildcard)
# %%
run_test(test_r04_mixed_actions)
# %%
run_test(test_no_finding_specific_action)
# %%
run_test(test_no_finding_no_policies)
# %%
run_test(test_only_flagged_user_returned)
# %%
run_test(test_deny_wildcard_not_flagged)
# %%
run_test(test_two_wildcard_policies_same_user)

# %% R09
run_test(test_r09_full_wildcard)
# %%
run_test(test_r09_service_wildcard)
# %%
run_test(test_r09_mixed_actions)
# %%
run_test(test_r09_no_finding_specific_action)
# %%
run_test(test_r09_no_finding_no_policies)
# %%
run_test(test_r09_only_flagged_role_returned)
# %%
run_test(test_r09_deny_wildcard_not_flagged)
# %%
run_test(test_r09_two_wildcard_policies_same_role)

# %% R10
run_test(test_r10_full_wildcard)
# %%
run_test(test_r10_service_wildcard)
# %%
run_test(test_r10_mixed_actions)
# %%
run_test(test_r10_no_finding_specific_action)
# %%
run_test(test_r10_no_finding_no_attached_policies)
# %%
run_test(test_r10_only_flagged_role_returned)
# %%
run_test(test_r10_aws_managed_policy_skipped)
# %%
run_test(test_r10_two_wildcard_policies_same_role)

# %%
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


# =============================================================================
# R09 — Role Inline Policy Wildcard Detection
# Mirrors R04 but targets IAM roles instead of users.
# A role with iam:* or s3:* carries identical privilege escalation risk.
# =============================================================================

TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def put_role_inline_policy(iam, rolename, policy_name, effect, action):
    """Helper: create an IAM role and attach an inline policy to it.

    Roles require a trust policy (AssumeRolePolicyDocument) to be created.
    We use a minimal one that allows Lambda to assume the role — the actual
    trust policy content doesn't matter for R09 detection.

    Args:
        iam:         the boto3 IAM client
        rolename:    the IAM role to create and attach the policy to
        policy_name: a name for the inline policy
        effect:      "Allow" or "Deny"
        action:      a string ("s3:*") or list (["iam:*", "ec2:Describe*"]) of IAM actions
    """
    iam.create_role(RoleName=rolename, AssumeRolePolicyDocument=TRUST_POLICY)
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": action, "Resource": "*"}],
        }
    )
    iam.put_role_policy(
        RoleName=rolename, PolicyName=policy_name, PolicyDocument=policy_doc
    )


def test_r09_full_wildcard(boto3_session):
    """R09: Role inline policy with Action: '*' — HIGH finding expected.

    A full wildcard grants every action across every AWS service.
    Same risk as R04 on users — no restrictions at all.
    """
    iam = boto3_session.client("iam")
    put_role_inline_policy(iam, "wildcard-role", "DangerousPolicy", "Allow", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 1
    assert r09[0]["severity"] == "HIGH"


def test_r09_service_wildcard(boto3_session):
    """R09: Role inline policy with Action: 's3:*' — HIGH finding expected.

    A service-level wildcard grants all operations on one service.
    R09 flags wildcards on: s3, iam, ec2, and lambda.
    """
    iam = boto3_session.client("iam")
    put_role_inline_policy(iam, "s3-wildcard-role", "S3WildcardPolicy", "Allow", "s3:*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 1
    assert r09[0]["severity"] == "HIGH"


def test_r09_mixed_actions(boto3_session):
    """R09: Role inline policy with Action: ['iam:*', 'ec2:DescribeInstances'] — HIGH finding expected.

    Even one wildcard in a mixed list triggers R09.
    'iam:*' alone allows privilege escalation — an attacker could attach policies to any principal.
    """
    iam = boto3_session.client("iam")
    put_role_inline_policy(
        iam,
        "mixed-action-role",
        "MixedPolicy",
        "Allow",
        ["iam:*", "ec2:DescribeInstances"],
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 1
    assert r09[0]["severity"] == "HIGH"


def test_r09_no_finding_specific_action(boto3_session):
    """A scoped inline policy on a role with no wildcard should produce no R09 findings.

    's3:GetObject' only allows reading objects — a least-privilege action.
    Verifies we don't produce false positives for correctly scoped roles.
    """
    iam = boto3_session.client("iam")
    put_role_inline_policy(iam, "scoped-role", "ScopedPolicy", "Allow", "s3:GetObject")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 0


def test_r09_no_finding_no_policies(boto3_session):
    """A role with no inline policies at all should produce no R09 findings.

    Many roles get permissions via managed policies, not inline policies.
    R09 only inspects inline policies — managed policies are out of scope.
    """
    iam = boto3_session.client("iam")
    iam.create_role(RoleName="no-policy-role", AssumeRolePolicyDocument=TRUST_POLICY)
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 0


def test_r09_only_flagged_role_returned(boto3_session):
    """Multiple roles — only the one with a wildcard policy should produce a finding.

    Verifies the auditor doesn't accidentally flag all roles when iterating.
    'clean-role' has a scoped policy — should be skipped.
    'dirty-role' has a wildcard — should produce exactly 1 R09 finding.
    The finding's resource_arn must identify 'dirty-role', not 'clean-role'.
    """
    iam = boto3_session.client("iam")
    put_role_inline_policy(iam, "clean-role", "CleanPolicy", "Allow", "s3:GetObject")
    put_role_inline_policy(iam, "dirty-role", "DirtyPolicy", "Allow", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 1
    assert "dirty-role" in r09[0]["resource_arn"]


def test_r09_deny_wildcard_not_flagged(boto3_session):
    """Effect=Deny with a wildcard action on a role should NOT produce a finding.

    Deny statements restrict what a role can do — they are the opposite of a risk.
    R09 only evaluates Effect=Allow statements.
    """
    iam = boto3_session.client("iam")
    put_role_inline_policy(iam, "deny-wildcard-role", "DenyPolicy", "Deny", "*")
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 0


def test_r09_two_wildcard_policies_same_role(boto3_session):
    """R09: A role with two separate inline policies both containing wildcards
    should produce 2 findings — one per policy.

    Verifies the policy loop doesn't stop after the first violation.
    """
    iam = boto3_session.client("iam")
    iam.create_role(RoleName="two-policy-role", AssumeRolePolicyDocument=TRUST_POLICY)
    policy_doc_s3 = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }
    )
    policy_doc_iam = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
        }
    )
    iam.put_role_policy(
        RoleName="two-policy-role", PolicyName="S3Policy", PolicyDocument=policy_doc_s3
    )
    iam.put_role_policy(
        RoleName="two-policy-role",
        PolicyName="IAMPolicy",
        PolicyDocument=policy_doc_iam,
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r09 = [f for f in findings if f["rule_id"] == "R09"]
    assert len(r09) == 2


# =============================================================================
# R10 — Customer-Managed Policy Wildcard Detection on Roles
# Extends R09 to cover managed policies attached to roles.
# A customer-managed policy with iam:* attached to a role is identical risk
# to an inline wildcard — the permissions are the same, only the delivery
# mechanism differs (managed policies are standalone objects vs embedded).
# =============================================================================


def attach_customer_managed_policy(iam, rolename, policy_name, effect, action):
    """Helper: create a role, create a customer-managed policy, and attach it.

    Customer-managed policies are standalone IAM objects with their own ARN
    containing the account ID (e.g., arn:aws:iam::123456789012:policy/MyPolicy).
    They are versioned — create_policy creates v1 as the default version.

    Three steps are required:
      1. create_role — the role must exist before we can attach a policy
      2. create_policy — creates the managed policy as a standalone IAM object
      3. attach_role_policy — links the managed policy to the role

    Without step 3, list_attached_role_policies returns an empty list for the role.

    Args:
        iam:         the boto3 IAM client
        rolename:    the IAM role to create
        policy_name: the name for the customer-managed policy
        effect:      "Allow" or "Deny"
        action:      a string ("s3:*") or list (["iam:*", "ec2:Describe*"])
    """
    iam.create_role(RoleName=rolename, AssumeRolePolicyDocument=TRUST_POLICY)
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": action, "Resource": "*"}],
        }
    )
    response = iam.create_policy(PolicyName=policy_name, PolicyDocument=policy_doc)
    iam.attach_role_policy(RoleName=rolename, PolicyArn=response["Policy"]["Arn"])


def test_r10_full_wildcard(boto3_session):
    """R10: Customer-managed policy with Action: '*' attached to a role — HIGH finding.

    A full wildcard grants every action across every AWS service.
    Identical risk to R04/R09 — the only difference is the policy is a managed
    object rather than embedded inline on the role.
    """
    iam = boto3_session.client("iam")
    attach_customer_managed_policy(
        iam, "r10-full-wildcard-role", "FullWildcardPolicy", "Allow", "*"
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 1
    assert r10[0]["severity"] == "HIGH"


def test_r10_service_wildcard(boto3_session):
    """R10: Customer-managed policy with Action: 's3:*' attached to a role — HIGH finding.

    A service-level wildcard grants all operations on one service.
    R10 flags wildcards on the same sensitive services as R04/R09: s3, iam, ec2, lambda.
    """
    iam = boto3_session.client("iam")
    attach_customer_managed_policy(
        iam, "r10-s3-wildcard-role", "S3WildcardPolicy", "Allow", "s3:*"
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 1
    assert r10[0]["severity"] == "HIGH"


def test_r10_mixed_actions(boto3_session):
    """R10: Customer-managed policy with Action: ['iam:*', 'ec2:DescribeInstances'] — HIGH.

    Even one wildcard in a mixed list triggers R10.
    'iam:*' alone allows privilege escalation — an attacker could create admin users
    or attach policies to any principal in the account.
    """
    iam = boto3_session.client("iam")
    attach_customer_managed_policy(
        iam,
        "r10-mixed-action-role",
        "MixedPolicy",
        "Allow",
        ["iam:*", "ec2:DescribeInstances"],
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 1
    assert r10[0]["severity"] == "HIGH"


def test_r10_no_finding_specific_action(boto3_session):
    """A customer-managed policy with only scoped actions should produce no R10 findings.

    's3:GetObject' is a least-privilege action — read-only access to a specific operation.
    Verifies R10 does not produce false positives for correctly scoped managed policies.
    """
    iam = boto3_session.client("iam")
    attach_customer_managed_policy(
        iam, "r10-scoped-role", "ScopedPolicy", "Allow", "s3:GetObject"
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 0


def test_r10_no_finding_no_attached_policies(boto3_session):
    """A role with no attached managed policies should produce no R10 findings.

    Many roles only have inline policies or no policies at all.
    R10 only inspects attached managed policies — a role with none should be skipped cleanly.
    """
    iam = boto3_session.client("iam")
    iam.create_role(
        RoleName="r10-no-policy-role", AssumeRolePolicyDocument=TRUST_POLICY
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 0


def test_r10_only_flagged_role_returned(boto3_session):
    """Multiple roles — only the one with the wildcard managed policy should be flagged.

    'r10-clean-role' has a scoped managed policy — should produce no R10 finding.
    'r10-dirty-role' has a wildcard managed policy — should produce exactly 1 R10 finding.
    The finding's resource_arn must identify 'r10-dirty-role', not 'r10-clean-role'.
    """
    iam = boto3_session.client("iam")
    attach_customer_managed_policy(
        iam, "r10-clean-role", "CleanManagedPolicy", "Allow", "s3:GetObject"
    )
    attach_customer_managed_policy(
        iam, "r10-dirty-role", "DirtyManagedPolicy", "Allow", "*"
    )
    findings = policy_scanner.run(boto3_session, RUN_ID)
    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 1
    assert "r10-dirty-role" in r10[0]["resource_arn"]


def test_r10_aws_managed_policy_skipped(boto3_session):
    """AWS-managed policies (e.g. AdministratorAccess) must NOT produce R10 findings.

    AWS-managed ARNs contain '::aws:' with no account ID:
      arn:aws:iam::aws:policy/AdministratorAccess  ← skipped
    Customer-managed ARNs contain the account ID:
      arn:aws:iam::123456789012:policy/MyPolicy    ← scanned

    AdministratorAccess grants Action: '*' — if we didn't filter AWS-managed
    policies, attaching it to any role would produce a false R10 finding.
    The filter checks the ARN prefix 'arn:aws:iam::aws:' before any API calls.

    Moto does not pre-load real AWS-managed policies, so we cannot call
    attach_role_policy with the AdministratorAccess ARN directly. Instead we
    patch list_attached_role_policies at the botocore level to inject the
    AWS-managed ARN — same technique used in test_credential_report.py for R02.
    This directly exercises the 'startswith("arn:aws:iam::aws:")' filter.
    """
    iam = boto3_session.client("iam")
    iam.create_role(RoleName="r10-admin-role", AssumeRolePolicyDocument=TRUST_POLICY)

    original_call = botocore.client.BaseClient._make_api_call

    def mock_api_call(self, operation_name, api_params):
        # Inject a fake AWS-managed policy into the attached policies list for our test role.
        if (
            operation_name == "ListAttachedRolePolicies"
            and api_params.get("RoleName") == "r10-admin-role"
        ):
            return {
                "AttachedPolicies": [
                    {
                        "PolicyName": "AdministratorAccess",
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    }
                ],
                "IsTruncated": False,
            }
        return original_call(self, operation_name, api_params)

    with patch("botocore.client.BaseClient._make_api_call", mock_api_call):
        findings = policy_scanner.run(boto3_session, RUN_ID)

    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 0


def test_r10_two_wildcard_policies_same_role(boto3_session):
    """R10: A role with two customer-managed wildcard policies should produce 2 findings.

    Each attached managed policy is evaluated independently.
    Verifies the policy loop emits one finding per violating policy.
    """
    iam = boto3_session.client("iam")
    iam.create_role(
        RoleName="r10-two-policy-role", AssumeRolePolicyDocument=TRUST_POLICY
    )

    # Create and attach the first customer-managed wildcard policy
    s3_policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }
    )
    s3_response = iam.create_policy(
        PolicyName="R10S3WildcardPolicy", PolicyDocument=s3_policy_doc
    )
    iam.attach_role_policy(
        RoleName="r10-two-policy-role", PolicyArn=s3_response["Policy"]["Arn"]
    )

    # Create and attach the second customer-managed wildcard policy
    iam_policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
        }
    )
    iam_response = iam.create_policy(
        PolicyName="R10IAMWildcardPolicy", PolicyDocument=iam_policy_doc
    )
    iam.attach_role_policy(
        RoleName="r10-two-policy-role", PolicyArn=iam_response["Policy"]["Arn"]
    )

    findings = policy_scanner.run(boto3_session, RUN_ID)
    r10 = [f for f in findings if f["rule_id"] == "R10"]
    assert len(r10) == 2


# %%

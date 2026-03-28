import os
import boto3
import pytest
from moto import mock_aws


# Sets fake AWS credentials in environment variables.
# %%Moto requires these to be present even though no real AWS calls are made.
@pytest.fixture
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


# Returns a real boto3 Session wrapped inside moto's mock_aws context.
# Any AWS API call made through this session is intercepted by moto
# and routed to an in-memory fake AWS — no real AWS account needed.
# Tests that need to call AWS services request this fixture by name.
@pytest.fixture
def boto3_session(aws_credentials):
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


# Creates the iam-audit-findings DynamoDB table in moto with the correct
# key schema (run_id as partition key, finding_id as sort key) and TTL
# enabled on the expires_at attribute. Yields the table object so tests
# can read and write findings directly.
@pytest.fixture
def dynamodb_table(boto3_session):
    dynamodb = boto3_session.resource("dynamodb")
    table = dynamodb.create_table(
        TableName="iam-audit-findings",
        KeySchema=[
            {"AttributeName": "run_id", "KeyType": "HASH"},
            {"AttributeName": "finding_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "run_id", "AttributeType": "S"},
            {"AttributeName": "finding_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.meta.client.get_waiter("table_exists").wait(TableName="iam-audit-findings")
    table.meta.client.update_time_to_live(
        TableName="iam-audit-findings",
        TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"},
    )
    yield table


# Creates a mock SNS topic named iam-auditor-alerts and yields its ARN.
# The handler publishes the weekly findings email to this topic.
@pytest.fixture
def sns_topic(boto3_session):
    sns = boto3_session.client("sns")
    response = sns.create_topic(Name="iam-auditor-alerts")
    yield response["TopicArn"]


# Seeds the 3 SSM parameters the Lambda handler reads at runtime.
# Depends on sns_topic so the SNS ARN parameter has a real value.
# Tests that exercise the handler request this fixture to simulate
# a fully configured environment.
@pytest.fixture
def ssm_params(boto3_session, sns_topic):
    ssm = boto3_session.client("ssm")
    ssm.put_parameter(
        Name="/iam-auditor/sns-topic-arn",
        Value=sns_topic,
        Type="String",
    )
    ssm.put_parameter(
        Name="/iam-auditor/dynamodb-table-name",
        Value="iam-audit-findings",
        Type="String",
    )
    ssm.put_parameter(
        Name="/iam-auditor/unused-days-threshold",
        Value="90",
        Type="String",
    )
    yield

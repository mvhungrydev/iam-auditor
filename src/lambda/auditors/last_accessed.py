import uuid
from datetime import datetime, timezone, timedelta


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
        "data_source": "last_accessed",
        "created_at": now.isoformat(),
        "expires_at": int((now + timedelta(days=90)).timestamp()),
    }


def run(session, run_id, unused_days):
    """Detect IAM roles unused for unused_days or more.

    Returns:
      R07 — role with no LastAuthenticated or last used > unused_days ago (MEDIUM)

    Skips roles under /aws-service-role/ — these are AWS-managed and cannot
    be deleted or modified by the customer.

    GenerateServiceLastAccessedDetails is async — we poll until COMPLETED.
    LastAuthenticated is checked across all services; the most recent is used.
    """
    iam = session.client("iam")
    findings = []
    threshold = timedelta(days=unused_days)
    now = datetime.now(timezone.utc)

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            if role["Path"].startswith("/aws-service-role/"):
                print(f"Skipping AWS service role: {role['RoleName']}")
                continue

            role_arn = role["Arn"]
            role_name = role["RoleName"]
            print(f"Scanning role: {role_name} ({role_arn})")

            resp = iam.generate_service_last_accessed_details(Arn=role_arn)
            job_id = resp["JobId"]
            print(f"  Generated job {job_id}")

            while True:
                details = iam.get_service_last_accessed_details(JobId=job_id)
                if details["JobStatus"] == "COMPLETED":
                    print(f"  Job {job_id} completed")
                    break

            # Find the most recent LastAuthenticated across all services.
            # A role may have accessed multiple services — we want the latest.
            # If no service has LastAuthenticated, the role has never been used.
            last_auth = None
            for service in details.get("ServicesLastAccessed", []):
                svc_auth = service.get("LastAuthenticated")
                if svc_auth:
                    if isinstance(svc_auth, str):
                        svc_auth = datetime.fromisoformat(svc_auth)
                    if last_auth is None or svc_auth > last_auth:
                        last_auth = svc_auth

            if last_auth is None or (now - last_auth) > threshold:
                detail = (
                    f"Role {role_name} has never been used"
                    if last_auth is None
                    else f"Role {role_name} last used {(now - last_auth).days} days ago"
                )
                print(f"  Finding: R07 — {detail}")
                findings.append(_finding(run_id, "R07", "MEDIUM", role_arn, detail))
            else:
                print(f"  OK — last used {(now - last_auth).days} days ago (threshold: {unused_days})")

    return findings

# app.py
"""
Cloud Security Scout - Lambda
Single-run aggregator: scans S3, SecurityGroups, RDS -> writes to DynamoDB, publishes to SNS,
and sends ONE Slack summary (if webhook available via env or Secrets Manager).
"""

import os
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

# --- AWS clients ---
session = boto3.session.Session()
dynamodb = boto3.resource("dynamodb")
sts = boto3.client("sts")
sns = boto3.client("sns")
secrets_client = boto3.client("secretsmanager")

# --- env ---
TABLE_NAME = os.environ.get("FINDINGS_TABLE")
SNS_ARN = os.environ.get("ALERT_TOPIC_ARN")
SECRET_NAME = os.environ.get("SECRET_NAME")  # optional: secretsmanager name that stores {"SLACK_WEBHOOK_URL": "..."}
SLACK_WEBHOOK_ENV = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
SCAN_REGIONS_ENV = os.environ.get("SCAN_REGIONS", "").strip()

# --- resources ---
table = dynamodb.Table(TABLE_NAME) if TABLE_NAME else None

# --- helpers ---
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def put_finding(item: dict):
    item.setdefault("finding_id", str(uuid.uuid4()))
    item.setdefault("timestamp", now_iso())
    if not table:
        print("No DynamoDB table configured; skipping DB write:", json.dumps(item))
        return
    try:
        table.put_item(Item=item)
    except Exception as e:
        print("Failed to write to DynamoDB:", e)

def publish_to_sns(message: str, subject: str = "CloudSecurityScout"):
    if not SNS_ARN:
        return
    try:
        payload = json.dumps({"default": message})
        sns.publish(TopicArn=SNS_ARN, Message=payload, Subject=subject, MessageStructure='json')
    except Exception as e:
        print("SNS publish failed:", e)

# --- Slack secret resolution (cached) ---
_cached_webhook: Optional[str] = None

def _get_secret_webhook() -> Optional[str]:
    global _cached_webhook
    if _cached_webhook:
        return _cached_webhook
    # 1) check explicit env var
    if SLACK_WEBHOOK_ENV:
        _cached_webhook = SLACK_WEBHOOK_ENV
        return _cached_webhook
    # 2) check Secrets Manager secret (SECRET_NAME)
    secret_name = SECRET_NAME
    if not secret_name:
        return None
    try:
        resp = secrets_client.get_secret_value(SecretId=secret_name)
        secret_string = resp.get("SecretString") or "{}"
        data = json.loads(secret_string)
        _cached_webhook = data.get("SLACK_WEBHOOK_URL")
        return _cached_webhook
    except ClientError as e:
        print("Failed to read secret:", e)
        return None
    except Exception as e:
        print("Secret parse failed:", e)
        return None

def send_slack_message(text: str) -> bool:
    webhook = _get_secret_webhook()
    if not webhook:
        # nothing configured
        return False
    try:
        import urllib.request
        data = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(webhook, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = getattr(resp, "status", None)
            return 200 <= status < 300
    except Exception as e:
        print("Slack notify failed:", e)
        return False

# --- alert buffer (aggregate per run) ---
ALERT_BUFFER = []

def buffer_alert(message: str):
    ALERT_BUFFER.append(message)

def publish_alert(message: str):
    # write to DynamoDB (record)
    # note: create a minimal finding entry for storage
    try:
        put_finding({
            "region": os.environ.get("AWS_REGION", "unknown"),
            "resource_type": "GENERAL",
            "resource_id": "-",
            "finding": message,
            "severity": "INFO",
            "remediation": ""
        })
    except Exception:
        pass
    # publish to SNS (immediate)
    publish_to_sns(message)
    # buffer for Slack summary
    buffer_alert(message)

# --- region discovery ---
def get_scan_regions():
    if SCAN_REGIONS_ENV:
        return [r.strip() for r in SCAN_REGIONS_ENV.split(",") if r.strip()]
    try:
        return session.get_available_regions("ec2")
    except Exception:
        return ["us-east-1"]

# --- scanners (S3, SecurityGroup, RDS) ---
def scan_s3(region: str):
    s3 = boto3.client("s3", region_name=region)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        print("s3 list_buckets failed:", e)
        return

    for b in buckets:
        name = b.get("Name")
        is_public_acl = False
        public_policy = False
        pab_missing_or_off = False

        # ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public_acl = True
                    break
        except Exception:
            pass

        # policy
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            policy_text = pol.get("Policy", "")
            try:
                policy = json.loads(policy_text)
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or principal.get("AWS") == "*":
                            public_policy = True
                            break
            except Exception:
                pass
        except Exception:
            pass

        # PublicAccessBlock
        try:
            pab = s3.get_public_access_block(Bucket=name)
            block = pab.get("PublicAccessBlockConfiguration", {})
            if not all(block.get(k, False) for k in ("BlockPublicAcls","IgnorePublicAcls","BlockPublicPolicy","RestrictPublicBuckets")):
                pab_missing_or_off = True
        except Exception:
            pab_missing_or_off = True

        if is_public_acl or public_policy or pab_missing_or_off:
            severity = "HIGH" if (is_public_acl or public_policy) else "MEDIUM"
            finding = {
                "region": region,
                "resource_type": "S3",
                "resource_id": name,
                "finding": "Bucket policy/ACL/PublicAccessBlock indicates potential public exposure",
                "severity": severity,
                "remediation": "Enable S3 Block Public Access and remove public ACL/policy; review bucket policy"
            }
            put_finding(finding)
            publish_alert(f"S3 public exposure: {name} ({region}) severity={severity}")

def scan_security_groups(region: str):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        resp = ec2.describe_security_groups(MaxResults=500)
    except Exception as e:
        print("describe_security_groups error:", e)
        return

    for sg in resp.get("SecurityGroups", []):
        sg_id = sg.get("GroupId")
        sg_name = sg.get("GroupName")
        for ip_perm in sg.get("IpPermissions", []):
            from_port = ip_perm.get("FromPort")
            to_port = ip_perm.get("ToPort")
            for ip_range in ip_perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                if cidr in ("0.0.0.0/0",):
                    sev = "CRITICAL" if (from_port == 0 and to_port == 65535) else "HIGH"
                    finding = {
                        "region": region,
                        "resource_type": "SecurityGroup",
                        "resource_id": sg_id,
                        "finding": f"SecurityGroup allows {cidr} on ports {from_port}-{to_port}",
                        "severity": sev,
                        "remediation": "Tighten security group sources; use specific CIDRs or VPC endpoints"
                    }
                    put_finding(finding)
                    publish_alert(f"Open SecurityGroup: {sg_id} ({sg_name}) ports {from_port}-{to_port}")

            for ipv6 in ip_perm.get("Ipv6Ranges", []):
                cidr6 = ipv6.get("CidrIpv6")
                if cidr6 in ("::/0",):
                    sev = "HIGH"
                    finding = {
                        "region": region,
                        "resource_type": "SecurityGroup",
                        "resource_id": sg_id,
                        "finding": f"SecurityGroup allows {cidr6} on ports {from_port}-{to_port}",
                        "severity": sev,
                        "remediation": "Tighten IPv6 sources"
                    }
                    put_finding(finding)
                    publish_alert(f"Open SecurityGroup (IPv6): {sg_id} ports {from_port}-{to_port}")

def scan_rds(region: str):
    rds = boto3.client("rds", region_name=region)
    try:
        resp = rds.describe_db_instances()
    except Exception as e:
        print("rds describe error:", e)
        return

    for inst in resp.get("DBInstances", []):
        dbid = inst.get("DBInstanceIdentifier")
        public = inst.get("PubliclyAccessible", False)
        if public:
            finding = {
                "region": region,
                "resource_type": "RDS",
                "resource_id": dbid,
                "finding": "RDS instance PubliclyAccessible = True",
                "severity": "HIGH",
                "remediation": "Disable public accessibility; place instance in private subnet and configure secure access"
            }
            put_finding(finding)
            publish_alert(f"Public RDS instance: {dbid} ({region})")

# --- main handler ---
def lambda_handler(event, context):
    try:
        account = sts.get_caller_identity().get("Account")
    except Exception:
        account = "unknown"
    print(f"Cloud Security Scout started for account {account}")

    regions = get_scan_regions()
    print("Scanning regions:", regions)

    for region in regions:
        try:
            scan_s3(region)
            scan_security_groups(region)
            scan_rds(region)
        except Exception as e:
            print(f"scan failed for region {region}: {e}")

    # aggregated Slack summary (single message)
    if ALERT_BUFFER:
        # build short human-friendly summary (top 30)
        top = ALERT_BUFFER[:30]
        summary_lines = [f"- {m}" for m in top]
        summary = "*Cloud Security Scout — Run Summary*\n" + "\n".join(summary_lines)
        if len(ALERT_BUFFER) > 30:
            summary += f"\n_and {len(ALERT_BUFFER) - 30} more findings..._"
        sent = send_slack_message(summary)
        if not sent:
            print("Slack notify not sent (no webhook or failed).")

    print("Scan complete")
    return {"status": "completed", "regions_scanned": len(regions)}

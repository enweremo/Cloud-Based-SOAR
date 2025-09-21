import boto3
from datetime import datetime, timezone
from decimal import Decimal

ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# Configuration
DDB_LOG_TABLE = 'RemediationLog'
DDB_NACL_TABLE = 'NACLBlockList'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'
NACL_ID = 'acl-0f452091cb4d548a1'
RULE_START = 50
RULE_END = 99

def lambda_handler(event, context):
    time_detected = datetime.now(timezone.utc)

    detail = event.get("detail", {})
    finding_type = detail.get("type", "")
    valid_types = [
        "custom.web.logs",
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"
    ]

    if finding_type not in valid_types:
        print(f"[!] Skipped: {finding_type}")
        return {"status": "ignored", "message": "Not part of playbook"}

    print(f"Web login abuse detected")
    suspicious_ip = detail.get("suspicious_ip")
    log_data = detail.get("log_data", "")
    region = detail.get("region", "<ACCOUNT_REGION>")
    account_id = detail.get("account_id", "unknown")
    geo_location = detail.get("geo_location", "unknown")
    severity_num = float(detail.get("severity", 0))
    if severity_num < 4:
        severity = "Low"
    elif severity_num < 7:
        severity = "Medium"
    elif severity_num < 9:
        severity = "High"
    else:
        severity = "Critical"

    username = detail.get("username", "unknown")
    user_arn = detail.get("user_arn", "unknown")
    time_occurred = detail.get("time_occurred", datetime.now(timezone.utc).isoformat())
    remediation_id = f"web-abuse-{time_detected.strftime('%Y%m%d%H%M%S')}"

    if not suspicious_ip:
        time_responded = datetime.now(timezone.utc)
        latency = Decimal(str((time_responded - time_detected).total_seconds()))
        print("[!] No suspicious_ip found in event.")
        return {"status": "error", "message": "Missing IP"}

    print(f"[+] Web login abuse detected from IP: {suspicious_ip}")

    # 1. Check if IP is already blocked in NACL
    try:
        nacl_response = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])
        entries = nacl_response['NetworkAcls'][0].get('Entries', [])
        for entry in entries:
            if (not entry.get('Egress') and
                entry.get('RuleAction') == 'deny' and
                entry.get('CidrBlock') == f"{suspicious_ip}/32"):
                print(f"[!] IP {suspicious_ip} already blocked in rule {entry.get('RuleNumber')}")
                time_responded = datetime.now(timezone.utc)
                latency = Decimal(str((time_responded - time_detected).total_seconds()))
                timestamp = time_responded.isoformat()
                dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
                    "id": remediation_id,
                    "timestamp": timestamp,
                    "finding_type": finding_type,
                    "severity": severity,
                    "region": region,
                    "geo_location": geo_location,
                    "source_ip": suspicious_ip,
                    "resource_id": "webserver-login-endpoint",
                    "affected_service": "EC2",
                    "iam_user": username,
                    "iam_user_arn": user_arn,
                    "account_id": account_id,
                    "action_taken": f"Skipped: IP {suspicious_ip} already blocked in NACL",
                    "action_status": "skipped",
                    "response_type": "network_block",
                    "playbook_name": "web_login_abuse_block",
                    "review_required": False,
                    "sns_sent": False,
                    "time_occurred": time_occurred,
                    "time_detected": time_detected.isoformat(),
                    "time_responded": time_responded.isoformat(),
                    "latency_seconds": latency,
                    "tags": ["login", "web", "deny", "skipped", "duplicate"]
                })
                return {"status": "skipped", "message": "IP already blocked in NACL"}
    except Exception as e:
        print(f"[!] Failed to check NACL entries: {str(e)}")
        time_responded = datetime.now(timezone.utc)
        latency = Decimal(str((time_responded - time_detected).total_seconds()))
        return {"status": "error", "message": "Could not validate NACL"}

    # 2. Find available rule number
    try:
        existing_rules = [entry['RuleNumber'] for entry in entries if not entry['Egress']]
        assigned_rule = next(
            (num for num in range(RULE_START, RULE_END + 1) if num not in existing_rules),
            None
        )
        if not assigned_rule:
            print("[!] No available NACL rule numbers.")
            time_responded = datetime.now(timezone.utc)
            latency = Decimal(str((time_responded - time_detected).total_seconds()))
            timestamp = time_responded.isoformat()
            dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
                "id": remediation_id,
                "timestamp": timestamp,
                "finding_type": finding_type,
                "severity": severity,
                "region": region,
                "geo_location": geo_location,
                "source_ip": suspicious_ip,
                "resource_id": "webserver-login-endpoint",
                "affected_service": "EC2",
                "iam_user": username,
                "iam_user_arn": user_arn,
                "account_id": account_id,
                "action_taken": "Failed: NACL rule limit reached (no available rule numbers)",
                "action_status": "error",
                "response_type": "network_block",
                "playbook_name": "web_login_abuse_block",
                "review_required": False,
                "sns_sent": False,
                "time_occurred": time_occurred,
                "time_detected": time_detected.isoformat(),
                "time_responded": time_responded.isoformat(),
                "latency_seconds": latency,
                "tags": ["login", "web", "deny", "error", "nacl_limit"]
            })
            return {"status": "error", "message": "NACL rule limit reached"}
    except Exception as e:
        print(f"[!] Failed to assign rule number: {str(e)}")
        time_responded = datetime.now(timezone.utc)
        latency = Decimal(str((time_responded - time_detected).total_seconds()))
        return {"status": "error", "message": str(e)}

    # 3. Block IP using NACL
    try:
        ec2.create_network_acl_entry(
            NetworkAclId=NACL_ID,
            RuleNumber=assigned_rule,
            Protocol='-1',
            RuleAction='deny',
            Egress=False,
            CidrBlock=f"{suspicious_ip}/32",
            PortRange={'From': 0, 'To': 65535}
        )
        print(f"[+] NACL rule {assigned_rule} added for IP {suspicious_ip}")
    except Exception as e:
        print(f"[!] Failed to block IP: {str(e)}")
        time_responded = datetime.now(timezone.utc)
        latency = Decimal(str((time_responded - time_detected).total_seconds()))
        timestamp = time_responded.isoformat()
        dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
            "id": remediation_id,
            "timestamp": timestamp,
            "finding_type": finding_type,
            "severity": severity,
            "region": region,
            "geo_location": geo_location,
            "source_ip": suspicious_ip,
            "resource_id": "webserver-login-endpoint",
            "affected_service": "EC2",
            "iam_user": username,
            "iam_user_arn": user_arn,
            "account_id": account_id,
            "action_taken": f"Failed: NACL rule creation failed: {str(e)}",
            "action_status": "error",
            "response_type": "network_block",
            "playbook_name": "web_login_abuse_block",
            "review_required": False,
            "sns_sent": False,
            "time_occurred": time_occurred,
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["login", "web", "deny", "error", "nacl_block"]
        })
        return {"status": "error", "message": str(e)}

    # 4. Log to NACLBlockList
    try:
        nacl_table = dynamodb.Table(DDB_NACL_TABLE)
        nacl_table.put_item(Item={
            "ip_address": suspicious_ip,
            "rule_number": assigned_rule,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "region": region,
            "geo_location": geo_location,
            "reason": "Web Login Abuse",
            "resource_id": "webserver-login-endpoint",
            "playbook_name": "web_login_abuse_block",
            "severity": severity,
            "iam_user": username,
            "iam_user_arn": user_arn
        })
        print("[+] Logged to NACLBlockList")
    except Exception as e:
        print(f"[!] Failed to log to NACLBlockList: {str(e)}")

    # 5. Log to RemediationLog
    time_responded = datetime.now(timezone.utc)
    latency = Decimal(str((time_responded - time_detected).total_seconds()))
    timestamp = time_responded.isoformat()
    try:
        remediation_table = dynamodb.Table(DDB_LOG_TABLE)
        remediation_table.put_item(Item={
            "id": remediation_id,
            "timestamp": timestamp,
            "finding_type": finding_type,
            "severity": severity,
            "region": region,
            "geo_location": geo_location,
            "source_ip": suspicious_ip,
            "resource_id": "webserver-login-endpoint",
            "affected_service": "EC2",
            "iam_user": username,
            "iam_user_arn": user_arn,
            "account_id": account_id,
            "action_taken": f"NACL deny rule {assigned_rule} applied",
            "action_status": "completed",
            "response_type": "network_block",
            "playbook_name": "web_login_abuse_block",
            "review_required": False,
            "sns_sent": False,
            "time_occurred": time_occurred,
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["login", "web", "deny", "manual_review"]
        })
        print("[+] Logged to RemediationLog")
    except Exception as e:
        print(f"[!] Failed to log to RemediationLog: {str(e)}")
        
    # 6. Notify via SNS and update sns_sent flag
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='SOAR Alert: Web Login Abuse',
            Message=f'Login abuse detected from IP {suspicious_ip}. Rule {assigned_rule} added to block access.'
        )
        print(f"[+] SNS alert sent")

        remediation_table.update_item(
            Key={"id": remediation_id},
            UpdateExpression="SET sns_sent = :val",
            ExpressionAttributeValues={":val": True}
        )
        print("[+] Updated sns_sent to True")
    except Exception as e:
        print(f"[!] Failed to publish SNS alert or update sns_sent: {str(e)}")

    return {"status": "success"}

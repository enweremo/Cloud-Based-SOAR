import boto3
from datetime import datetime, timezone
from decimal import Decimal

ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# Constants
DDB_TABLE = 'RemediationLog'
BLOCKLIST_TABLE = 'NACLBlockList'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'
BLOCKLIST_NACL_ID = 'acl-0f452091cb4d548a1'
RULE_START = 50
RULE_END = 99

def lambda_handler(event, context):
    time_detected = datetime.now(timezone.utc)
    detail = event.get("detail", {})
    finding_id = detail.get("id", "unknown")
    instance_id = detail.get("resource", {}).get("instanceDetails", {}).get("instanceId", "unknown")
    action = detail.get("service", {}).get("action", {})
    attacker_ip = (
        action.get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
        action.get("portProbeAction", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
        action.get("remoteIpDetails", {}).get("ipAddressV4") or
        "0.0.0.0"
    )
    geo_location = (
        action.get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("geoLocation", {}).get("countryCode") or
        action.get("portProbeAction", {}).get("remoteIpDetails", {}).get("geoLocation", {}).get("countryCode") or
        action.get("remoteIpDetails", {}).get("geoLocation", {}).get("countryCode") or
        "unknown"
    )
    finding_type = detail.get("type", "")
    valid_types = [
        "UnauthorizedAccess:EC2/TorClient",
        "UnauthorizedAccess:Runtime/TorClient"
    ]

    if finding_type not in valid_types:
        print(f"[!] Skipped: {finding_type}")
        return {"status": "ignored", "message": "Not part of playbook"}
    
    region = detail.get("region", "<ACCOUNT_REGION>")
    account_id = detail.get("accountId", "unknown")
    severity_num = float(detail.get("severity", 5))
    if severity_num < 4:
        severity = "Low"
    elif severity_num < 7:
        severity = "Medium"
    elif severity_num < 9:
        severity = "High"
    else:
        severity = "Critical"

    remediation_id = f"tor-{time_detected.strftime('%Y%m%d%H%M%S')}"

    print(f"Tor traffic detected from IP {attacker_ip} on EC2 instance: {instance_id}")

    # 1. Tag the EC2 instance
    try:
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'Status', 'Value': 'TorAccessDetected'}]
        )
        print(f"Tagged instance {instance_id} as TorAccessDetected")
    except Exception as e:
        print(f"Tagging failed: {str(e)}")

    # 2. Check if IP is already blocked in the NACL
    try:
        nacl_response = ec2.describe_network_acls(NetworkAclIds=[BLOCKLIST_NACL_ID])
        entries = nacl_response['NetworkAcls'][0].get('Entries', [])
        for entry in entries:
            if (not entry.get('Egress') and
                entry.get('RuleAction') == 'deny' and
                entry.get('CidrBlock') == f"{attacker_ip}/32"):
                print(f"[!] IP {attacker_ip} already blocked in NACL rule {entry.get('RuleNumber')}")               
                time_responded = datetime.now(timezone.utc)
                latency = Decimal(str((time_responded - time_detected).total_seconds()))
                dynamodb.Table(DDB_TABLE).put_item(Item={
                    "id": remediation_id,
                    "finding_id": finding_id,
                    "timestamp": time_responded.isoformat(),
                    "finding_type": finding_type,
                    "severity": severity,
                    "region": region,
                    "geo_location": geo_location,
                    "source_ip": attacker_ip,
                    "resource_id": instance_id,
                    "affected_service": "EC2",
                    "iam_user": "unknown",
                    "iam_user_arn": "unknown",
                    "account_id": account_id,
                    "action_taken": f"Skipped: IP {attacker_ip} already blocked in NACL",
                    "action_status": "skipped",
                    "response_type": "network_block",
                    "playbook_name": "tor_access_block",
                    "review_required": False,
                    "sns_sent": False,
                    "time_occurred": time_detected.isoformat(),
                    "time_detected": time_detected.isoformat(),
                    "time_responded": time_responded.isoformat(),
                    "latency_seconds": latency,
                    "tags": ["skipped", "duplicate", "nacl_block"]
                })
                return {"status": "skipped", "message": "IP already blocked in NACL"}
    except Exception as e:
        print(f"[!] Failed to check NACL entries: {str(e)}")
        return {"status": "error", "message": "Could not validate NACL"}

    # 3. Find available rule number
    try:
        existing_rules = [entry['RuleNumber'] for entry in entries if not entry['Egress']]
        rule_number = next(
            (num for num in range(RULE_START, RULE_END + 1) if num not in existing_rules),
            None
        )

        if not rule_number:
            print("[!] No available NACL rule numbers.")            
            time_responded = datetime.now(timezone.utc)
            latency = Decimal(str((time_responded - time_detected).total_seconds()))
            dynamodb.Table(DDB_TABLE).put_item(Item={
                "id": remediation_id,
                "finding_id": finding_id,
                "timestamp": time_responded.isoformat(),
                "finding_type": finding_type,
                "severity": severity,
                "region": region,
                "geo_location": geo_location,
                "source_ip": attacker_ip,
                "resource_id": instance_id,
                "affected_service": "EC2",
                "iam_user": "unknown",
                "iam_user_arn": "unknown",
                "account_id": account_id,
                "action_taken": "Failed: NACL rule limit reached (no available rule numbers)",
                "action_status": "error",
                "response_type": "network_block",
                "playbook_name": "tor_access_block",
                "review_required": False,
                "sns_sent": False,
                "time_occurred": time_detected.isoformat(),
                "time_detected": time_detected.isoformat(),
                "time_responded": time_responded.isoformat(),
                "latency_seconds": latency,
                "tags": ["error", "nacl_limit", "nacl_block"]
            })
            return {"status": "error", "message": "NACL rule limit reached"}
    except Exception as e:
        print(f"[!] Failed to assign rule number: {str(e)}")
        return {"status": "error", "message": str(e)}

    # 4. Block IP using NACL
    try:
        ec2.create_network_acl_entry(
            NetworkAclId=BLOCKLIST_NACL_ID,
            RuleNumber=rule_number,
            Protocol='-1',
            RuleAction='deny',
            Egress=False,
            CidrBlock=f"{attacker_ip}/32"
        )
        print(f"Blocked IP {attacker_ip} with rule {rule_number} in NACL {BLOCKLIST_NACL_ID}")

        # Log to NACLBlockList
        nacl_table = dynamodb.Table(BLOCKLIST_TABLE)
        nacl_table.put_item(Item={
            "ip_address": attacker_ip,
            "rule_number": rule_number,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": "Tor Access Detected",
            "region": region,
            "geo_location": geo_location,
            "resource_id": instance_id,
            "playbook_name": "tor_access_block",
            "severity": severity
        })
    except Exception as e:
        print(f"NACL block/logging failed: {str(e)}")
        time_responded = datetime.now(timezone.utc)
        latency = Decimal(str((time_responded - time_detected).total_seconds()))
        dynamodb.Table(DDB_TABLE).put_item(Item={
            "id": remediation_id,
            "finding_id": finding_id,
            "timestamp": time_responded.isoformat(),
            "finding_type": finding_type,
            "severity": severity,
            "region": region,
            "geo_location": geo_location,
            "source_ip": attacker_ip,
            "resource_id": instance_id,
            "affected_service": "EC2",
            "iam_user": "unknown",
            "iam_user_arn": "unknown",
            "account_id": account_id,
            "action_taken": f"Failed: NACL rule creation failed: {str(e)}",
            "action_status": "error",
            "response_type": "network_block",
            "playbook_name": "tor_access_block",
            "review_required": False,
            "sns_sent": False,
            "time_occurred": time_detected.isoformat(),
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["error", "nacl_block"]
        })
        return {"status": "error", "message": "NACL block failed"}

    # 5. Log to RemediationLog (success)
    try:
        time_responded = datetime.now(timezone.utc)
        latency = Decimal(str((time_responded - time_detected).total_seconds()))
        remediation_table = dynamodb.Table(DDB_TABLE)
        remediation_table.put_item(Item={
            "id": remediation_id,
            "finding_id": finding_id,
            "timestamp": time_responded.isoformat(),
            "finding_type": finding_type,
            "severity": severity,
            "region": region,
            "geo_location": geo_location,
            "source_ip": attacker_ip,
            "resource_id": instance_id,
            "affected_service": "EC2",
            "iam_user": "unknown",
            "iam_user_arn": "unknown",
            "account_id": account_id,
            "action_taken": f"NACL rule {rule_number} deny for {attacker_ip}",
            "action_status": "completed",
            "response_type": "network_block",
            "playbook_name": "tor_access_block",
            "review_required": False,
            "sns_sent": False,
            "time_occurred": time_detected.isoformat(),
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["ec2", "tor", "deny"]
        })
        print("[+] Logged remediation to DynamoDB")
    except Exception as e:
        print(f"DynamoDB remediation logging failed: {str(e)}")

    # 6. SNS Notification and update sns_sent
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='SOAR Alert: Tor-Based Access',
            Message=f'Tor traffic detected on EC2 instance {instance_id}. IP {attacker_ip} has been blocked and logged.'
        )
        print("[+] SNS alert sent")

        remediation_table.update_item(
            Key={"id": remediation_id},
            UpdateExpression="SET sns_sent = :val",
            ExpressionAttributeValues={":val": True}
        )
        print("[+] Updated sns_sent to True")
    except Exception as e:
        print(f"SNS alert/update failed: {str(e)}")

    return {"status": "success"}

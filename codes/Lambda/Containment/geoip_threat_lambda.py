import boto3
from datetime import datetime, timezone
from decimal import Decimal
import json

# Main config
DDB_LOG_TABLE = 'RemediationLog'
DDB_NACL_TABLE = 'NACLBlockList'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'
NACL_ID = '<NACL_ID>'
RULE_START = 100
RULE_END = 150
HIGH_RISK_COUNTRIES = {'TR', 'Turkey', 'CN', 'China', 'RU', 'Russia', 'KP', 'North Korea'}

ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

def lambda_handler(event, context):
    print("[DEBUG] Incoming Event:")
    print(json.dumps(event, indent=2, default=str))
    time_detected = datetime.now(timezone.utc)  # Accurate time_detected

    try:
        detail = event.get("detail", {})
        finding_type = detail.get("type", "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom")
        service = detail.get("service", {})
        action = service.get("action", {})

        ip = (
            action.get("remoteIpDetails", {}).get("ipAddressV4") or
            action.get("portProbeAction", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
            action.get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
            action.get("actionDetails", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
            service.get("action", {}).get("remoteIpDetails", {}).get("ipAddressV4") or
            "unknown"
        )
        country = (
            action.get("remoteIpDetails", {}).get("country", {}).get("isoCode") or
            action.get("remoteIpDetails", {}).get("country", {}).get("countryName") or
            action.get("portProbeAction", {}).get("remoteIpDetails", {}).get("country", {}).get("isoCode") or
            action.get("portProbeAction", {}).get("remoteIpDetails", {}).get("country", {}).get("countryName") or
            action.get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("country", {}).get("isoCode") or
            action.get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("country", {}).get("countryName") or
            service.get("action", {}).get("remoteIpDetails", {}).get("country", {}).get("isoCode") or
            service.get("action", {}).get("remoteIpDetails", {}).get("country", {}).get("countryName") or
            "unknown"
        )

        region = detail.get("region", "<ACCOUNT_REGION>")
        account_id = detail.get("accountId", "unknown")
        resource_id = (
            detail.get("resource", {}).get("instanceDetails", {}).get("instanceId") or
            detail.get("resource", {}).get("resourceType", "unknown")
        )
        severity_num = float(detail.get("severity", 9))
        severity = (
            "Low" if severity_num < 4 else
            "Medium" if severity_num < 7 else
            "High" if severity_num < 9 else
            "Critical"
        )
        remediation_id = f"geoip-{time_detected.strftime('%Y%m%d%H%M%S')}"

        # Handle missing IP or country
        if ip == "unknown" or country == "unknown":
            time_responded = datetime.now(timezone.utc)
            latency = Decimal(str((time_responded - time_detected).total_seconds()))
            dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
                "id": remediation_id,
                "finding_id": detail.get("id", "unknown"),
                "timestamp": time_responded.isoformat(),
                "finding_type": finding_type,
                "severity": severity,
                "region": region,
                "geo_location": country,
                "source_ip": ip,
                "resource_id": resource_id,
                "affected_service": "EC2",
                "iam_user": "unknown",
                "iam_user_arn": "unknown",
                "account_id": account_id,
                "action_taken": "Failed: Missing IP/country in finding",
                "action_status": "skipped",
                "response_type": "network_restriction",
                "playbook_name": "geoip_threat_response",
                "review_required": False,
                "sns_sent": False,
                "time_occurred": time_detected.isoformat(),
                "time_detected": time_detected.isoformat(),
                "time_responded": time_responded.isoformat(),
                "latency_seconds": latency,
                "tags": ["skipped", "missing_field", "nacl_block"]
            })
            return {"status": "skipped", "reason": "missing ip or country"}

        if country not in HIGH_RISK_COUNTRIES:
            print(f"[INFO] IP {ip} from {country} is not in HIGH_RISK_COUNTRIES. Skipping.")
            return {"status": "ignored"}

        print(f"[!] High-risk GeoIP detected: {ip} from {country}")

        # Step 1: Check if IP is already blocked in NACL
        try:
            nacl = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])['NetworkAcls'][0]
            entries = nacl.get('Entries', [])
            for entry in entries:
                if (not entry['Egress'] and entry['RuleAction'] == 'deny' and entry['CidrBlock'] == f"{ip}/32"):
                    time_responded = datetime.now(timezone.utc)
                    latency = Decimal(str((time_responded - time_detected).total_seconds()))
                    print(f"[INFO] IP {ip} already blocked in NACL rule {entry['RuleNumber']}")
                    dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
                        "id": remediation_id,
                        "finding_id": detail.get("id", "unknown"),
                        "timestamp": time_responded.isoformat(),
                        "finding_type": finding_type,
                        "severity": severity,
                        "region": region,
                        "geo_location": country,
                        "source_ip": ip,
                        "resource_id": resource_id,
                        "affected_service": "EC2",
                        "iam_user": "unknown",
                        "iam_user_arn": "unknown",
                        "account_id": account_id,
                        "action_taken": f"Skipped: IP {ip} already blocked in NACL",
                        "action_status": "skipped",
                        "response_type": "network_restriction",
                        "playbook_name": "geoip_threat_response",
                        "review_required": False,
                        "sns_sent": False,
                        "time_occurred": time_detected.isoformat(),
                        "time_detected": time_detected.isoformat(),
                        "time_responded": time_responded.isoformat(),
                        "latency_seconds": latency,
                        "tags": ["skipped", "duplicate", "nacl_block"]
                    })
                    return {"status": "skipped", "message": "IP already blocked"}
        except Exception as e:
            print(f"[ERROR] Failed to query NACL: {str(e)}")
            time_responded = datetime.now(timezone.utc)
            latency = Decimal(str((time_responded - time_detected).total_seconds()))
            return {"status": "error", "reason": str(e)}

        # Step 2: Assign a rule number for new deny rule
        try:
            existing_rules = {entry['RuleNumber'] for entry in entries if not entry['Egress']}
            assigned = next((n for n in range(RULE_START, RULE_END + 1) if n not in existing_rules), None)
            if not assigned:
                print("[ERROR] No available rule numbers for NACL.")
                time_responded = datetime.now(timezone.utc)
                latency = Decimal(str((time_responded - time_detected).total_seconds()))
                dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
                    "id": remediation_id,
                    "finding_id": detail.get("id", "unknown"),
                    "timestamp": time_responded.isoformat(),
                    "finding_type": finding_type,
                    "severity": severity,
                    "region": region,
                    "geo_location": country,
                    "source_ip": ip,
                    "resource_id": resource_id,
                    "affected_service": "EC2",
                    "iam_user": "unknown",
                    "iam_user_arn": "unknown",
                    "account_id": account_id,
                    "action_taken": "Failed: NACL rule limit reached",
                    "action_status": "error",
                    "response_type": "network_restriction",
                    "playbook_name": "geoip_threat_response",
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
            print(f"[ERROR] Failed to assign rule number: {str(e)}")
            time_responded = datetime.now(timezone.utc)
            latency = Decimal(str((time_responded - time_detected).total_seconds()))
            return {"status": "error", "reason": str(e)}

        # Step 3: Block IP in NACL
        try:
            ec2.create_network_acl_entry(
                NetworkAclId=NACL_ID,
                RuleNumber=assigned,
                Protocol='-1',
                RuleAction='deny',
                Egress=False,
                CidrBlock=f"{ip}/32",
                PortRange={'From': 0, 'To': 65535}
            )
            print(f"[SUCCESS] Blocked IP {ip} with rule {assigned}")
        except Exception as e:
            print(f"[ERROR] NACL rule creation failed: {str(e)}")
            time_responded = datetime.now(timezone.utc)
            latency = Decimal(str((time_responded - time_detected).total_seconds()))
            dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
                "id": remediation_id,
                "finding_id": detail.get("id", "unknown"),
                "timestamp": time_responded.isoformat(),
                "finding_type": finding_type,
                "severity": severity,
                "region": region,
                "geo_location": country,
                "source_ip": ip,
                "resource_id": resource_id,
                "affected_service": "EC2",
                "iam_user": "unknown",
                "iam_user_arn": "unknown",
                "account_id": account_id,
                "action_taken": f"Failed: NACL rule creation failed: {str(e)}",
                "action_status": "error",
                "response_type": "network_restriction",
                "playbook_name": "geoip_threat_response",
                "review_required": False,
                "sns_sent": False,
                "time_occurred": time_detected.isoformat(),
                "time_detected": time_detected.isoformat(),
                "time_responded": time_responded.isoformat(),
                "latency_seconds": latency,
                "tags": ["error", "nacl_block"]
            })
            return {"status": "error", "message": f"NACL rule creation failed: {str(e)}"}

        # Step 4: Log to NACLBlockList
        try:
            dynamodb.Table(DDB_NACL_TABLE).put_item(Item={
                'ip_address': ip,
                'rule_number': assigned,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'reason': f"GeoIP block from {country}",
                'region': region,
                'geo_location': country,
                'resource_id': resource_id,
                'playbook_name': 'geoip_threat_response',
                'severity': severity
            })
        except Exception as e:
            print(f"[ERROR] Failed to write to NACLBlockList: {str(e)}")

        # Step 5: Log to RemediationLog (final action - all actions complete)
        time_responded = datetime.now(timezone.utc)
        latency = Decimal(str((time_responded - time_detected).total_seconds()))
        try:
            dynamodb.Table(DDB_LOG_TABLE).put_item(Item={
                "id": remediation_id,
                "finding_id": detail.get("id", "unknown"),
                "timestamp": time_responded.isoformat(),
                "finding_type": finding_type,
                "severity": severity,
                "region": region,
                "geo_location": country,
                "source_ip": ip,
                "resource_id": resource_id,
                "affected_service": "EC2",
                "iam_user": "unknown",
                "iam_user_arn": "unknown",
                "account_id": account_id,
                "action_taken": f"NACL rule {assigned} added to block IP",
                "action_status": "completed",
                "response_type": "network_restriction",
                "playbook_name": "geoip_threat_response",
                "review_required": True,
                "sns_sent": False,
                "time_occurred": time_detected.isoformat(),
                "time_detected": time_detected.isoformat(),
                "time_responded": time_responded.isoformat(),
                "latency_seconds": latency,
                "tags": ["geoip", "nacl_block", "threat_location"]
            })
            print(f"[SUCCESS] Logged to RemediationLog")
        except Exception as e:
            print(f"[ERROR] Failed to write to RemediationLog: {str(e)}")

        # Step 6: Send SNS Alert and update sns_sent flag
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject='SOAR Alert: GeoIP Threat Blocked',
                Message=f'Blocked IP {ip} from high-risk country {country} via NACL rule {assigned}.'
            )
            print(f"[SUCCESS] SNS alert sent")

            remediation_table = dynamodb.Table(DDB_LOG_TABLE)
            remediation_table.update_item(
                Key={"id": remediation_id},
                UpdateExpression="SET sns_sent = :val",
                ExpressionAttributeValues={":val": True}
            )
            print("[SUCCESS] Updated sns_sent to True")
        except Exception as e:
            print(f"[ERROR] Failed to send SNS or update sns_sent: {str(e)}")

        return {"status": "success"}

    except Exception as e:
        print(f"[FATAL] Exception in handler: {str(e)}")
        print("[FATAL] Incoming event for postmortem:")
        print(json.dumps(event, indent=2, default=str))
        # Optional: Log error details if needed with similar latency calc
        return {"status": "fatal_error", "reason": str(e)}

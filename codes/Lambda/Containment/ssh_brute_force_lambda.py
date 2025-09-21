import boto3
from datetime import datetime, timezone
from decimal import Decimal

ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

DDB_TABLE = 'RemediationLog'
SNS_TOPIC_ARN = 'arn:aws:sns:<ACCOUNT_REGION>:<AWS_ACCOUNT_ID>:SecurityAlertTopic'

def lambda_handler(event, context):
    time_detected = datetime.now(timezone.utc)

    detail = event.get("detail", {})
    finding_id = detail.get("id", "unknown")
    instance_id = detail.get("resource", {}).get("instanceDetails", {}).get("instanceId", "unknown")
    region = detail.get("region", "<ACCOUNT_REGION>")
    account_id = detail.get("accountId", "unknown")
    severity_num = float(detail.get("severity", 0))
    if severity_num < 4:
        severity = "Low"
    elif severity_num < 7:
        severity = "Medium"
    elif severity_num < 9:
        severity = "High"
    else:
        severity = "Critical"
    finding_type = detail.get("type", "UnauthorizedAccess:EC2/SSHBruteForce")

    source_ip = detail.get("service", {}).get("action", {}).get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("ipAddressV4", "unknown")
    geo_location = detail.get("service", {}).get("action", {}).get("networkConnectionAction", {}).get("remoteIpDetails", {}).get("geoLocation", {}).get("countryCode", "unknown")

    print(f"[+] SSH brute force detected on EC2 instance: {instance_id}")

    # Step 1: Get associated security groups
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        sg_ids = [sg['GroupId'] for sg in response['Reservations'][0]['Instances'][0]['SecurityGroups']]
    except Exception as e:
        print(f"[!] Error retrieving SGs: {str(e)}")
        return {"status": "error", "message": str(e)}

    # Step 2: Revoke port 22 access
    for sg_id in sg_ids:
        try:
            sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
            ip_permissions = sg.get('IpPermissions', [])
            for rule in ip_permissions:
                if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') == 22:
                    ip_ranges = rule.get('IpRanges', [])
                    if ip_ranges:
                        ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[{
                                'IpProtocol': 'tcp',
                                'FromPort': 22,
                                'ToPort': 22,
                                'IpRanges': ip_ranges
                            }]
                        )
                        print(f"[+] Revoked SSH access from {sg_id} for: {[r['CidrIp'] for r in ip_ranges]}")
        except Exception as e:
            print(f"[!] Error updating SG {sg_id}: {str(e)}")

    # Step 3: Tag instance
    try:
        ec2.create_tags(Resources=[instance_id], Tags=[{'Key': 'Status', 'Value': 'Quarantined'}])
        print(f"[+] Tagged {instance_id} as Quarantined")
    except Exception as e:
        print(f"[!] Failed to tag instance: {str(e)}")

    # Step 4: Generate timestamps
    time_responded = datetime.now(timezone.utc)
    latency = Decimal(str((time_responded - time_detected).total_seconds())) 
    incident_id = f"sshbrute-{time_detected.strftime('%Y%m%d%H%M%S')}"

    # Step 5: Log to DynamoDB
    table = dynamodb.Table(DDB_TABLE)
    try:
        table.put_item(Item={
            "id": incident_id,
            "finding_id": finding_id,
            "timestamp": time_responded.isoformat(),
            "finding_type": finding_type,
            "severity": severity,
            "region": region,
            "geo_location": geo_location,
            "source_ip": source_ip,
            "resource_id": instance_id,
            "affected_service": "EC2",
            "iam_user": "unknown",
            "iam_user_arn": "unknown",
            "account_id": account_id,
            "action_taken": "Revoked port 22 access and quarantined instance",
            "action_status": "completed",
            "response_type": "network_restriction",
            "playbook_name": "ssh_brute_force_response",
            "review_required": False,
            "sns_sent": False,
            "time_occurred": time_detected.isoformat(),
            "time_detected": time_detected.isoformat(),
            "time_responded": time_responded.isoformat(),
            "latency_seconds": latency,
            "tags": ["ssh", "brute_force", "ec2"]
        })
        print("[+] Logged remediation to DynamoDB")
    except Exception as e:
        print(f"[!] DynamoDB error: {str(e)}")

    # Step 6: Send SNS alert and update flag
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="SOAR Alert: SSH Brute Force Detected",
            Message=(
                f"SSH brute force attack detected on instance {instance_id}.\n"
                f"Port 22 access revoked, instance quarantined.\n"
                f"Time: {time_responded.isoformat()}"
            )
        )
        print("[+] SNS alert sent")

        # Update sns_sent = True
        table.update_item(
            Key={"id": incident_id},
            UpdateExpression="SET sns_sent = :val",
            ExpressionAttributeValues={":val": True}
        )
        print("[+] Updated sns_sent to True") 
    except Exception as e:
        print(f"[!] SNS send/update failed: {str(e)}")

    return {"status": "success", "message": "SSH brute force handled and logged."}

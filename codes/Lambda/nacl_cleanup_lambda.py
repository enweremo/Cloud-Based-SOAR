import boto3
from datetime import datetime, timezone, timedelta

ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')

DDB_NACL_TABLE = 'NACLBlockList'
NACL_ID = '<NACL_ID>'
AGE_THRESHOLD_HOURS = 48

def lambda_handler(event, context):
    # Load NACL rules
    nacl = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])['NetworkAcls'][0]
    entries = nacl.get('Entries', [])

    # Load DynamoDB mapping for timestamp lookup
    table = dynamodb.Table(DDB_NACL_TABLE)
    try:
        db_items = table.scan()['Items']
    except Exception as e:
        print(f"Failed to scan NACLBlockList: {e}")
        db_items = []
    # Build a dict: { (ip, rule_number) : timestamp }
    db_lookup = {}
    for item in db_items:
        ip = item.get('ip_address')
        rule_number = int(item.get('rule_number'))
        ts = item.get('timestamp')
        if ip and rule_number and ts:
            db_lookup[(ip, rule_number)] = ts

    now = datetime.now(timezone.utc)
    removed_count = 0

    for entry in entries:
        rule_number = entry['RuleNumber']
        cidr = entry['CidrBlock']
        action = entry['RuleAction']
        egress = entry['Egress']

        # Only handle inbound Deny rules for single IPs (not 0.0.0.0/0)
        if (not egress and
            action == 'deny' and
            cidr != "0.0.0.0/0"):
            ip = cidr.split("/")[0]
            timestamp_str = db_lookup.get((ip, rule_number), None)
            if not timestamp_str:
                print(f"Skipping rule {rule_number} for {cidr}: no DynamoDB timestamp found.")
                continue
            # Fix for Z timestamps
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str.replace('Z', '+00:00')
            timestamp = datetime.fromisoformat(timestamp_str)
            age = now - timestamp
            if age > timedelta(hours=AGE_THRESHOLD_HOURS):
                try:
                    ec2.delete_network_acl_entry(
                        NetworkAclId=NACL_ID,
                        RuleNumber=rule_number,
                        Egress=False
                    )
                    print(f"Removed expired NACL rule {rule_number} for IP {cidr} (age: {age})")
                    removed_count += 1
                except Exception as e:
                    print(f"Failed to delete rule {rule_number} for {cidr}: {str(e)}")
            else:
                print(f"Rule {rule_number} for {cidr} is not expired (age: {age})")

    print(f"Cleanup completed, rules removed: {removed_count}")
    return {
        "status": "completed",
        "rules_removed": removed_count
    }

import json
import boto3
import logging
# Configure structured logging for compliance audit trails
logger = logging.getLogger()
logger.setLevel(logging.INFO)
iam_client = boto3.client('iam')
def lambda_handler(event, context):
logger.info("Received EventBridge Security Finding Payload:")
logger.info(json.dumps(event))

try:
# Extract event detail from Access Analyzer payload
detail = event.get('detail', {})
resource_type = detail.get('resourceType')
resource_arn = detail.get('resource')

# Verify that the flagged resource is an IAM Role
if resource_type == 'AWS::IAM::Role':
# Extract role name from ARN (arn:aws:iam::123456789012:role/RoleName)
role_name = resource_arn.split('/')[-1]
logger.warning(f"[!] Security Alert: Unsafe external trust policy flagged on IAM Role: {role_name}")

# Define a safe baseline trust policy (restricting assumptions strictly to local Lambda service)
safe_trust_policy = {
"Version": "2012-10-17",
"Statement": [
{
"Effect": "Allow",
"Principal": {
"Service": "lambda.amazonaws.com"
},
"Action": "sts:AssumeRole"
}
]
}

# Execute automated remediation
response = iam_client.update_assume_role_policy(
RoleName=role_name,
PolicyDocument=json.dumps(safe_trust_policy)
)

logger.info(f"[+] SUCCESS: Automatically remediated trust policy for IAM Role: {role_name}")
return {
'statusCode': 200,
'body': json.dumps(f"Successfully remediated role {role_name}")
}

except Exception as e:
logger.error(f"[!] ERROR during remediation execution: {str(e)}")
raise e

return {
'statusCode': 200,
'body': json.dumps('Event processed, no action required.')
}

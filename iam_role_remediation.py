import json
import boto3
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam_client = boto3.client("iam")


def audit_log(action, resource_arn, details=None):
    """Log timestamp, resource ARN, and remediation action."""
    logger.info(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource_arn": resource_arn or "unknown",
        "action": action,
        "details": details or {}
    }))


def lambda_handler(event, context):
    logger.info("Received EventBridge security finding.")

    # Extract finding details
    detail = event.get("detail", {})
    resource_type = detail.get("resourceType")
    resource_arn = detail.get("resource")

    audit_log("FINDING_RECEIVED", resource_arn, {
        "resource_type": resource_type
    })

    # Verify that the resource is an IAM role
    if resource_type != "AWS::IAM::Role" or not resource_arn:
        audit_log("SKIPPED_UNSUPPORTED_RESOURCE", resource_arn)
        return {
            "statusCode": 200,
            "body": json.dumps("No supported IAM role found.")
        }

    # Extract and validate the role ARN
    arn_parts = resource_arn.split(":")
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or arn_parts[2] != "iam"
        or not arn_parts[5].startswith("role/")
    ):
        audit_log("INVALID_ROLE_ARN", resource_arn)
        return {
            "statusCode": 400,
            "body": json.dumps("Invalid IAM role ARN.")
        }

    role_name = arn_parts[5].split("/")[-1]

    try:
        # Confirm that the role exists
        role_response = iam_client.get_role(RoleName=role_name)
        role = role_response["Role"]

        if role["Arn"] != resource_arn:
            audit_log("ROLE_ARN_MISMATCH", resource_arn)
            return {
                "statusCode": 409,
                "body": json.dumps("Role ARN mismatch; remediation aborted.")
            }

        logger.warning(
            "Security finding identified for role %s", resource_arn
        )

        # Simplified lab baseline: trust the Lambda service principal.
        # This does not, by itself, restrict access to your AWS account.
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

        current_policy = role["AssumeRolePolicyDocument"]

        if current_policy == safe_trust_policy:
            audit_log("NO_CHANGE_REQUIRED", resource_arn)
            return {
                "statusCode": 200,
                "body": json.dumps("Trust policy already matches baseline.")
            }

        # Apply the replacement trust policy
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(safe_trust_policy)
        )

        # Verify the resulting policy
        updated_role = iam_client.get_role(RoleName=role_name)["Role"]

        if updated_role["AssumeRolePolicyDocument"] != safe_trust_policy:
            audit_log("VERIFICATION_FAILED", resource_arn)
            raise RuntimeError("Trust policy verification failed.")

        audit_log("TRUST_POLICY_REMEDIATED", resource_arn, {
            "trusted_service": "lambda.amazonaws.com"
        })

        return {
            "statusCode": 200,
            "body": json.dumps(
                f"Successfully remediated role {role_name}."
            )
        }

    except iam_client.exceptions.NoSuchEntityException:
        audit_log("ROLE_ALREADY_DELETED", resource_arn)
        return {
            "statusCode": 200,
            "body": json.dumps(
                "Role no longer exists; remediation skipped."
            )
        }

    except ClientError as error:
        error_code = error.response.get("Error", {}).get(
            "Code", "Unknown"
        )
        audit_log("AWS_API_ERROR", resource_arn, {
            "error_code": error_code
        })
        raise

    except Exception as error:
        audit_log("REMEDIATION_ERROR", resource_arn, {
            "error_type": type(error).__name__
        })
        raise

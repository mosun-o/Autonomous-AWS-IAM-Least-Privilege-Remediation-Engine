# Autonomous-AWS-IAM-Least-Privilege-Remediation-Engine
This project implements the design, build, and testing of an end-to-end event-driven cloud remediation pipeline for compute resources and IAM roles.

## Core Learning Objective

Design, implement, and test an event-driven AWS security remediation pipeline that detects IAM permission misconfigurations and applies automated remediation to enforce the principle of least privilege.

## Skills Practiced

**AWS IAM Security:** working with IAM roles, policies, permission boundaries, and least-privilege access.

**Event-Driven Architecture:** designing event-driven workflows that trigger remediation in response to security findings.

**Cloud Automation:** developing automated remediation logic to reduce manual intervention in cloud security operations.

**Security Validation**: testing remediation workflows and verifying that corrective actions are applied as intended.

## Tech stack

- AWS IAM Access Analyzer
- Amazon EventBridge
- AWS Lambda
- AWS CloudWatch Logs
- Python (boto3)

## Architecture Flow

```text
IAM Access Analyzer → EventBridge → Lambda → IAM Role
                                      ↓
                                 CloudWatch Logs
```

| Component | Role |
|---|---|
| **IAM Access Analyzer** | Detects any overprivileged IAM roles and generates findings |
| **Amazon EventBridge** | Matches findings with a rule and triggers the remediation function |
| **AWS Lambda** | Validates findings and executes remediation logic |
| **AWS IAM** | Provides the roles and permissions that the remediation function evaluates | 
| **Amazon CloudWatch Logs** | Records execution details, remediation outcomes, and errors for auditing and troubleshooting |












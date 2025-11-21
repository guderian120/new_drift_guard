# AWS Drift Detection - Setup Guide

## Overview

DriftGuard now scans **real AWS infrastructure** to detect configuration drifts. The system connects to your AWS account, scans resources, and detects policy violations.

## What Gets Scanned

### EC2 Instances
- **Missing Environment tag**: All instances must have an `Environment` tag
- **Missing Owner tag**: All instances must have an `Owner` tag

### S3 Buckets
- **Versioning disabled**: All buckets should have versioning enabled
- **Encryption disabled**: All buckets must have encryption enabled (CRITICAL)

### Security Groups
- **Open to internet (0.0.0.0/0)**: Security groups allowing ingress from anywhere (CRITICAL)

### RDS Instances
- **Publicly accessible**: RDS instances that are publicly accessible (CRITICAL)
- **Insufficient backup retention**: RDS instances with less than 7 days backup retention

## Required AWS Permissions

Your AWS IAM user/role needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
        "rds:DescribeDBInstances",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

## Setup Instructions

### 1. Configure AWS Environment

1. Go to **Environments** page
2. Click **Add Environment**
3. Fill in:
   - **Name**: e.g., "Production AWS"
   - **Provider**: Select "AWS"
   - **AWS Access Key ID**: Your AWS access key
   - **AWS Secret Access Key**: Your AWS secret key
4. Click **Validate & Save**

The system will validate your credentials immediately.

### 2. Run Infrastructure Scan

1. Go to **Dashboard**
2. Click **Scan Infrastructure** button
3. Wait for the scan to complete
4. View detected drifts in the **Drifts** page

## How It Works

1. **Connection**: DriftGuard connects to AWS using boto3 with your credentials
2. **Resource Scanning**: Scans EC2, S3, RDS, and Security Groups across your account
3. **Policy Checks**: Compares actual configuration against expected policies
4. **Drift Detection**: Identifies resources that don't comply with policies
5. **Forensics**: Queries CloudTrail to determine who made changes and when

## Forensic Information

For each detected drift, DriftGuard attempts to retrieve:
- **Who**: Username/IAM role that made the change
- **When**: Timestamp of the change
- **How**: Method used (Console, CLI, API)
- **Where**: Source IP address
- **What**: API calls made

*Note: CloudTrail data may not be available for all resources or if CloudTrail is not enabled.*

## Troubleshooting

### "No AWS environments configured"
- Add an AWS environment with valid credentials first

### "Error scanning environment"
- Check that your AWS credentials are valid
- Verify IAM permissions are correctly configured
- Ensure CloudTrail is enabled for forensic data

### "No drifts detected"
- Your infrastructure is compliant! 🎉
- Or you may need to adjust the drift detection policies

## Next Steps

- **Remediate Drifts**: Click "Revert Changes" or "Codify Drift" on drift detail pages
- **Use AI Assistant**: Ask the AI chatbot for help understanding and fixing drifts
- **Schedule Scans**: (Coming soon) Automatic periodic scanning
- **Custom Policies**: (Coming soon) Define your own drift detection rules

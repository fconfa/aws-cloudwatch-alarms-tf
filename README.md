# AWS CloudWatch Alarms

Terraform project to create a series of sample CloudWatch alarms  to monitor many aspects of your account and infrastructure.

## Requirements

### Tools
* Terraform (tested only on 0.12+)
* AWS CLI suggested
* AWS Account credentials configured in AWSCLI or passed via environment variables

### AWS
* Enable CloudTrail and straming to a CloudWatch Log Group to enable creating alarms based on CloudTrail events
* Enable VPC Flow Logs and streaming to a CloudWatch Log Group to enable creating alerts based on network traffic filters
* Enable query logging in Route53 to send logs to CloudWatch and enable alerts based on DNS queries

## Variables

You must provide valid values for the following variables by editing the terraform.tfvars file.

* aws_account_id **(required):** The Id of the AWS account to use
* aws_region **(required):** The AWS region to provision resources in
* cloudwatch_log_group **(required):** The name of the CloudWatch Log Group where CloudTrail events are sent
* vpn_id **(optional)**: The Id of a VPN connection to add alerts to (no VPN alarm will be created if this value is empty)

## VPC alarms

Alarm Name|Description|Trigger
---|---|---
Internet Gateway configuration change|Alarms on changes on Internet Gateways|>=1 within 5 min
VPC Route Table changed|Detects changes to a VPC's Route Table|-
VPC Network ACL changes|Detects changes to a VPC's Network ACL|-
VPC changes|Detect changes to VPCs|-
VPN down|Triggers when the state of both VPN tunnels in an AWS VPN connection are down|-
VPN Data Transfer Out|Alerts on outgoing VPN traffic over a specific threshold|-
VPN Data Transfer In|Alerts on incoming VPN traffic over a specific threshold|-
SSH connection rejected|Alarms on SSH session rejected. Requires VPC Flow Log enabled and streaming to CloudWatch|>=10 within 1 hour
RDP connections from internet


## IAM alarms

Alarm Name|Description|Trigger
---|---|---
Root account login detected|Detects usage of the root account|-
IAM policy change detected|Detects IAM Policies changes|-
IAM User change detected|Detects changes to IAM users (creation/deletion/update, updating passwords or Access Keys, attaching/detaching policies from IAM users or groups)|-
CloudTrail config changed|Detects changes of CloudTrail configuration|-
Unauthorized API call|Detects unauthorized API calls|-
API activity without MFA|Detects API activity without MFA|-
Console login failed|Alert on 3 or more AWS Console failed logins|>=3 failed logins in 5min
Console login without MFA|Alert on AWS Console logins without MFA|-
Changes to MFA|Alarm that triggers when changes are made to IAM MFA devices (Virtual or Hardware)|-

## EC2 alarms

Alarm Name|Description|Trigger
---|---|---
EC2 changes detected|Alerts when changes are detected on EC2 instances|-
Security Group change detected|Alerts on changes to Security Groups|-

## Route53

Alarm Name|Description|Trigger
---|---|---
Route53 / MyApp HealthCheck|Fired when R53 health check on specified endpoint fails|<1 over 2 min period
Route53 / MyApp - High connection time|Monitor average connection time to endpoint|>2000ms over 2min period

## Cost

* Metrics collected by the CloudWatch Agent on EC2 instances are billed as custom metrics.
* TBC...
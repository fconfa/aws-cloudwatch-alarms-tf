#--------------------------------------------------------------
# GENERAL
#--------------------------------------------------------------

variable "common_tags" {
    description = "(Optional) A list of common tags to be propagated to every created resource"
    default = {}
}

#--------------------------------------------------------------
# AWS
#--------------------------------------------------------------

variable "aws_account_id" {
    description = "(Required) The AWS Account ID to be used in IAM statements"
    type = "string"
}

variable "aws_region" {
    description = "(Required) The AWS Region for creating resources"
    type = "string"
}

variable "cloudwatch_log_group" {
    description = "(Required) Name of the CloudWatch Log Group used to deliver CloudTrail logs"
    type = "string"
}

variable "vpn_id" {
    description = "(Optional) The Id of the VPN connection to check. Leave empty if no VPN should be monitored."
    default = ""
}
variable "common_tags" {
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
    description = "(Required) Name of the CloudWatch Log Group used to deliver CloudTrail"
    type = "string"
}

variable "vpn_id" {
    description = "(Optional) The Id of the VPN connection to check"
    default = ""
}
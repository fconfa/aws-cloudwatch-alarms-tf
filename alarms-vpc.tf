#---------------------------------------------------
# Detect and alert on changes on an Internet Gateway in a VPC
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-igw-changes" {
    name = "internet_gateway_changes"
    pattern = <<PATTERN
{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "GatewayEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-igw-changes" {
    alarm_name                = "Internet Gateway configuration change"
    alarm_description         = "Alarms on changes on Internet Gateways"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "GatewayEventCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on changes on VPC Route Tables
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-vpc-route-changes" {
    name = "vpc_route_table_changes"
    pattern = <<PATTERN
{ ($.eventName = AssociateRouteTable) || ($.eventName = CreateRoute) ||
    ($.eventName = CreateRouteTable) || ($.eventName = DeleteRoute) ||
    ($.eventName = DeleteRouteTable) || ($.eventName = ReplaceRoute) ||
    ($.eventName = ReplaceRouteTableAssociation) || ($.eventName =
    DisassociateRouteTable) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "VpcRouteTableEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-vpc-route-changes" {
    alarm_name                = "VPC Route Table changed"
    alarm_description         = "Triggers when changes are made to a VPC's Route Table"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "VpcRouteTableEventCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on Network ACL changes
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-vpc-nacl-changes" {
    name = "vpc_network_acl_changes"
    pattern = <<PATTERN
{ ($.eventName = CreateNetworkAcl) || ($.eventName =
    CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) ||
    ($.eventName = DeleteNetworkAclEntry) || ($.eventName =
    ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)
    }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "NetworkAclEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-vpc-nacl-changes" {
    alarm_name                = "VPC Network ACL changes"
    alarm_description         = "Triggers when changes are made to a VPC's Network ACL"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "NetworkAclEventCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on VPC changes
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-vpc-changes" {
    name = "vpc_changes"
    pattern = <<PATTERN
{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName
    = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) ||
    ($.eventName = CreateVpcPeeringConnection) || ($.eventName =
    DeleteVpcPeeringConnection) || ($.eventName =
    RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) ||
    ($.eventName = DetachClassicLinkVpc) || ($.eventName =
    DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "VpcEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-vpc-changes" {
    alarm_name                = "VPC changes"
    alarm_description         = "Triggers when changes are made to a VPC"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "VpcEventCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#========================================================================
#       VPN ALERTS
#========================================================================

#---------------------------------------------------
# Detect and alert on VPN down.
#
# Notes:
#   - This alarm uses a preset metric
#   - This alarm is created onlty if the VpnId is not empty
#---------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "alarm-vpn-down" {
    count = "${var.vpn_id == "" ? 0 : 1}"

    alarm_name                = "VPN down"
    alarm_description         = "Triggers when the state of both VPN tunnels in an AWS VPN connection are down"

    namespace                 = "AWS/VPN"
    metric_name               = "TunnelState"
    comparison_operator       = "LessThanOrEqualToThreshold"
    threshold                 = "0"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Maximum"

    dimensions = {
        VpnId = "${var.vpn_id}"
    }
}

#---------------------------------------------------
# Alerts when the traffic outgoing over a managed AWS VPN tunnel
# hits a certain threshold.
#
# Default: Less than 1,000,000 bytes in 15 minutes
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "alarm-vpn-data-out" {
    count = "${var.vpn_id == "" ? 0 : 1}"

    alarm_name                = "VPN Data Transfer Out"
    alarm_description         = "Alarms on outgoing VPN traffic"

    namespace                 = "AWS/VPN"
    metric_name               = "TunnelDataOut"
    comparison_operator       = "LessThanThreshold"
    threshold                 = "1000000"
    evaluation_periods        = "1"
    period                    = "900"
    statistic                 = "Sum"

    dimensions = {
        VpnId = "${var.vpn_id}"
    }
}

#---------------------------------------------------
# Alerts when the traffic incoming over a managed AWS VPN tunnel hits a certain threshold.
#
# Trigger: Over 5,000,000 bytes in 15 minutes
#---------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "alarm-vpn-data-in" {
    count = "${var.vpn_id == "" ? 0 : 1}"

    alarm_name                = "VPN Data Transfer In"
    alarm_description         = "Alarms on incoming VPN traffic"

    namespace                 = "AWS/VPN"
    metric_name               = "TunnelDataIn"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "5000000"
    evaluation_periods        = "1"
    period                    = "900"
    statistic                 = "Sum"

    dimensions = {
        VpnId = "${var.vpn_id}"
    }
}

#========================================================================
#       MISC ALERTS
#========================================================================

#---------------------------------------------------
# Detect and alert on failed SSH connections is a VPC.
#
# Notes:
#   - requires VPC flow log
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-ssh-rejected" {
    name = "ssh_rejected"
    pattern = <<PATTERN
[version, account, eni, source, destination, srcport, destport="22", protocol="6", packets, bytes, windowstart, windowend, action="REJECT", flowlogstatus]
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "VPCFlowLogsMetrics"
        name = "RejectedSSHCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-ssh-rejected" {
    alarm_name                = "SSH connection rejected"
    alarm_description         = "Alarms on SSH session rejected"

    namespace                 = "VPCFlowLogsMetrics"
    metric_name               = "RejectedSSHCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "10"
    evaluation_periods        = "1"
    period                    = "3600"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

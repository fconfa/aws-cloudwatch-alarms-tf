#---------------------------------------------------
# Alerts when a Security Group is changed.
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-securitygroup-changes" {
    name = "securitygroup_changes"
    pattern = <<PATTERN
{($.eventName = AuthorizeSecurityGroupIngress) ||
 ($.eventName = AuthorizeSecurityGroupEgress) ||
 ($.eventName = RevokeSecurityGroupIngress) ||
 ($.eventName = RevokeSecurityGroupEgress) ||
 ($.eventName = CreateSecurityGroup) ||
 ($.eventName = DeleteSecurityGroup) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "SecurityGroupEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-securitygroup-changes" {
    alarm_name                = "Security Group changed"
    alarm_description         = "Alarms on Security Groups changes"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "SecurityGroupEventCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Alerts when changes are made to an EC2 instance state
# (ie. started, stopped, rebooted, ...)
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-ec2-changes" {
    name = "ec2_changes"
    pattern = <<PATTERN
{($.eventName = RunInstances) ||
 ($.eventName = RebootInstances) ||
 ($.eventName = StartInstances) ||
 ($.eventName = StopInstances) ||
 ($.eventName = TerminateInstances) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "EC2InstanceEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-ec2-changes" {
    alarm_name                = "EC2 changes detected"
    alarm_description         = "Alarms when changes to EC2 instances are detected"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "EC2InstanceEventCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

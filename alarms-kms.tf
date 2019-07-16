#---------------------------------------------------
# Alerts when changes are detected on a KMS Customer key
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-kms-key-oper" {
    name = "KMSCustomerKeyOperations"
    pattern = <<PATTERN
{ ($.eventSource = kms.amazonaws.com) &&  (($.eventName=DisableKey) ||
($.eventName=ScheduleKeyDeletion) || ($.eventName=CancelKeyDeletion) ||
($.eventName=CreateKey) || ($.eventName=CreateAlias) ||
($.eventName=EnableKey) || ($.eventName=PutKeyPolicy) ||
($.eventName=ImportKeyMaterial) ||
($.eventName=DeleteImportedKeyMaterial)) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "KMSCustomerKeyUpdates"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-kms-key-changes" {
    alarm_name                = "KMS Customer key changes"
    alarm_description         = "Customer key updated"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "KMSCustomerKeyUpdates"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "60"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Alerts when Customer key gets disabled or scheduled for deletion
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-kms-key-disable" {
    name = "KMSKeyDisable"
    pattern = <<PATTERN
{ ($.eventSource = kms.amazonaws.com) &&  (($.eventName=DisableKey) ||
($.eventName=ScheduleKeyDeletion)) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "KMSCustomerKeyDeletion"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-kms-key-delete" {
    alarm_name                = "KMS Customer key delete"
    alarm_description         = "triggers if customer created CMKs get disabled or scheduled for deletion"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "KMSCustomerKeyDeletion"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "60"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

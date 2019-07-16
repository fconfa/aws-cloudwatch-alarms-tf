#---------------------------------------------------
# Detect and alert on S3 Bucket changes on Acl, policy,
# CORS, Lifecycle and replication.
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-s3-changes" {
    name = "s3_bucket_activity"
    pattern = <<PATTERN
{($.eventSource = s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "S3BucketActivityEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-s3-changes" {
    alarm_name                  = "S3 Bucket changes"
    alarm_description           = "Detect changes to S3 Bucket"

    namespace                   = "CloudTrailMetrics"
    metric_name                 = "S3BucketActivityEventCount"
    comparison_operator         = "GreaterThanOrEqualToThreshold"
    threshold                   = "1"
    evaluation_periods          = "1"
    period                      = "300"
    statistic                   = "Sum"
    treat_missing_data          = "notBreaching"
}
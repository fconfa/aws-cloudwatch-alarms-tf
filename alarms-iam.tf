#################################################################
# These alarms requires CloudTrail to stream logs to CloudWatch
#################################################################

#---------------------------------------------------
# Detect and alert on root account usage
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "filter-root-logins" {
    name = "detect_root_logins"
    pattern = <<PATTERN
{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "RootAccountUsageCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-root-login" {
    alarm_name                = "Root account login detected"
    alarm_description         = "This alarm detects usage of the root account"

    namespace                 = "CloudTrailMetrics"
    metric_name               = "RootAccountUsageCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}


#---------------------------------------------------
# Detect and alert on IAM policy change
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "count-iam-policy-change" {
    name = "IAMPolicyChangeCount"
    pattern = <<PATTERN
{ ( ($.eventSource = "iam.amazonaws.com") && (($.eventName = "Put*Policy") || ($.eventName = "Attach*") || ($.eventName = "Detach*") || ($.eventName = "Create*") || ($.eventName = "Update*") || ($.eventName = "Upload*") || ($.eventName = "Delete*") || ($.eventName = "Remove*") || ($.eventName = "Set*")) ) }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "IAMPolicyChangeCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-iam-policy-change" {
    alarm_name                  = "IAM policy change detected"
    comparison_operator         = "GreaterThanOrEqualToThreshold"
    threshold                   = "1"
    evaluation_periods          = "1"
    metric_name                 = "IAMPolicyChangeCount"
    namespace                   = "CloudTrailMetrics"
    period                      = "300"
    statistic                   = "Sum"
    alarm_description           = "Fired on IAM policy change"
    treat_missing_data          = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on IAM user change
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-iam-user-change" {
    name = "IAMUserChangeCount"
    pattern = <<PATTERN
{($.eventName=AddUserToGroup)||($.eventName=ChangePassword)||($.eventName=CreateAccessKey)||($.eventName=CreateUser)||($.eventName=UpdateAccessKey)||($.eventName=UpdateGroup)||($.eventName=UpdateUser)||($.eventName=AttachGroupPolicy)||($.eventName=AttachUserPolicy)||($.eventName=DeleteUserPolicy)||($.eventName=DetachGroupPolicy)||($.eventName=DetachUserPolicy)||($.eventName=PutUserPolicy)}
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "IAMPolicyEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-iam-user-change" {
    alarm_name                  = "IAM User change detected"
    comparison_operator         = "GreaterThanOrEqualToThreshold"
    threshold                   = "1"
    evaluation_periods          = "1"
    metric_name                 = "IAMPolicyEventCount"
    namespace                   = "CloudTrailMetrics"
    period                      = "300"
    statistic                   = "Sum"
    alarm_description           = "Fired on IAM policy change"
    treat_missing_data          = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on CloudTrail configuration change.
#
# This rule detects the following CloudTrail operational events:
#    "StopLogging"
#    "StartLogging"
#    "UpdateTrail"
#    "DeleteTrail"
#    "CreateTrail"
#    "RemoveTags"
#    "AddTags"
#    "PutEventSelectors"
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-cloudtrail-config-change" {
    name = "CloudTrailConfigChange"
    pattern = <<PATTERN
{ ($.eventName = StopLogging) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = CreateTrail) || ($.eventName = RemoveTags) || ($.eventName = AddTags)}
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "CloudTrailConfigChangeCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-cloudtrail-config-changed" {
    alarm_name                = "CloudTrail config change"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    metric_name               = "CloudTrailConfigChangeCount"
    namespace                 = "CloudTrailMetrics"
    period                    = "300"
    statistic                 = "Sum"
    alarm_description         = "This alarm detects changes to CloudTrail configuration"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on unhautorized API calls
#
# Trigger: >=3 unauthorized calls within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-unhautorized-api-call" {
    name = "UnauthorizedAPICall"
    pattern = <<PATTERN
{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "UnauthorizedAttemptCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-unauthorized-api-call" {
    alarm_name                = "Unauthorized API call"
    alarm_description         = "Trigger an alarm if multiple unauthorized requests"
    namespace                 = "CloudTrailMetrics"
    metric_name               = "UnauthorizedAttemptCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "3"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on API activity without MFA
#
# Trigger: >=3 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-api-activity-no-mfa" {
    name = "ApiActivityWithoutMFA"
    pattern = <<PATTERN
{ $.userIdentity.sessionContext.attributes.mfaAuthenticated != "true" }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "ApiActivityWithoutMFA"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-api-activity-no-mfa" {
    alarm_name                = "API activity without MFA"
    alarm_description         = "Trigger an alarm if an API activity without MFA is detected"
    namespace                 = "CloudTrailMetrics"
    metric_name               = "ApiActivityWithoutMFA"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "3"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Failed console login
#
# Trigger: >=3 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-console-login-failed" {
    name = "ConsoleLoginFailed"
    pattern = <<PATTERN
{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "ConsoleLoginFailed"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-console-login-failed" {
    alarm_name                = "Console login failed"
    alarm_description         = "Trigger an alarm if AWS Console authentication failures are detected."
    namespace                 = "CloudTrailMetrics"
    metric_name               = "ConsoleLoginFailed"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "3"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}

#---------------------------------------------------
# Detect and alert on console login without MFA
#
# Trigger: >=1 event within 5 minutes
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-console-login-no-mfa" {
    name = "ConsoleLoginWithoutMFA"
    pattern = <<PATTERN
{ $.userIdentity.sessionContext.attributes.mfaAuthenticated != "true" }
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "ConsoleLoginWithoutMFA"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-console-login-no-mfa" {
    alarm_name                = "Console login without MFA"
    alarm_description         = "Trigger an alarm if a login without MFA is detected"
    namespace                 = "CloudTrailMetrics"
    metric_name               = "ConsoleLoginWithoutMFA"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}


#---------------------------------------------------
# Detect changes to MFA
#---------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "filter-mfa-changes" {
    name = "IAMMFAChanges"
    pattern = <<PATTERN
{($.eventName=CreateVirtualMFADevice)||($.eventName=DeactivateMFADevice)||($.eventName=DeleteVirtualMFADevice)||($.eventName=EnableMFADevice)||($.eventName=ResyncMFADevice)}
PATTERN

    log_group_name = "${var.cloudwatch_log_group}"

    metric_transformation {
        namespace = "CloudTrailMetrics"
        name = "IAMPolicyEventCount"
        value = "1"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-mfa-changes" {
    alarm_name                = "Changes to MFA"
    alarm_description         = "Alarm that triggers when changes are made to IAM MFA devices (Virtual or Hardware)"
    namespace                 = "CloudTrailMetrics"
    metric_name               = "IAMPolicyEventCount"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "300"
    statistic                 = "Sum"
    treat_missing_data        = "notBreaching"
}


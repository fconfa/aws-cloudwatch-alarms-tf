#---------------------------------------------------
# Configure Route53 HealthChecks with alarms.
#
# We rely on Route53 Health Checks ability to send
# events to CloudWatch.
#
# Metrics:
#   * HealthCheckStatus (Minimum, 1=Healthy,0=Unhealthy)
#   * ConnectionTime (ms, Average)
#   * HealthCheckPercentageHealthy (percent, Average)
#
# Variables needed:
#   
#---------------------------------------------------

resource "aws_route53_health_check" "myapplication_health" {
    fqdn = "caronte.helvetelabs.net"
    port = 443
    type = "TCP"
    failure_threshold = 5
    request_interval = 30
    measure_latency = true  # enables latency-based metrics

    tags = {
        Name = "myapp-health-check"
    }  
}

resource "aws_cloudwatch_metric_alarm" "alarm-r53-healthcheck-sample" {
    alarm_name                = "Route53 / MyApp HealthCheck"
    alarm_description         = "Route53 failed for MyApp"

    namespace                 = "AWS/Route53"
    metric_name               = "HealthCheckStatus"
    comparison_operator       = "LessThanThreshold"
    threshold                 = "1"
    evaluation_periods        = "1"
    period                    = "120"
    statistic                 = "Minimum"
    treat_missing_data        = "notBreaching"

    dimensions = {
        HealthCheckId = "${aws_route53_health_check.myapplication_health.id}"
    }
}

resource "aws_cloudwatch_metric_alarm" "alarm-r53-myapp-connection-time" {
    alarm_name                = "Route53 / MyApp - High connection time"
    alarm_description         = "Average connection time to MyApp"

    namespace                 = "AWS/Route53"
    metric_name               = "ConnectionTime"
    comparison_operator       = "GreaterThanOrEqualToThreshold"
    threshold                 = "2000"
    evaluation_periods        = "1"
    period                    = "120"
    statistic                 = "Average"
    treat_missing_data        = "missing" #"notBreaching"

    dimensions = {
        HealthCheckId = "${aws_route53_health_check.myapplication_health.id}"
    }
}

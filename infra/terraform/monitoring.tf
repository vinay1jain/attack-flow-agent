resource "aws_cloudwatch_log_group" "agent" {
  name              = "/ecs/attack-flow-agent-${var.environment}"
  retention_in_days = 30
}

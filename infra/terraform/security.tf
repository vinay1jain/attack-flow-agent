resource "aws_security_group" "alb" {
  name_prefix = "af-alb-${var.environment}-"
  vpc_id      = var.vpc_id
  description = "ALB for Attack Flow Agent"

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [var.ctix_security_group_id]
    description     = "HTTP from application backend"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "agent" {
  name_prefix = "af-agent-${var.environment}-"
  vpc_id      = var.vpc_id
  description = "ECS tasks for Attack Flow Agent"

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "HTTP from ALB"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound (LLM APIs, upstream API)"
  }
}

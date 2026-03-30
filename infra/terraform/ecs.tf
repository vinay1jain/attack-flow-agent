resource "aws_ecs_cluster" "agent" {
  name = "attack-flow-agent-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "agent" {
  family                   = "attack-flow-agent-${var.environment}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.agent_cpu
  memory                   = var.agent_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "agent"
      image     = "${aws_ecr_repository.agent.repository_url}:${var.agent_image_tag}"
      essential = true

      portMappings = [
        {
          containerPort = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "AGENT_HOST", value = "0.0.0.0" },
        { name = "AGENT_PORT", value = "8000" },
        { name = "AGENT_LOG_LEVEL", value = "INFO" },
        { name = "LLM_MODEL", value = var.llm_model },
        { name = "CTIX_BASE_URL", value = var.ctix_internal_url },
      ]

      secrets = [
        { name = "OPENAI_API_KEY", valueFrom = "${aws_secretsmanager_secret.agent_secrets.arn}:OPENAI_API_KEY::" },
        { name = "CTIX_ACCESS_ID", valueFrom = "${aws_secretsmanager_secret.agent_secrets.arn}:CTIX_ACCESS_ID::" },
        { name = "CTIX_SECRET_KEY", valueFrom = "${aws_secretsmanager_secret.agent_secrets.arn}:CTIX_SECRET_KEY::" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.agent.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')\" || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 15
      }
    }
  ])
}

resource "aws_ecs_service" "agent" {
  name            = "attack-flow-agent-${var.environment}"
  cluster         = aws_ecs_cluster.agent.id
  task_definition = aws_ecs_task_definition.agent.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.agent.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.agent.arn
    container_name   = "agent"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.agent]
}

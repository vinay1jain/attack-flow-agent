output "ecr_repository_url" {
  description = "ECR repository URL for the agent image"
  value       = aws_ecr_repository.agent.repository_url
}

output "alb_dns_name" {
  description = "Internal ALB DNS name"
  value       = aws_lb.agent.dns_name
}

output "agent_service_url" {
  description = "Agent service URL via ALB"
  value       = "http://${aws_lb.agent.dns_name}"
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.agent.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.agent.name
}

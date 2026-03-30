variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "vpc_id" {
  description = "VPC ID where application EC2 instances run"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for ALB"
  type        = list(string)
}

variable "ctix_security_group_id" {
  description = "Security group ID of application EC2 instances (for ingress rules)"
  type        = string
}

variable "ctix_internal_url" {
  description = "Internal URL of the upstream threat-intel API (e.g., http://10.0.1.50:8080)"
  type        = string
}

variable "agent_image_tag" {
  description = "Docker image tag for the agent"
  type        = string
  default     = "latest"
}

variable "agent_cpu" {
  description = "Fargate CPU units (1024 = 1 vCPU)"
  type        = number
  default     = 1024
}

variable "agent_memory" {
  description = "Fargate memory in MiB"
  type        = number
  default     = 2048
}

variable "desired_count" {
  description = "Number of agent tasks"
  type        = number
  default     = 1
}

variable "llm_model" {
  description = "LiteLLM model string"
  type        = string
  default     = "openai/gpt-4o"
}

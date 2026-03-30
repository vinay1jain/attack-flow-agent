terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Configure per environment
    # bucket = "your-terraform-state-bucket"
    # key    = "attack-flow-agent/terraform.tfstate"
    # region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ctix-attack-flow-agent"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

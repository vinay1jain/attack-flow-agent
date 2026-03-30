resource "aws_secretsmanager_secret" "agent_secrets" {
  name        = "attack-flow-agent/${var.environment}"
  description = "Secrets for the Attack Flow Agent"
}

# Secret values are set manually via AWS Console or CLI:
# aws secretsmanager put-secret-value --secret-id "attack-flow-agent/dev" \
#   --secret-string '{"OPENAI_API_KEY":"sk-...","CTIX_ACCESS_ID":"...","CTIX_SECRET_KEY":"..."}'

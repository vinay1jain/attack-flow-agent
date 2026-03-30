.PHONY: help dev test lint format build up down logs clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev: ## Run agent in development mode
	cd agent && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test: ## Run tests
	cd agent && python -m pytest tests/ -v

lint: ## Run linter
	cd agent && ruff check app/ tests/

format: ## Format code
	cd agent && ruff format app/ tests/

build: ## Build Docker image
	docker-compose build

up: ## Start services
	docker-compose up -d

down: ## Stop services
	docker-compose down

logs: ## Tail logs
	docker-compose logs -f agent

clean: ## Remove generated files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -type f -name "*.pyc" -delete 2>/dev/null; true

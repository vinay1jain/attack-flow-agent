from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class LLMSettings(BaseSettings):
    model: str = Field("openai/gpt-4o", description="LiteLLM model string for reasoning")
    extraction_model: str = Field(
        "openai/gpt-4o-mini", description="LiteLLM model string for extraction"
    )
    local_model: str = Field("ollama/llama3", description="Local model for TLP:RED")
    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    anthropic_api_key: str = Field("", alias="ANTHROPIC_API_KEY")
    request_timeout: int = Field(120, description="LLM request timeout in seconds")
    max_retries: int = Field(2, description="Max retries on LLM failure")

    model_config = {"env_prefix": "LLM_", "extra": "ignore"}


class CTIXSettings(BaseSettings):
    base_url: str = Field("http://localhost", alias="CTIX_BASE_URL")
    access_id: str = Field("", alias="CTIX_ACCESS_ID")
    secret_key: str = Field("", alias="CTIX_SECRET_KEY")
    verify_ssl: bool = Field(True, alias="CTIX_VERIFY_SSL")
    request_timeout: int = Field(30)

    model_config = {"env_prefix": "CTIX_", "extra": "ignore"}


class NarrativeSettings(BaseSettings):
    token_budget: int = Field(25000, description="Max tokens for assembled narrative")
    min_sdos: int = Field(5, description="Minimum SDOs for meaningful flow")
    max_chars: int = Field(100000, description="Max characters for narrative")

    model_config = {"env_prefix": "NARRATIVE_", "extra": "ignore"}


class RateLimitSettings(BaseSettings):
    per_tenant: int = Field(20, description="Max generations per tenant per window")
    window_seconds: int = Field(3600, description="Rate limit window in seconds")

    model_config = {"env_prefix": "RATE_LIMIT_", "extra": "ignore"}


class Settings(BaseSettings):
    host: str = Field("0.0.0.0", alias="AGENT_HOST")
    port: int = Field(8000, alias="AGENT_PORT")
    log_level: str = Field("INFO", alias="AGENT_LOG_LEVEL")
    ttp_chainer_path: str = Field("/app/ttp_chainer", alias="TTP_CHAINER_PATH")

    llm: LLMSettings = Field(default_factory=LLMSettings)
    ctix: CTIXSettings = Field(default_factory=CTIXSettings)
    narrative: NarrativeSettings = Field(default_factory=NarrativeSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)

    model_config = {"env_prefix": "AGENT_", "extra": "ignore"}


_settings: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    global _settings
    if _settings is None or reload:
        _settings = Settings()
    return _settings

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path, override=True)


class Settings(BaseSettings):
    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    llm_model: str = Field("openai/gpt-4o", alias="LLM_MODEL")
    extraction_model: str = Field("openai/gpt-4o-mini", alias="LLM_EXTRACTION_MODEL")
    ttp_chainer_path: str = Field("", alias="TTP_CHAINER_PATH")
    frontend_url: str = Field("http://localhost:5173", alias="FRONTEND_URL")
    port: int = Field(8000, alias="PORT")
    max_upload_mb: int = 50

    model_config = {"env_prefix": "", "extra": "ignore"}


_settings: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    global _settings
    if _settings is None or reload:
        _settings = Settings()
    return _settings

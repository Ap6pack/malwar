# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Application configuration via environment variables and .env files."""

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MALWAR_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Database
    db_path: Path = Path("malwar.db")

    # API server
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_workers: int = 1
    api_keys: list[str] = []

    @field_validator("api_keys", mode="before")
    @classmethod
    def _parse_api_keys(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        return v if isinstance(v, list) else []

    # LLM (Anthropic)
    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.0
    llm_skip_below_risk: int = 15

    # URL crawler
    crawler_max_urls: int = 10
    crawler_timeout: float = 5.0
    crawler_max_redirects: int = 3
    crawler_max_response_bytes: int = 1_048_576
    crawler_concurrency: int = 5

    # Scanner
    scan_max_file_size: int = 524_288
    scan_default_layers: list[str] = [
        "rule_engine",
        "url_crawler",
        "llm_analyzer",
        "threat_intel",
    ]

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"


def get_settings() -> Settings:
    return Settings()

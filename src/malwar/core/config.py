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
        env_ignore_empty=True,
    )

    # Database
    db_path: Path = Path("malwar.db")
    auto_migrate: bool = True
    db_backend: str = "sqlite"  # "sqlite" or "postgres"
    postgres_url: str = ""  # e.g. "postgresql://user:pass@host:5432/malwar"
    postgres_pool_min: int = 2
    postgres_pool_max: int = 10

    # API server
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_workers: int = 1
    api_keys: list[str] = []
    cors_origins: list[str] = ["*"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_origins(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v if isinstance(v, list) else []

    @field_validator("api_keys", mode="before")
    @classmethod
    def _parse_api_keys(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        return v if isinstance(v, list) else []

    # Webhook notifications
    webhook_urls: list[str] = []
    webhook_url: str = ""
    webhook_secret: str = ""
    webhook_verdicts: list[str] = ["MALICIOUS", "SUSPICIOUS"]

    @field_validator("webhook_urls", mode="before")
    @classmethod
    def _parse_webhook_urls(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [u.strip() for u in v.split(",") if u.strip()]
        return v if isinstance(v, list) else []

    @field_validator("webhook_verdicts", mode="before")
    @classmethod
    def _parse_webhook_verdicts(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v if isinstance(v, list) else []

    # LLM (Anthropic)
    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-6"
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.0
    llm_skip_below_risk: int = 15

    # Rate limiting
    rate_limit_rpm: int = 60
    rate_limit_per_key: int = 600   # per minute for authenticated (API key)
    rate_limit_per_ip: int = 60     # per minute for unauthenticated (IP)

    # URL crawler
    crawler_max_urls: int = 10
    crawler_timeout: float = 5.0
    crawler_max_redirects: int = 3
    crawler_max_response_bytes: int = 1_048_576
    crawler_concurrency: int = 5

    # Custom YAML rules
    custom_rules_dir: str = ""

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

    # Plugins
    plugins_dir: str = ""
    enabled_plugins: list[str] = []
    plugin_module_paths: list[str] = []

    @field_validator("enabled_plugins", mode="before")
    @classmethod
    def _parse_enabled_plugins(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v if isinstance(v, list) else []

    @field_validator("plugin_module_paths", mode="before")
    @classmethod
    def _parse_plugin_module_paths(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v if isinstance(v, list) else []

    # ML risk scoring
    ml_enabled: bool = True
    ml_weight: float = 0.3  # Weight of ML score vs rule score (0.0 to 1.0)

    # Cache
    cache_backend: str = "memory"  # "memory" or "redis"
    cache_ttl: int = 3600  # seconds (default 1 hour)
    redis_url: str = "redis://localhost:6379/0"

    # Notification channels
    notification_channels: list[str] = []
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    pagerduty_routing_key: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from: str = ""
    smtp_to: list[str] = []

    @field_validator("notification_channels", mode="before")
    @classmethod
    def _parse_notification_channels(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [c.strip() for c in v.split(",") if c.strip()]
        return v if isinstance(v, list) else []

    @field_validator("smtp_to", mode="before")
    @classmethod
    def _parse_smtp_to(cls, v: object) -> list[str]:
        if isinstance(v, str):
            return [a.strip() for a in v.split(",") if a.strip()]
        return v if isinstance(v, list) else []


def get_settings() -> Settings:
    return Settings()

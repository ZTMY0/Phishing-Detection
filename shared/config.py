from pathlib import Path
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_path: str = "data/phishguard.db"
    jwt_secret: str = Field(
        default="change-me-in-production-at-least-32-chars",
        validation_alias=AliasChoices("JWT_SECRET", "GATEWAY_SECRET"),
    )

    auth_service_url: str = "http://localhost:8001"
    audit_service_url: str = "http://localhost:8003"
    analysis_grpc_host: str = "localhost"
    analysis_grpc_port: int = 50051
    gateway_port: int = 8000

    token_expire_minutes: int = 60
    refresh_expire_days: int = 7
    inactivity_timeout_minutes: int = 30
    max_email_body_chars: int = 10_000
    max_url_count: int = 50
    rate_limit_per_minute: int = 30


@lru_cache(maxsize=None)
def get_settings() -> Settings:
    return Settings()

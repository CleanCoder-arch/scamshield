import json
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
MAX_TEXT_LENGTH = 8_000
MAX_TEXT_BODY_BYTES = 128 * 1024


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=MODELS_DIR.parent / ".env",
        env_file_encoding="utf-8-sig",
        env_ignore_empty=True,
        extra="ignore",
        hide_input_in_errors=True,
    )

    gemini_api_key: SecretStr | None = None
    safe_browsing_api_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    phishtank_api_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    upstash_redis_rest_url: str | None = None
    upstash_redis_rest_token: SecretStr | None = None
    database_url: SecretStr | None = None
    app_api_salt: SecretStr | None = None
    allowed_origins: Annotated[list[str], NoDecode] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    max_image_bytes: int = Field(default=4 * 1024 * 1024, ge=1, le=8 * 1024 * 1024)
    max_image_pixels: int = Field(default=16_000_000, ge=1, le=20_000_000)
    max_urls: int = Field(default=6, ge=1, le=10)
    max_concurrent_scans: int = Field(default=4, ge=1, le=8)
    scan_rate_limit: int = Field(default=12, ge=1, le=120)
    scan_rate_window_seconds: int = Field(default=3_600, ge=1, le=86_400)
    dedup_seconds: int = Field(default=20, ge=0, le=3_600)
    threat_timeout_seconds: float = Field(default=4, gt=0, le=15)
    enable_whois: bool = True
    gemini_timeout_seconds: float = Field(default=15, gt=0, le=60)
    gemini_requests_per_minute: int = Field(default=10, ge=1, le=15)
    gemini_requests_per_day: int = Field(default=200, ge=1, le=500)

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            if value.lstrip().startswith("["):
                return json.loads(value)
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


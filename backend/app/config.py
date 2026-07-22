from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    app_name: str = "MICEPP Scanner"
    environment: Literal["development", "test", "production"] = "development"
    api_prefix: str = "/api/v1"
    secret_key: str = Field(default="development-only-change-me", alias="APP_SECRET_KEY")
    audit_hmac_key: str = Field(default="development-audit-change-me")
    access_token_minutes: int = 60

    database_url: str = "sqlite:///./data/micepp.db"
    redis_url: str = "redis://localhost:6379/0"
    evidence_root: Path = Path("./data/evidence")
    work_root: Path = Path("./data/work")
    report_root: Path = Path("./reports")
    model_root: Path = Path("./models")
    yara_rules_root: Path = Path("./rules")

    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None
    bootstrap_admin_full_name: str = "Administrateur MICEPP"

    clamav_host: str = "localhost"
    clamav_port: int = 3310
    clamav_timeout_seconds: int = 120
    yara_timeout_seconds: int = 30

    cape_base_url: str | None = None
    cape_api_token: str | None = None
    cape_verify_tls: bool = True
    cape_poll_seconds: int = 10
    cape_timeout_seconds: int = 900

    max_upload_bytes: int = 50 * 1024**3
    max_extracted_files: int = 100_000
    max_extracted_bytes: int = 100 * 1024**3
    sandbox_risk_threshold: int = 55
    model_min_samples_per_class: int = 20
    allowed_origins: str = "http://localhost:8787"

    @field_validator("cape_base_url")
    @classmethod
    def normalize_url(cls, value: str | None) -> str | None:
        return value.rstrip("/") if value else None

    def validate_production_secrets(self) -> None:
        if self.environment != "production":
            return
        weak = ("change_me", "change-me", "development", "password")
        for name, value in (
            ("APP_SECRET_KEY", self.secret_key),
            ("AUDIT_HMAC_KEY", self.audit_hmac_key),
        ):
            if len(value) < 32 or any(token in value.lower() for token in weak):
                raise RuntimeError(f"{name} doit être un secret aléatoire d'au moins 32 caractères")
        if self.bootstrap_admin_password and (
            len(self.bootstrap_admin_password) < 14
            or any(token in self.bootstrap_admin_password.lower() for token in weak)
        ):
            raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD est trop faible")

    def ensure_directories(self) -> None:
        for path in (self.evidence_root, self.work_root, self.report_root, self.model_root):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

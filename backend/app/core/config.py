"""Central application configuration."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated
from uuid import UUID

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=True, extra="ignore")

    APP_NAME: str = "Enterprise Auth System"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    DATABASE_URL: str = "postgresql+asyncpg://auth:auth@localhost:5432/authdb"
    REDIS_URL: str | None = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None
    REDIS_MAX_CONNECTIONS: int = 50
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "enterprise-auth-system"
    JWT_AUDIENCE: str = "enterprise-auth-api"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM_EMAIL: str = "noreply@example.com"
    SMTP_USE_TLS: bool = False
    SMTP_TIMEOUT_SECONDS: Annotated[float, Field(gt=0, le=60)] = 10.0
    FRONTEND_URL: str = "http://localhost:5173"
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    CAPTCHA_LENGTH: int = 6
    CAPTCHA_EXPIRE_SECONDS: int = 300
    CAPTCHA_FONT_PATH: str | None = None
    DEFAULT_TENANT_ID: UUID = UUID("550e8400-e29b-41d4-a716-446655440000")
    DEFAULT_TENANT_SLUG: str = "default"
    DEFAULT_TENANT_NAME: str = "Default Tenant"
    ALLOWED_ORIGINS: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    SECURITY_HSTS_ENABLED: bool = True
    SECURITY_HSTS_MAX_AGE_SECONDS: int = 31_536_000
    SECURITY_CSP: str = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    COMMON_PASSWORDS: set[str] = Field(default_factory=lambda: {"password", "password123", "123456", "123456789", "qwerty", "admin", "admin123", "letmein", "welcome"})

    @field_validator("FRONTEND_URL")
    @classmethod
    def normalize_frontend_url(cls, value: str) -> str:
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_security(self) -> "Settings":
        if (not self.JWT_SECRET_KEY or len(self.JWT_SECRET_KEY) < 32) and not self.DEBUG:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters outside development")
        return self

    @property
    def redis_dsn(self) -> str:
        if self.REDIS_URL:
            return self.REDIS_URL
        password = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{password}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def hsts_header_value(self) -> str:
        return f"max-age={self.SECURITY_HSTS_MAX_AGE_SECONDS}; includeSubDomains"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

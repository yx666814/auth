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
    # Access tokens are signed RS256 so other systems can verify them against
    # the public JWKS without being able to mint their own. The private key is
    # given either inline (env var) or as a path to a mounted file.
    JWT_PRIVATE_KEY: str | None = None
    JWT_PRIVATE_KEY_PATH: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    JWT_PUBLIC_KEY_PATH: str | None = None
    JWT_KEY_ID: str = "auth-1"
    # Retired public keys, as a JSON object of kid -> PEM. Tokens they signed
    # keep verifying until they expire, so rotation does not sign users out.
    JWT_PREVIOUS_PUBLIC_KEYS: str | None = None
    JWT_PREVIOUS_PUBLIC_KEYS_PATH: str | None = None
    JWT_ALGORITHM: str = "RS256"
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
    # The first administrator cannot be granted by an administrator, so this
    # list names the addresses that receive the admin role at registration.
    # Anything not in it gets DEFAULT_ROLES. Leave it empty and promote through
    # the database instead (see README: bootstrapping the first admin).
    BOOTSTRAP_ADMIN_EMAILS: list[str] = Field(default_factory=list)
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

    @field_validator("BOOTSTRAP_ADMIN_EMAILS")
    @classmethod
    def normalize_bootstrap_emails(cls, value: list[str]) -> list[str]:
        # Compare the way login does: lower-cased and trimmed, or the match
        # silently misses an address because of a stray space in the env var.
        return sorted({email.strip().lower() for email in value if email and email.strip()})

    @model_validator(mode="after")
    def validate_security(self) -> "Settings":
        if not self.DEBUG and not (
            self.JWT_PRIVATE_KEY
            or self.JWT_PRIVATE_KEY_PATH
            # A public key alone cannot sign, but allows verification-only
            # consumers (another service sharing this settings class) to start.
            or self.JWT_PUBLIC_KEY
            or self.JWT_PUBLIC_KEY_PATH
        ):
            raise ValueError(
                "JWT_PRIVATE_KEY, JWT_PRIVATE_KEY_PATH, JWT_PUBLIC_KEY or "
                "JWT_PUBLIC_KEY_PATH is required outside development"
            )
        if self.JWT_ALGORITHM != "RS256":
            raise ValueError("JWT_ALGORITHM must be RS256; HS256 shares a secret with verifiers")
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

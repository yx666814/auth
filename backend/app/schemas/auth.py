"""Validated HTTP contracts for authentication endpoints."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from ..core.config import settings


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    captcha_token: str = Field(min_length=20, max_length=256)
    captcha_value: str = Field(min_length=4, max_length=16)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if value.casefold() in settings.COMMON_PASSWORDS:
            raise ValueError("Password is too common")
        if not any(char.islower() for char in value) or not any(char.isupper() for char in value) or not any(char.isdigit() for char in value) or not any(not char.isalnum() for char in value):
            raise ValueError("Password must contain upper-case, lower-case, numeric, and special characters")
        if any(value[index] == value[index + 1] == value[index + 2] for index in range(len(value) - 2)):
            raise ValueError("Password contains too many repeated characters")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    captcha_token: str = Field(min_length=20, max_length=256)
    captcha_value: str = Field(min_length=4, max_length=16)
    device_id: str | None = Field(default=None, max_length=255)
    device_name: str | None = Field(default=None, max_length=255)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: EmailStr
    email_verified: bool

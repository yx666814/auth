"""Application dependencies kept separate from the supplied core package."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import jwt
import redis.asyncio as redis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from .core.security import check_token_blacklist, decode_access_token
from .database import get_db
from .models.user import User
from .repositories.user_repository import EmailVerificationTokenRepository, RefreshTokenRepository, UserRepository
from .services.auth_service import AuthService
from .services.captcha_service import CaptchaService
from .services.email_service import EmailService
from .core.config import settings


bearer = HTTPBearer(auto_error=False)


def get_redis(request: Request) -> redis.Redis:
    """Return the process-shared Redis pool managed by the app lifespan."""
    client = getattr(request.app.state, "redis", None)
    if client is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    return client


def get_public_tenant_id() -> UUID:
    """Public auth endpoints belong to the configured tenant.

    A multi-tenant deployment should resolve this value at the edge from an
    authenticated hostname or trusted gateway, rather than accepting a client
    supplied tenant header.
    """
    return settings.DEFAULT_TENANT_ID


def get_auth_service(
    db: AsyncSession = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    tenant_id: UUID = Depends(get_public_tenant_id),
) -> AuthService:
    return build_auth_service(db, redis_client, tenant_id)


def build_auth_service(db: AsyncSession, redis_client: redis.Redis, tenant_id: UUID) -> AuthService:
    """Build a service for a resolved tenant without trusting client headers."""
    return AuthService(
        db,
        UserRepository(db, tenant_id),
        RefreshTokenRepository(db, tenant_id),
        EmailVerificationTokenRepository(db, tenant_id),
        EmailService(db, tenant_id),
        CaptchaService(redis_client),
        tenant_id,
        redis_client,
    )


@dataclass(frozen=True)
class AuthenticatedUser:
    user: User
    token: str
    tenant_id: UUID


async def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
    _redis_client: redis.Redis = Depends(get_redis),
) -> AuthenticatedUser:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = decode_access_token(credentials.credentials)
        jti = payload.get("jti")
        if not payload.get("sub") or not payload.get("tenant_id") or (jti and await check_token_blacklist(_redis_client, jti)):
            raise jwt.InvalidTokenError("Invalid access token")
        tenant_id = UUID(payload["tenant_id"])
        user = await UserRepository(db, tenant_id).find_by_id(UUID(payload["sub"]))
    except (ValueError, jwt.InvalidTokenError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from None
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")
    return AuthenticatedUser(user=user, token=credentials.credentials, tenant_id=tenant_id)

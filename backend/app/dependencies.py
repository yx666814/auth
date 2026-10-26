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
from .core.roles import has_any_role, normalize_roles
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
    roles: tuple[str, ...] = ()


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
    # Roles come from the row, not the token claim: the row is loaded either
    # way, and reading it here means a revoked role stops working immediately
    # rather than when the token expires. The claim exists for *external*
    # consumers, which cannot query this database.
    return AuthenticatedUser(
        user=user,
        token=credentials.credentials,
        tenant_id=tenant_id,
        roles=tuple(normalize_roles(user.roles)),
    )


def require_roles(*required: str):
    """Dependency factory: allow the request only if it holds one of ``required``.

    A superuser role satisfies every requirement (see ``core.roles``), so new
    gates never need the admin list updated.

    Status codes carry meaning for API clients: 401 covers "who are you?" and
    is raised by ``get_authenticated_user``; 403 means the caller is known but
    lacks the role, so the client should not prompt for a new login.
    """
    if not required:
        raise ValueError("require_roles() needs at least one role")

    async def guard(
        current: AuthenticatedUser = Depends(get_authenticated_user),
    ) -> AuthenticatedUser:
        if not has_any_role(current.roles, required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return current

    return guard

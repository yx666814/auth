"""Authentication API routes."""

from __future__ import annotations

import base64
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from ..dependencies import (
    build_auth_service,
    get_auth_service,
    get_db,
    get_redis,
    bearer,
)
from ..core.security import decode_access_token
from ..middleware.rate_limit import enforce_rate_limit
from ..schemas.auth import LoginRequest, RefreshTokenRequest, RegisterRequest
from ..services.auth_service import AccountLockedError, AuthenticationError, AuthService
from ..services.captcha_service import CaptchaService

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/captcha")
async def captcha(redis_client=Depends(get_redis)) -> dict[str, str]:
    token, image = await CaptchaService(redis_client).generate()
    return {"token": token, "image": f"data:image/png;base64,{base64.b64encode(image).decode('ascii')}"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    http_request: Request,
    service: AuthService = Depends(get_auth_service),
    redis_client=Depends(get_redis),
) -> dict[str, str]:
    await enforce_rate_limit(http_request, redis_client, "register", limit=5, window_seconds=60)
    try:
        return await service.register(request.email, request.password, request.captcha_token, request.captcha_value)
    except AuthenticationError:
        # Keep captcha and duplicate-email failures indistinguishable.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to register this email address") from None


@router.post("/login")
async def login(
    request: LoginRequest,
    http_request: Request,
    service: AuthService = Depends(get_auth_service),
    redis_client=Depends(get_redis),
) -> dict:
    await enforce_rate_limit(http_request, redis_client, "login", limit=10, window_seconds=60)
    try:
        return await service.login(
            request.email, request.password, request.captcha_token, request.captcha_value,
            request.device_id, request.device_name,
        )
    except AccountLockedError as exc:
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=str(exc)) from exc
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials") from exc


@router.post("/refresh")
async def refresh(
    request: RefreshTokenRequest,
    http_request: Request,
    service: AuthService = Depends(get_auth_service),
    redis_client=Depends(get_redis),
) -> dict[str, str]:
    await enforce_rate_limit(http_request, redis_client, "refresh", limit=20, window_seconds=60)
    try:
        return await service.refresh(request.refresh_token)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc


@router.post("/verify-email")
async def verify_email(
    token: str = Query(min_length=20, max_length=256),
    user_id: UUID = Query(),
    service: AuthService = Depends(get_auth_service),
) -> dict[str, str]:
    try:
        await service.verify_email(token, user_id)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"message": "Email verified"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
    redis_client=Depends(get_redis),
) -> None:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = decode_access_token(credentials.credentials, verify_exp=False)
        user_id = UUID(payload["sub"])
        tenant_id = UUID(payload["tenant_id"])
    except (KeyError, ValueError, jwt.InvalidTokenError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from None
    service = build_auth_service(db, redis_client, tenant_id)
    try:
        await service.logout(credentials.credentials, user_id)
    except AuthenticationError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from None

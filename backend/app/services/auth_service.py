"""Authentication use cases and transaction boundaries."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import secrets
from typing import Any
from uuid import UUID

import jwt
import redis.asyncio as redis
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import settings
from ..core.roles import DEFAULT_ROLES, ROLE_ADMIN
from ..core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    revoke_token,
    should_rehash_password,
    verify_password,
)
from ..repositories.user_repository import (
    EmailVerificationTokenRepository,
    RefreshTokenRepository,
    UserRepository,
)
from .captcha_service import CaptchaService
from .email_service import EmailService

logger = logging.getLogger(__name__)


class AuthenticationError(ValueError):
    pass


class AccountLockedError(AuthenticationError):
    pass


class AuthService:
    def __init__(
        self,
        db: AsyncSession,
        user_repo: UserRepository,
        refresh_tokens: RefreshTokenRepository,
        email_tokens: EmailVerificationTokenRepository,
        email_service: EmailService,
        captcha_service: CaptchaService,
        tenant_id: UUID,
        redis_client: redis.Redis,
    ) -> None:
        self.db = db
        self.user_repo = user_repo
        self.refresh_tokens = refresh_tokens
        self.email_tokens = email_tokens
        self.email_service = email_service
        self.captcha_service = captcha_service
        self.tenant_id = tenant_id
        self.redis = redis_client

    async def register(self, email: str, password: str, captcha_token: str, captcha_value: str) -> dict[str, str]:
        if not await self.captcha_service.verify(captcha_token, captcha_value):
            raise AuthenticationError("Invalid or expired captcha")
        normalized_email = email.strip().lower()
        if await self.user_repo.find_by_email(normalized_email):
            raise AuthenticationError("Unable to register this email address")
        try:
            user = await self.user_repo.create(
                normalized_email,
                hash_password(password),
                roles=self._registration_roles(normalized_email),
            )
            # The verification token is committed with the user. SMTP failure
            # is non-transactional and must not discard a valid account.
            token = secrets.token_urlsafe(32)
            await self.email_tokens.create(user.id, token)
            await self.db.commit()
        except IntegrityError as exc:
            await self.db.rollback()
            raise AuthenticationError("Unable to register this email address") from exc
        try:
            await self.email_service.send_existing_verification_token(user.id, normalized_email, token)
        except Exception:
            # Retry can be offered without exposing SMTP internals to clients.
            logger.exception("Verification email delivery failed for user %s", user.id)
        return {"user_id": str(user.id), "email": normalized_email, "message": "Registration complete"}

    async def login(
        self, email: str, password: str, captcha_token: str, captcha_value: str,
        device_id: str | None = None, device_name: str | None = None,
    ) -> dict[str, Any]:
        if not await self.captcha_service.verify(captcha_token, captcha_value):
            raise AuthenticationError("Invalid credentials")
        user = await self.user_repo.find_by_email(email.strip().lower())
        if user is None or not user.is_active:
            raise AuthenticationError("Invalid credentials")
        now = datetime.now(timezone.utc)
        if user.locked_until and user.locked_until > now:
            raise AccountLockedError("Account is temporarily locked")
        if not verify_password(password, user.password_hash):
            attempts, locked_until = await self.user_repo.increment_failed_attempts(user)
            await self.db.commit()
            if locked_until and locked_until > now:
                raise AccountLockedError("Account is temporarily locked")
            raise AuthenticationError("Invalid credentials")
        if should_rehash_password(user.password_hash):
            user.password_hash = hash_password(password)
            await self.db.flush()
        await self.user_repo.reset_failed_attempts(user)
        refresh_token = create_refresh_token()
        await self.refresh_tokens.create(user.id, refresh_token, device_id, device_name)
        await self.db.commit()
        return self._token_response(user, refresh_token)

    async def refresh(self, refresh_token: str) -> dict[str, str]:
        record, _replay_detected = await self.refresh_tokens.rotate(refresh_token)
        if record is None:
            await self.db.commit()
            raise AuthenticationError("Invalid refresh token")
        user = await UserRepository(self.db, record.tenant_id).find_by_id(record.user_id)
        if user is None or not user.is_active:
            await RefreshTokenRepository(self.db, record.tenant_id).revoke_all_user_tokens(record.user_id)
            await self.db.commit()
            raise AuthenticationError("Invalid refresh token")
        await self.db.commit()
        # Roles are re-read from the row, so a demotion takes effect here on the
        # next refresh even though the old token still claims the old roles.
        access_token, _ = create_access_token(
            str(user.id), str(record.tenant_id), getattr(user, "roles", ()) or ()
        )
        return {"access_token": access_token, "refresh_token": record.token, "token_type": "bearer"}

    async def logout(self, access_token: str, user_id: UUID) -> None:
        try:
            payload = decode_access_token(access_token, verify_exp=False)
            if payload.get("sub") != str(user_id):
                raise AuthenticationError("Invalid access token")
            expiry = payload.get("exp")
            if payload.get("jti"):
                await revoke_token(self.redis, payload["jti"], expiry)
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError("Invalid access token") from exc
        await self.refresh_tokens.revoke_all_user_tokens(user_id)
        await self.db.commit()

    async def verify_email(self, token: str, user_id: UUID) -> None:
        if not await self.email_tokens.consume(token, user_id):
            raise AuthenticationError("Invalid or expired verification link")
        user = await self.user_repo.find_by_id(user_id)
        if user is None:
            raise AuthenticationError("Invalid or expired verification link")
        await self.user_repo.verify_email(user)
        await self.db.commit()

    @staticmethod
    def _registration_roles(email: str) -> list[str]:
        """Roles a brand-new account starts with.

        Normally just the baseline role. A deployment with no administrator yet
        would otherwise be unreachable through the API, so addresses named in
        ``BOOTSTRAP_ADMIN_EMAILS`` are registered as administrators instead.
        The list is configuration, not client input, so this cannot be used to
        self-promote.
        """
        if email in settings.BOOTSTRAP_ADMIN_EMAILS:
            return sorted({*DEFAULT_ROLES, ROLE_ADMIN})
        return list(DEFAULT_ROLES)

    def _token_response(self, user: Any, refresh_token: str) -> dict[str, Any]:
        roles = getattr(user, "roles", None) or ()
        access_token, _ = create_access_token(str(user.id), str(self.tenant_id), roles)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "email_verified": user.email_verified,
                "roles": sorted(roles),
            },
        }

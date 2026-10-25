# backend/app/repositories/user_repository.py (完全改正版)
"""
Repository 层 - 企业级多租户版本
不处理 commit，只处理数据访问
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, case, select, update
from typing import Optional
from dataclasses import dataclass
from uuid import UUID  # 关键修正：从 uuid 模块导入 UUID，不是 typing
from ..models.user import User, RefreshToken, EmailVerificationToken
from datetime import datetime, timezone, timedelta
import hashlib
from ..core.config import settings
from ..core.security import create_refresh_token


class UserRepository:
    """用户数据访问层"""

    def __init__(self, db: AsyncSession, tenant_id: UUID):
        self.db = db
        self.tenant_id: UUID = tenant_id  # 多租户隔离：强制所有查询都带租户ID

    async def find_by_email(self, email: str) -> Optional[User]:
        """
        根据邮箱查找用户（租户内）

        Args:
            email: 用户邮箱

        Returns:
            User 对象或 None
        """
        result = await self.db.execute(
            select(User).where(
                and_(
                    User.tenant_id == self.tenant_id,
                    User.email == email,
                    User.deleted_at.is_(None)  # 软删除过滤
                )
            )
        )
        return result.scalar_one_or_none()

    async def find_by_id(self, user_id: UUID) -> Optional[User]:
        """根据 ID 查找用户（租户内）"""
        result = await self.db.execute(
            select(User).where(
                and_(
                    User.tenant_id == self.tenant_id,
                    User.id == user_id,
                    User.deleted_at.is_(None)
                )
            )
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        email: str,
        password_hash: str,
        created_by: Optional[UUID] = None
    ) -> User:
        """
        创建新用户

        Args:
            email: 用户邮箱
            password_hash: 加密后的密码
            created_by: 创建者ID（审计）

        Returns:
            新创建的 User 对象
        """
        user = User(
            tenant_id=self.tenant_id,  # 自动填充租户ID
            email=email,
            password_hash=password_hash,
            email_verified=False,
            created_by=created_by
        )

        self.db.add(user)
        # 注意：不调用 commit，交给 Service 层处理事务
        await self.db.flush()  # flush 刷新以获取自动生成的 ID

        return user

    async def increment_failed_attempts(self, user: User) -> tuple[int, datetime | None]:
        """
        增加登录失败次数

        关键修正：
        1. 使用原子 SQL UPDATE（而不是手动 SELECT + UPDATE），避免并发竞态
        2. 从配置读取阈值，不硬编码
        3. 同时处理锁定逻辑

        Args:
            user: User 对象（主要用于获取 user_id）
        """
        now = datetime.now(timezone.utc)
        lock_until = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
        next_attempts = User.failed_login_attempts + 1
        result = await self.db.execute(
            update(User).where(
                and_(
                    User.id == user.id,
                    User.tenant_id == self.tenant_id,
                    User.deleted_at.is_(None),
                    # Do not keep extending an active lock on every attempt.
                    (User.locked_until.is_(None) | (User.locked_until <= now)),
                )
            ).values(
                failed_login_attempts=next_attempts,
                locked_until=case(
                    (next_attempts >= settings.MAX_LOGIN_ATTEMPTS, lock_until),
                    else_=User.locked_until,
                ),
                updated_by=user.id  # 审计
            ).returning(User.failed_login_attempts, User.locked_until)
        )
        row = result.first()
        if row is None:
            current = await self.db.execute(
                select(User.failed_login_attempts, User.locked_until).where(
                    and_(User.id == user.id, User.tenant_id == self.tenant_id)
                )
            )
            row = current.one()
        return row.failed_login_attempts, row.locked_until

    async def reset_failed_attempts(self, user: User) -> None:
        """重置登录失败次数"""
        await self.db.execute(
            update(User).where(
                and_(
                    User.id == user.id,
                    User.tenant_id == self.tenant_id
                )
            ).values(
                failed_login_attempts=0,
                locked_until=None,
                updated_by=user.id
            )
        )
        await self.db.refresh(user, attribute_names=["failed_login_attempts", "locked_until"])

    async def verify_email(self, user: User) -> None:
        """标记邮箱为已验证"""
        await self.db.execute(
            update(User).where(
                and_(
                    User.id == user.id,
                    User.tenant_id == self.tenant_id
                )
            ).values(
                email_verified=True,
                updated_by=user.id
            )
        )


class RefreshTokenRepository:
    """Refresh Token 数据访问层"""

    def __init__(self, db: AsyncSession, tenant_id: UUID):
        self.db = db
        self.tenant_id: UUID = tenant_id

    @staticmethod
    def _hash_token(token: str) -> str:
        """使用 SHA256 hash token（存储到数据库）"""
        return hashlib.sha256(token.encode()).hexdigest()

    async def create(
        self,
        user_id: UUID,
        token: str,
        device_id: Optional[str] = None,
        device_name: Optional[str] = None,
        expires_at: Optional[datetime] = None  # 关键修正：允许 None
    ) -> str:
        """
        创建 Refresh Token

        关键修正：expires_at 参数类型应该允许 None

        Args:
            user_id: 用户ID
            token: 原始 token 字符串
            device_id: 设备标识
            device_name: 设备名称
            expires_at: 过期时间（可选）

        Returns:
            token_hash（用于验证）
        """
        token_hash = self._hash_token(token)

        # 如果没有指定过期时间，使用配置的默认值
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            )

        refresh_token = RefreshToken(
            tenant_id=self.tenant_id,
            user_id=user_id,
            token_hash=token_hash,
            device_id=device_id,
            device_name=device_name,
            expires_at=expires_at
        )

        self.db.add(refresh_token)
        await self.db.flush()

        return token_hash

    async def revoke(
        self,
        token: str,
        user_id: UUID,
        reason: str = "user_logout"
    ) -> None:
        """撤销 token"""
        token_hash = self._hash_token(token)

        await self.db.execute(
            update(RefreshToken).where(
                and_(
                    RefreshToken.tenant_id == self.tenant_id,
                    RefreshToken.user_id == user_id,
                    RefreshToken.token_hash == token_hash
                )
            ).values(
                revoked=True,
                revoked_at=datetime.now(timezone.utc),
                revoked_reason=reason
            )
        )

    async def revoke_all_user_tokens(self, user_id: UUID) -> None:
        """撤销用户的所有 token（强制重新登录）"""
        await self.db.execute(
            update(RefreshToken).where(
                and_(
                    RefreshToken.tenant_id == self.tenant_id,
                    RefreshToken.user_id == user_id,
                    RefreshToken.revoked.is_(False)
                )
            ).values(
                revoked=True,
                revoked_at=datetime.now(timezone.utc),
                revoked_reason="security_incident"
            )
        )

    async def rotate(self, token: str) -> tuple["RotatedRefreshToken" | None, bool]:
        """Consume a refresh token and atomically issue its successor.

        Returns ``(new_record, replay_detected)``. A previously rotated token
        is treated as a replay attempt and invalidates the user's sessions.
        """
        token_hash = self._hash_token(token)
        result = await self.db.execute(
            select(RefreshToken)
            .where(
                RefreshToken.token_hash == token_hash,
            )
            .with_for_update()
        )
        current = result.scalar_one_or_none()
        if current is None:
            return None, False

        if current.revoked or current.expires_at <= datetime.now(timezone.utc):
            replay_detected = current.revoked_reason == "refresh_rotation"
            if replay_detected:
                await self.db.execute(update(RefreshToken).where(and_(RefreshToken.tenant_id == current.tenant_id, RefreshToken.user_id == current.user_id, RefreshToken.revoked.is_(False))).values(revoked=True, revoked_at=datetime.now(timezone.utc), revoked_reason="security_incident"))
            return None, replay_detected

        next_token = create_refresh_token()
        next_hash = self._hash_token(next_token)
        current.revoked = True
        current.revoked_at = datetime.now(timezone.utc)
        current.revoked_reason = "refresh_rotation"
        successor = RefreshToken(
            tenant_id=current.tenant_id,
            user_id=current.user_id,
            token_hash=next_hash,
            device_id=current.device_id,
            device_name=current.device_name,
            parent_token_hash=token_hash,
            rotation_count=(current.rotation_count or 0) + 1,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        self.db.add(successor)
        await self.db.flush()
        return RotatedRefreshToken(
            user_id=current.user_id,
            tenant_id=current.tenant_id,
            token=next_token,
            device_id=current.device_id,
            device_name=current.device_name,
        ), False


@dataclass(frozen=True)
class RotatedRefreshToken:
    user_id: UUID
    tenant_id: UUID
    token: str
    device_id: str | None
    device_name: str | None


class EmailVerificationTokenRepository:
    """邮箱验证 Token 数据访问层"""

    def __init__(self, db: AsyncSession, tenant_id: UUID):
        self.db = db
        self.tenant_id: UUID = tenant_id

    @staticmethod
    def _hash_token(token: str) -> str:
        """使用 SHA256 hash token"""
        return hashlib.sha256(token.encode()).hexdigest()

    async def create(
        self,
        user_id: UUID,
        token: str
    ) -> str:
        """
        创建邮箱验证 token

        关键修正：存储 token 的 hash，不存储明文

        Args:
            user_id: 用户ID
            token: 原始 token 字符串

        Returns:
            token_hash
        """
        token_hash = self._hash_token(token)

        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
        )

        verification_token = EmailVerificationToken(
            tenant_id=self.tenant_id,
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at
        )

        self.db.add(verification_token)
        await self.db.flush()

        return token_hash

    async def consume(self, token: str, user_id: UUID) -> bool:
        """
        验证邮箱验证 token

        Args:
            token: 原始 token 字符串
            user_id: 用户ID

        Returns:
            token 是否有效且未使用
        """
        token_hash = self._hash_token(token)

        result = await self.db.execute(
            update(EmailVerificationToken).where(
                and_(
                    EmailVerificationToken.tenant_id == self.tenant_id,
                    EmailVerificationToken.user_id == user_id,
                    EmailVerificationToken.token_hash == token_hash,
                    EmailVerificationToken.used.is_(False),
                    EmailVerificationToken.expires_at > datetime.now(timezone.utc)
                )
            ).values(used=True, used_at=datetime.now(timezone.utc)).returning(EmailVerificationToken.id)
        )
        return result.scalar_one_or_none() is not None

# backend/app/models/user.py (完全改正版 - 多租户)
"""
用户数据库模型 - 企业级多租户版本
"""
from sqlalchemy import Column, String, Boolean, Integer, DateTime, func, ForeignKey, Index, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from ..database import Base
from ..core.roles import DEFAULT_ROLES


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug = Column(String(64), nullable=False, unique=True)
    name = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class User(Base):
    """用户表 - 支持多租户"""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # 多租户隔离：每个用户属于一个租户
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False, index=True)

    email = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)

    email_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # 角色列表，例如 ["user"] 或 ["admin", "user"]。
    # A JSONB list rather than a join table: the set is small, always read in
    # full with the row, and copied verbatim into the access token.
    roles = Column(
        JSONB,
        nullable=False,
        default=lambda: list(DEFAULT_ROLES),
        server_default=text("'[\"user\"]'::jsonb"),
    )

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # 软删除
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    # 审计字段
    created_by = Column(UUID(as_uuid=True), nullable=True)  # 谁创建的
    updated_by = Column(UUID(as_uuid=True), nullable=True)  # 谁最后修改的

    # 复合索引：租户 + 邮箱（确保邮箱在租户内唯一）
    __table_args__ = (
        Index('ix_users_tenant_email', 'tenant_id', 'email', unique=True),
        # 角色查询（“这个用户是否持有 admin？”）走 JSONB 包含运算
        Index('ix_users_roles', 'roles', postgresql_using='gin'),
    )


class RefreshToken(Base):
    """Refresh Token 表 - 支持多设备管理和轮换"""
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # 多租户隔离
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False, index=True)

    # 外键：指向 User 表
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # 关键改进：存储 token 的 hash，不存储明文
    token_hash = Column(String(255), nullable=False, unique=True)

    # 设备标识：支持多设备登录管理
    device_id = Column(String(255), nullable=True)
    device_name = Column(String(255), nullable=True)  # e.g., "iPhone 14 Pro"

    # Token 轮换（refresh token rotation）
    parent_token_hash = Column(String(255), nullable=True)  # 上一个 token 的 hash
    rotation_count = Column(Integer, default=0)  # 轮换次数

    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(255), nullable=True)  # e.g., "user_logout"

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index('ix_refresh_tokens_tenant_user', 'tenant_id', 'user_id'),
        Index('ix_refresh_tokens_device', 'tenant_id', 'device_id'),
    )


class EmailVerificationToken(Base):
    """邮箱验证 Token 表"""
    __tablename__ = "email_verification_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False, index=True)

    # 外键：指向 User 表
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # 关键修正：存储 token 的 hash，而不是明文
    token_hash = Column(String(255), nullable=False, unique=True)

    # 关键修正：添加创建时间字段
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    used_at = Column(DateTime(timezone=True), nullable=True)

"""Security primitives for passwords, JWTs and request-scoped Redis."""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Optional
import secrets
import uuid
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError
import redis.asyncio as redis
from .config import settings


ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# ---------- 密码 ----------

def hash_password(password: str) -> str:
    """使用 Argon2id 加密密码"""
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    验证密码。
    捕获所有可能的异常，避免畸形 hash 或类型错误导致 500。
    """
    if not isinstance(password_hash, str) or not password_hash:
        return False
    try:
        ph.verify(password_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash, TypeError):
        return False


def should_rehash_password(password_hash: str) -> bool:
    """检查密码是否需要重新哈希（Argon2 参数升级时）"""
    if not isinstance(password_hash, str) or not password_hash:
        return False
    try:
        return ph.check_needs_rehash(password_hash)
    except (InvalidHash, TypeError):
        return False


# ---------- Access Token (JWT) ----------

def create_access_token(
    user_id: str,
    tenant_id: str,
    expires_delta: Optional[timedelta] = None,
) -> tuple[str, str]:
    """
    创建 Access Token。

    Returns:
        (token, jti)
    """
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())

    expire = now + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "jti": jti,
        "type": "access",
        "iat": now,
        "exp": expire,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return token, jti


def decode_access_token(
    token: str,
    *,
    expected_tenant_id: str | uuid.UUID | None = None,
    verify_exp: bool = True,
) -> dict:
    """
    解码并验证 Access Token 的签名、颁发者、受众、过期时间和类型。

    注意：本函数不检查黑名单。调用方在解码后，必须自行调用
    `check_token_blacklist(redis_client, payload["jti"])` 来确认 Token 未被撤销。

    Raises:
        jwt.ExpiredSignatureError
        jwt.InvalidTokenError
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "require": ["sub", "tenant_id", "jti", "type", "iat", "exp", "iss", "aud"],
                "verify_exp": verify_exp,
            },
        )
    except jwt.ExpiredSignatureError as e:
        raise jwt.ExpiredSignatureError("Access Token 已过期") from e
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f"无效的 Access Token: {e}") from e

    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("无效的 token 类型")
    if expected_tenant_id is not None and payload.get("tenant_id") != str(expected_tenant_id):
        raise jwt.InvalidTokenError("token 租户上下文不匹配")

    return payload


# ---------- Refresh Token (随机串) ----------

def create_refresh_token() -> str:
    """
    生成 Refresh Token 明文。
    数据库只存储它的 SHA256 哈希（由 repository 层负责）。
    """
    return secrets.token_urlsafe(64)


# ---------- Token 黑名单 ----------

async def check_token_blacklist(redis_client: redis.Redis, jti: str) -> bool:
    """Check a token blacklist entry using an explicit shared Redis client."""
    if not jti:
        return False
    exists = await redis_client.exists(f"token_blacklist:{jti}")
    return bool(exists)


def token_ttl(expires_at: int | float | datetime | None) -> int:
    if expires_at is None:
        return settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    timestamp = expires_at.timestamp() if isinstance(expires_at, datetime) else float(expires_at)
    return max(0, int(timestamp - datetime.now(timezone.utc).timestamp()))


async def revoke_token(
    redis_client: redis.Redis,
    jti: str,
    expires_at: int | float | datetime | None,
) -> None:
    """
    将 jti 加入黑名单。
    ``expires_at`` accepts a JWT ``exp`` claim or expiry datetime.
    """
    if not jti:
        return
    ttl = token_ttl(expires_at)
    if ttl <= 0:
        return
    await redis_client.setex(f"token_blacklist:{jti}", ttl, "1")

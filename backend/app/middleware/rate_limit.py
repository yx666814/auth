"""Redis-backed fixed-window rate limiting for sensitive authentication paths."""

from __future__ import annotations

import time

from fastapi import HTTPException, Request, status
import redis.asyncio as redis


async def enforce_rate_limit(
    request: Request, redis_client: redis.Redis, scope: str, limit: int, window_seconds: int = 60
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    window = int(time.time() // window_seconds)
    key = f"rate-limit:{scope}:{client_ip}:{window}"
    script = "local c = redis.call('INCR', KEYS[1]); if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return c"
    count = int(await redis_client.eval(script, 1, key, window_seconds + 1))
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(window_seconds)},
        )

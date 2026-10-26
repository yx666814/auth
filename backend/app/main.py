"""FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis

from .api.admin import router as admin_router
from .api.auth import router as auth_router
from .api.user import router as user_router
from .database import engine
from .core.config import settings

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", settings.SECURITY_CSP)
        if settings.SECURITY_HSTS_ENABLED and not settings.DEBUG:
            response.headers.setdefault("Strict-Transport-Security", settings.hsts_header_value)
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = redis.Redis.from_url(
        settings.redis_dsn,
        max_connections=settings.REDIS_MAX_CONNECTIONS,
        decode_responses=True,
    )
    app.state.redis = client
    logger.info("Starting %s %s", settings.APP_NAME, settings.VERSION)
    try:
        yield
    finally:
        await client.aclose()
        app.state.redis = None
        await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(auth_router, prefix="/api")
app.include_router(user_router, prefix="/api")
app.include_router(admin_router, prefix="/api")


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}

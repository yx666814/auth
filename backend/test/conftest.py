"""Test fixtures for the authentication API.

The suite runs against real PostgreSQL and Redis: the behaviour under test
(unique indexes, ``FOR UPDATE`` token rotation, Lua scripts, blocklists) is
exactly the part an in-memory fake would get wrong.

    docker compose up -d postgres redis
    docker compose exec postgres createdb -U auth auth_test
    TEST_DATABASE_URL=postgresql+asyncpg://auth:auth@localhost:5432/auth_test pytest

Environment overrides are applied before ``app`` is imported, because
``app.core.config`` builds its settings singleton at import time.
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault(
    "DATABASE_URL",
    os.environ.get(
        "TEST_DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/auth_test"
    ),
)
os.environ.setdefault("REDIS_HOST", os.environ.get("TEST_REDIS_HOST", "localhost"))
os.environ.setdefault("REDIS_PORT", os.environ.get("TEST_REDIS_PORT", "6379"))
os.environ.setdefault("REDIS_DB", "15")  # keep test cache out of the dev database's
# No signing key is configured on purpose: DEBUG=true makes the key manager mint
# an ephemeral RSA pair, which is fast and keeps tokens from surviving a run.
os.environ.setdefault("SMTP_HOST", "localhost")
os.environ.setdefault("SMTP_PORT", "1025")
os.environ.setdefault("FRONTEND_URL", "http://localhost:5173")

from sqlalchemy import text  # noqa: E402
from sqlalchemy.engine.url import make_url  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
import app.models.user  # noqa: E402,F401  (registers the tables on Base.metadata)

_schema_ready = False

TRUNCATE = text(
    "TRUNCATE TABLE email_verification_tokens, refresh_tokens, users RESTART IDENTITY CASCADE"
)


def _guard_disposable_database() -> None:
    """Refuse to truncate anything that is not obviously a test database."""
    database = make_url(settings.DATABASE_URL).database or ""
    if "test" in database.lower() or os.environ.get("ALLOW_NON_TEST_DATABASE") == "1":
        return
    raise RuntimeError(
        f"Refusing to run: DATABASE_URL points at {database!r}, which does not look "
        "disposable and this suite truncates tables. Point TEST_DATABASE_URL at a "
        "dedicated database (e.g. auth_test), or set ALLOW_NON_TEST_DATABASE=1."
    )


async def _ensure_schema() -> None:
    global _schema_ready
    if _schema_ready:
        return
    _guard_disposable_database()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(
            text(
                "INSERT INTO tenants (id, slug, name, is_active) "
                "VALUES (:id, :slug, :name, true) ON CONFLICT (id) DO NOTHING"
            ),
            {
                "id": settings.DEFAULT_TENANT_ID,
                "slug": settings.DEFAULT_TENANT_SLUG,
                "name": settings.DEFAULT_TENANT_NAME,
            },
        )
    _schema_ready = True


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """An HTTP client whose requests are served in-process by the ASGI app."""
    # httpx does not run Starlette's lifespan; entering it manually gives the
    # app its Redis client (app.state.redis), exactly as uvicorn would.
    async with app.router.lifespan_context(app):
        await _ensure_schema()
        async with engine.begin() as connection:
            await connection.execute(TRUNCATE)
        await app.state.redis.flushdb()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as http:
            yield http


@pytest.fixture
def captured_emails(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    """Collect verification emails instead of opening an SMTP connection."""
    from app.services.email_service import EmailService

    sent: list[dict[str, str]] = []

    async def fake_send(self, user_id, email, token):  # noqa: ANN001, ARG001
        sent.append({"user_id": str(user_id), "email": email, "token": token})

    monkeypatch.setattr(EmailService, "send_existing_verification_token", fake_send)
    return sent

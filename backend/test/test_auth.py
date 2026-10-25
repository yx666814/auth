"""End-to-end tests for the authentication API.

Every test drives the real ASGI app over HTTP and asserts on status codes and
response bodies only, so refactors inside the service layer stay invisible to
the suite. Captcha answers are read straight out of Redis rather than mocked
away: the one-time-consumption semantics are part of the contract.
"""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient

from app.main import app

PASSWORD = "Correct-Horse-Battery-9"  # upper, lower, digit, symbol, > 12 chars
EMAIL = "ada@example.com"


async def _captcha(client: AsyncClient) -> tuple[str, str]:
    """Fetch a challenge and return (token, answer) by reading it from Redis."""
    response = await client.get("/api/auth/captcha")
    assert response.status_code == 200
    body = response.json()
    assert body["image"].startswith("data:image/png;base64,")
    token = body["token"]
    answer = await app.state.redis.get(f"captcha:{token}")
    assert isinstance(answer, str) and len(answer) == 6
    return token, answer


async def _register(
    client: AsyncClient, email: str = EMAIL, password: str = PASSWORD
) -> dict[str, Any]:
    token, answer = await _captcha(client)
    response = await client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "captcha_token": token,
            "captcha_value": answer,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _login(client: AsyncClient, email: str = EMAIL, password: str = PASSWORD) -> dict[str, Any]:
    token, answer = await _captcha(client)
    return (
        await client.post(
            "/api/auth/login",
            json={
                "email": email,
                "password": password,
                "captcha_token": token,
                "captcha_value": answer,
                "device_id": "test-device",
                "device_name": "pytest",
            },
        )
    ).json()


async def _login_status(client: AsyncClient, password: str) -> int:
    token, answer = await _captcha(client)
    response = await client.post(
        "/api/auth/login",
        json={
            "email": EMAIL,
            "password": password,
            "captcha_token": token,
            "captcha_value": answer,
        },
    )
    return response.status_code


# --------------------------------------------------------------------------- #
# Health and transport hardening
# --------------------------------------------------------------------------- #


async def test_health_is_public_and_short(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_security_headers_are_present(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


# --------------------------------------------------------------------------- #
# Captcha
# --------------------------------------------------------------------------- #


async def test_captcha_is_single_use(client: AsyncClient) -> None:
    token, answer = await _captcha(client)
    first = await client.post(
        "/api/auth/register",
        json={
            "email": EMAIL,
            "password": PASSWORD,
            "captcha_token": token,
            "captcha_value": answer,
        },
    )
    assert first.status_code == 201

    second = await client.post(
        "/api/auth/register",
        json={
            "email": "grace@example.com",
            "password": PASSWORD,
            "captcha_token": token,
            "captcha_value": answer,
        },
    )
    assert second.status_code == 400


async def test_wrong_captcha_answer_is_rejected(client: AsyncClient) -> None:
    token, _ = await _captcha(client)
    response = await client.post(
        "/api/auth/register",
        json={
            "email": EMAIL,
            "password": PASSWORD,
            "captcha_token": token,
            "captcha_value": "WRONG1",
        },
    )
    assert response.status_code == 400


async def test_captcha_answer_is_case_insensitive(client: AsyncClient) -> None:
    token, answer = await _captcha(client)
    response = await client.post(
        "/api/auth/register",
        json={
            "email": EMAIL,
            "password": PASSWORD,
            "captcha_token": token,
            "captcha_value": answer.lower(),
        },
    )
    assert response.status_code == 201


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


async def test_register_creates_account_and_sends_verification(
    client: AsyncClient, captured_emails: list[dict[str, str]]
) -> None:
    body = await _register(client)
    assert body["email"] == EMAIL
    assert body["user_id"]
    assert len(captured_emails) == 1
    assert captured_emails[0]["email"] == EMAIL
    assert captured_emails[0]["user_id"] == body["user_id"]

    tokens = await app.state.redis.keys("token_blacklist:*")
    assert tokens == []  # registration must not issue or revoke access tokens


async def test_register_rejects_duplicate_email(client: AsyncClient) -> None:
    await _register(client)
    token, answer = await _captcha(client)
    response = await client.post(
        "/api/auth/register",
        json={
            "email": EMAIL.upper(),  # normalised server-side
            "password": PASSWORD,
            "captcha_token": token,
            "captcha_value": answer,
        },
    )
    assert response.status_code == 400


async def test_register_rejects_weak_password(client: AsyncClient) -> None:
    token, answer = await _captcha(client)
    response = await client.post(
        "/api/auth/register",
        json={
            "email": EMAIL,
            "password": "short",
            "captcha_token": token,
            "captcha_value": answer,
        },
    )
    assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Login, lockout, and rate limiting
# --------------------------------------------------------------------------- #


async def test_login_returns_tokens_and_profile(client: AsyncClient) -> None:
    await _register(client)
    body = await _login(client)

    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == EMAIL
    assert body["user"]["email_verified"] is False

    me = await client.get(
        "/api/users/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["email"] == EMAIL


async def test_login_with_wrong_password_is_401(client: AsyncClient) -> None:
    await _register(client)
    assert await _login_status(client, "Wrong-Password-123") == 401


async def test_login_for_unknown_email_is_401(client: AsyncClient) -> None:
    assert await _login_status(client, PASSWORD) == 401


async def test_account_locks_after_five_failed_attempts(client: AsyncClient) -> None:
    await _register(client)

    for _ in range(4):
        assert await _login_status(client, "Wrong-Password-123") == 401

    # The fifth failure trips the threshold and answers 423 rather than 401.
    assert await _login_status(client, "Wrong-Password-123") == 423

    # Even the correct password is refused while the lock is in force.
    assert await _login_status(client, PASSWORD) == 423


async def test_login_rate_limit_returns_429(client: AsyncClient) -> None:
    await _register(client)

    # One real request creates the fixed-window counter for this client and
    # minute; then top it up to the limit so the next request must be refused.
    # Driving the counter directly keeps the test independent of where the
    # minute boundary happens to fall.
    first = await _login_status(client, "Wrong-Password-123")
    assert first in (401, 423)

    keys = [key async for key in app.state.redis.scan_iter(match="rate-limit:login:*")]
    assert len(keys) == 1
    await app.state.redis.set(keys[0], 10)

    response = await client.post(
        "/api/auth/login",
        json={
            "email": EMAIL,
            "password": PASSWORD,
            "captcha_token": "x" * 32,
            "captcha_value": "ABC123",
        },
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"


# --------------------------------------------------------------------------- #
# Refresh-token rotation
# --------------------------------------------------------------------------- #


async def test_refresh_rotates_the_token(client: AsyncClient) -> None:
    await _register(client)
    session = await _login(client)

    response = await client.post(
        "/api/auth/refresh", json={"refresh_token": session["refresh_token"]}
    )
    assert response.status_code == 200
    rotated = response.json()
    assert rotated["refresh_token"] != session["refresh_token"]
    assert rotated["access_token"]

    # The successor is accepted on its own next rotation.
    again = await client.post(
        "/api/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
    )
    assert again.status_code == 200


async def test_replaying_a_rotated_token_revokes_every_session(client: AsyncClient) -> None:
    await _register(client)
    first = await _login(client)
    second = await _login(client)  # a second device

    rotated = await client.post(
        "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert rotated.status_code == 200
    successor = rotated.json()["refresh_token"]

    replay = await client.post(
        "/api/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert replay.status_code == 401

    # Replay is treated as a stolen-token signal: the whole family dies,
    # including the successor and the other device's token.
    for token in (successor, second["refresh_token"]):
        response = await client.post("/api/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 401


async def test_refresh_rejects_garbage(client: AsyncClient) -> None:
    response = await client.post("/api/auth/refresh", json={"refresh_token": "x" * 64})
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# Email verification
# --------------------------------------------------------------------------- #


async def test_verify_email_marks_the_account_and_cannot_be_replayed(
    client: AsyncClient, captured_emails: list[dict[str, str]]
) -> None:
    registered = await _register(client)
    token = captured_emails[0]["token"]

    response = await client.post(
        "/api/auth/verify-email",
        params={"token": token, "user_id": registered["user_id"]},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Email verified"}

    session = await _login(client)
    profile = await client.get(
        "/api/users/me", headers={"Authorization": f"Bearer {session['access_token']}"}
    )
    assert profile.json()["email_verified"] is True

    replay = await client.post(
        "/api/auth/verify-email",
        params={"token": token, "user_id": registered["user_id"]},
    )
    assert replay.status_code == 400


async def test_verify_email_rejects_unknown_token(client: AsyncClient) -> None:
    response = await client.post(
        "/api/auth/verify-email",
        params={"token": "not-a-real-token-but-long-enough", "user_id": "550e8400-e29b-41d4-a716-446655440000"},
    )
    assert response.status_code == 400


# --------------------------------------------------------------------------- #
# Logout
# --------------------------------------------------------------------------- #


async def test_logout_blacklists_the_access_token_and_revokes_refresh_tokens(
    client: AsyncClient,
) -> None:
    await _register(client)
    session = await _login(client)
    headers = {"Authorization": f"Bearer {session['access_token']}"}

    assert (await client.get("/api/users/me", headers=headers)).status_code == 200

    logout = await client.post("/api/auth/logout", headers=headers)
    assert logout.status_code == 204

    assert (await client.get("/api/users/me", headers=headers)).status_code == 401

    refresh = await client.post(
        "/api/auth/refresh", json={"refresh_token": session["refresh_token"]}
    )
    assert refresh.status_code == 401


async def test_logout_requires_a_token(client: AsyncClient) -> None:
    assert (await client.post("/api/auth/logout")).status_code == 401


async def test_protected_route_rejects_missing_bearer(client: AsyncClient) -> None:
    assert (await client.get("/api/users/me")).status_code == 401

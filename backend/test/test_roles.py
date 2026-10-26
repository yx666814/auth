"""Tests for RS256/JWKS token signing and the role system.

Split from ``test_auth.py`` (login lifecycle) so each half can be read on its
own. The captcha/register/login helpers are duplicated rather than imported
because ``test/`` is not a package; keep the two copies in step.

The central claim these tests defend is that the two authorization layers
disagree *on purpose*: an external consumer trusts the ``roles`` claim in a
token (a snapshot), while this service's own gates re-read ``users.roles`` on
every request. Both behaviours are asserted here, because a change that
"simplifies" either one would quietly break the contract.
"""

from __future__ import annotations

import json
from typing import Any

import jwt as pyjwt
import pytest
from httpx import AsyncClient
from jwt.algorithms import RSAAlgorithm

from app.core.config import settings
from app.core.jwt_keys import generate_key_pair, get_key_manager
from app.main import app

PASSWORD = "Correct-Horse-Battery-9"  # upper, lower, digit, symbol, > 12 chars
ADMIN_EMAIL = "admin@example.com"
USER_EMAIL = "ada@example.com"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


async def _captcha(client: AsyncClient) -> tuple[str, str]:
    """Fetch a challenge and return (token, answer) by reading it from Redis."""
    response = await client.get("/api/auth/captcha")
    assert response.status_code == 200
    body = response.json()
    token = body["token"]
    answer = await app.state.redis.get(f"captcha:{token}")
    assert isinstance(answer, str) and len(answer) == 6
    return token, answer


async def _register(
    client: AsyncClient, email: str = USER_EMAIL, password: str = PASSWORD
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


async def _login(
    client: AsyncClient, email: str = USER_EMAIL, password: str = PASSWORD
) -> dict[str, Any]:
    token, answer = await _captcha(client)
    response = await client.post(
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
    assert response.status_code == 200, response.text
    return response.json()


def _bearer(session: dict[str, Any]) -> dict[str, str]:
    return {"Authorization": f"Bearer {session['access_token']}"}


async def _set_roles(
    client: AsyncClient,
    headers: dict[str, str],
    user_id: str,
    roles: list[str],
) -> Any:
    return await client.post(
        f"/api/admin/users/{user_id}/roles", json={"roles": roles}, headers=headers
    )


def _claims(token: str) -> dict[str, Any]:
    """Read a token's claims without verifying it — for assertions only.

    Verification against the published JWKS has its own test; here we only care
    what was put into the claim. ``verify_aud``/``verify_exp`` are switched off
    because PyJWT would otherwise reject the document before returning it.
    """
    return pyjwt.decode(
        token,
        options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
    )


@pytest.fixture
def bootstrap_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Name an address in BOOTSTRAP_ADMIN_EMAILS before it registers.

    Registration is the only path to a first administrator, so this is the
    supported way to obtain one in a test — no database poke, no bypass of the
    service layer.
    """
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAILS", [ADMIN_EMAIL])


async def _admin_session(client: AsyncClient) -> dict[str, Any]:
    """Register and sign in the bootstrap administrator."""
    await _register(client, email=ADMIN_EMAIL)
    return await _login(client, email=ADMIN_EMAIL)


async def _user_session(client: AsyncClient) -> dict[str, Any]:
    await _register(client, email=USER_EMAIL)
    return await _login(client, email=USER_EMAIL)


# --------------------------------------------------------------------------- #
# JWKS
# --------------------------------------------------------------------------- #


async def test_jwks_publishes_only_public_key_material(client: AsyncClient) -> None:
    response = await client.get("/api/auth/jwks")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "public, max-age=300"

    keys = response.json()["keys"]
    assert len(keys) == 1  # no retired keys are configured in the test env

    key = keys[0]
    assert key["kid"] == get_key_manager().kid
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["e"] and key["n"]

    # A JWKS that shipped "d" (or any CRT factor) hands out the private key and
    # with it the ability to mint tokens for every user and role.
    assert not {"d", "p", "q", "dp", "dq", "qi", "oth"} & set(key)


async def test_issued_token_verifies_against_the_published_jwks(
    client: AsyncClient,
) -> None:
    await _register(client)
    session = await _login(client)
    token = session["access_token"]

    header = pyjwt.get_unverified_header(token)
    assert header["typ"] == "at"  # RFC 9068: lets consumers reject ID tokens
    assert header["alg"] == "RS256"

    published = (await client.get("/api/auth/jwks")).json()["keys"]
    matching = [key for key in published if key["kid"] == header["kid"]]
    assert len(matching) == 1

    # This is the integration contract: an outside system with nothing but the
    # JWKS document can verify the token and read its roles.
    public_key = RSAAlgorithm.from_jwk(json.dumps(matching[0]))
    claims = pyjwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
    )
    assert claims["type"] == "access"
    assert claims["roles"] == ["user"]
    assert claims["sub"] == session["user"]["id"]


async def test_token_signed_with_a_foreign_key_is_rejected(client: AsyncClient) -> None:
    """Possession of the JWKS must not be enough to mint a token."""
    await _register(client)
    session = await _login(client)
    user_id = session["user"]["id"]

    foreign_private, _ = generate_key_pair()
    forged = pyjwt.encode(
        {
            "sub": user_id,
            "tenant_id": str(settings.DEFAULT_TENANT_ID),
            "jti": "forged",
            "type": "access",
            "roles": ["admin"],
            "iat": 1_700_000_000,
            "exp": 4_102_444_800,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        },
        foreign_private,
        algorithm="RS256",
        # Claims the *active* key's id, so only the signature distinguishes it.
        headers={"kid": get_key_manager().kid, "typ": "at"},
    )

    response = await client.get(
        "/api/users/me", headers={"Authorization": f"Bearer {forged}"}
    )
    assert response.status_code == 401


async def test_token_naming_an_unknown_key_is_rejected(client: AsyncClient) -> None:
    await _register(client)
    session = await _login(client)

    # Signed with the real key, but claiming a kid that is neither active nor
    # retired: the verifier refuses to guess which key was used.
    claims = _claims(session["access_token"])
    response = await client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {session['access_token']}"},
    )
    assert response.status_code == 200  # sanity: the token itself is fine

    unknown_kid = pyjwt.encode(
        claims,
        get_key_manager().private_key,
        algorithm="RS256",
        headers={"kid": "retired-key-9", "typ": "at"},
    )
    rejected = await client.get(
        "/api/users/me", headers={"Authorization": f"Bearer {unknown_kid}"}
    )
    assert rejected.status_code == 401


# --------------------------------------------------------------------------- #
# Role gates: 401 vs 403
# --------------------------------------------------------------------------- #


async def test_admin_routes_are_401_without_a_token(client: AsyncClient) -> None:
    assert (await client.get("/api/admin/roles")).status_code == 401
    assert (await client.get("/api/admin/users")).status_code == 401


async def test_admin_routes_are_403_for_an_authenticated_non_admin(
    client: AsyncClient,
) -> None:
    session = await _user_session(client)
    headers = _bearer(session)

    for path in ("/api/admin/roles", "/api/admin/users"):
        response = await client.get(path, headers=headers)
        # 403, not 401: the caller is known, so the client must not re-prompt
        # for a login — the request can only fail again.
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient role"


# --------------------------------------------------------------------------- #
# Bootstrapping and the admin surface
# --------------------------------------------------------------------------- #


async def test_bootstrap_admin_registers_with_the_admin_role(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    await _register(client, email=ADMIN_EMAIL)
    session = await _login(client, email=ADMIN_EMAIL)

    assert session["user"]["roles"] == ["admin", "user"]
    assert _claims(session["access_token"])["roles"] == ["admin", "user"]

    me = await client.get("/api/users/me", headers=_bearer(session))
    assert me.status_code == 200
    assert me.json()["roles"] == ["admin", "user"]


async def test_registration_grants_only_the_baseline_role(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    session = await _user_session(client)
    # An address not in BOOTSTRAP_ADMIN_EMAILS gets nothing extra, which is
    # what keeps self-promotion impossible.
    assert session["user"]["roles"] == ["user"]


async def test_admin_lists_the_role_vocabulary(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    session = await _admin_session(client)
    response = await client.get("/api/admin/roles", headers=_bearer(session))
    assert response.status_code == 200

    names = [entry["name"] for entry in response.json()]
    assert names == ["admin", "support", "user"]
    assert all(entry["description"] for entry in response.json())


async def test_admin_lists_accounts_in_the_tenant(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    admin = await _admin_session(client)
    await _register(client, email=USER_EMAIL)

    response = await client.get("/api/admin/users", headers=_bearer(admin))
    assert response.status_code == 200
    by_email = {entry["email"]: entry for entry in response.json()}
    assert set(by_email) == {ADMIN_EMAIL, USER_EMAIL}
    assert by_email[ADMIN_EMAIL]["roles"] == ["admin", "user"]
    assert by_email[USER_EMAIL]["roles"] == ["user"]


# --------------------------------------------------------------------------- #
# Assigning roles
# --------------------------------------------------------------------------- #


async def test_assigned_roles_apply_to_an_existing_token_immediately(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    """The service's own gates read the row, not the claim in the token."""
    admin = await _admin_session(client)
    user = await _user_session(client)
    user_headers = _bearer(user)

    assert (await client.get("/api/admin/roles", headers=user_headers)).status_code == 403

    response = await _set_roles(
        client, _bearer(admin), user["user"]["id"], ["admin", "user"]
    )
    assert response.status_code == 200
    assert response.json()["roles"] == ["admin", "user"]

    # Same token, no re-login: the promotion is live because the gate re-reads
    # users.roles. (The token's own claim still says ["user"].)
    assert _claims(user["access_token"])["roles"] == ["user"]
    assert (await client.get("/api/admin/roles", headers=user_headers)).status_code == 200


async def test_demotion_also_applies_immediately(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    admin = await _admin_session(client)
    admin_headers = _bearer(admin)
    user = await _user_session(client)

    await _set_roles(client, admin_headers, user["user"]["id"], ["admin", "user"])
    assert (await client.get("/api/admin/roles", headers=_bearer(user))).status_code == 200

    demoted = await _set_roles(client, admin_headers, user["user"]["id"], ["user"])
    assert demoted.status_code == 200
    assert (await client.get("/api/admin/roles", headers=_bearer(user))).status_code == 403


async def test_unknown_role_is_rejected(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    admin = await _admin_session(client)
    user = await _user_session(client)

    response = await _set_roles(
        client, _bearer(admin), user["user"]["id"], ["wizard"]
    )
    assert response.status_code == 400
    assert "wizard" in response.json()["detail"]

    # Nothing was written: the account still has its baseline role.
    me = await client.get("/api/users/me", headers=_bearer(user))
    assert me.json()["roles"] == ["user"]


async def test_setting_roles_for_an_unknown_account_is_404(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    admin = await _admin_session(client)
    response = await _set_roles(
        client,
        _bearer(admin),
        "11111111-1111-1111-1111-111111111111",
        ["user"],
    )
    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# Last-administrator guard
# --------------------------------------------------------------------------- #


async def test_last_admin_cannot_be_demoted(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    admin = await _admin_session(client)

    response = await _set_roles(client, _bearer(admin), admin["user"]["id"], ["user"])
    assert response.status_code == 409
    assert response.json()["detail"] == "Cannot remove the last administrator"

    # Refused, so the administrator still is one.
    assert (await client.get("/api/admin/roles", headers=_bearer(admin))).status_code == 200


async def test_admin_may_step_down_once_another_admin_exists(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    admin = await _admin_session(client)
    admin_headers = _bearer(admin)
    user = await _user_session(client)

    promoted = await _set_roles(
        client, admin_headers, user["user"]["id"], ["admin", "user"]
    )
    assert promoted.status_code == 200

    stepped_down = await _set_roles(
        client, admin_headers, admin["user"]["id"], ["user"]
    )
    assert stepped_down.status_code == 200

    # The old admin's token stops opening the admin API at once; the new
    # administrator's keeps working.
    assert (await client.get("/api/admin/roles", headers=admin_headers)).status_code == 403
    assert (await client.get("/api/admin/roles", headers=_bearer(user))).status_code == 200


# --------------------------------------------------------------------------- #
# Snapshot vs. live roles on refresh
# --------------------------------------------------------------------------- #


async def test_refresh_reissues_the_roles_claim_from_the_row(
    client: AsyncClient, bootstrap_admin: None
) -> None:
    """External consumers see a change at the next refresh, at the latest."""
    admin = await _admin_session(client)
    user = await _user_session(client)
    assert _claims(user["access_token"])["roles"] == ["user"]

    changed = await _set_roles(
        client, _bearer(admin), user["user"]["id"], ["support", "user"]
    )
    assert changed.status_code == 200

    refreshed = await client.post(
        "/api/auth/refresh", json={"refresh_token": user["refresh_token"]}
    )
    assert refreshed.status_code == 200
    assert _claims(refreshed.json()["access_token"])["roles"] == ["support", "user"]

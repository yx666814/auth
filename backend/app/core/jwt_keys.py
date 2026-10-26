"""Asymmetric signing keys for access tokens, plus the public JWKS document.

Why RS256 and not HS256
-----------------------
An HMAC secret verifies *and* signs, so every party that can check a token can
also mint one. That is fine inside a single process, but this service is meant
to be consumed by other systems: handing each integrator the signing secret
would let any of them forge tokens for every other system. RS256 splits the two
- the private key never leaves this service, and consumers verify against the
public key published at the JWKS endpoint.

Key rotation
------------
Tokens carry a ``kid`` header naming the key that signed them. Retiring a key
means generating a new pair, publishing it as active, and keeping the old
*public* key in ``JWT_PREVIOUS_PUBLIC_KEYS`` until every token it signed has
expired (access tokens live 15 minutes, so a 30-minute overlap is ample). The
JWKS document lists both, which is why rotation does not force a sign-out.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.algorithms import RSAAlgorithm

from .config import settings

logger = logging.getLogger(__name__)

# RFC 9068: the JOSE ``typ`` header of an access token. Setting it lets a
# consumer reject an ID token that was presented in place of an access token.
ACCESS_TOKEN_TYPE = "at"


def _read_key_material(inline: str | None, path: str | None) -> str | None:
    """Return PEM text from whichever of the two settings is populated.

    Inline values are useful where the orchestrator injects a secret as an
    environment variable (Docker Compose, Kubernetes); a path is expected to
    hold a mounted file. Newlines are restored because PEM can never survive a
    single-line env var otherwise.
    """
    if inline:
        return inline.replace("\\n", "\n")
    if path:
        return Path(path).read_text(encoding="utf-8")
    return None


def generate_key_pair() -> tuple[str, str]:
    """Create a fresh RSA-2048 key pair, returned as ``(private_pem, public_pem)``."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def public_key_from_private(private_pem: str) -> str:
    """Derive the public half of a private key, so only one value must be set."""
    key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


class KeyManager:
    """Loads the signing keys once and serves the active private key and JWKS."""

    def __init__(self) -> None:
        private_pem = _read_key_material(settings.JWT_PRIVATE_KEY, settings.JWT_PRIVATE_KEY_PATH)
        public_pem = _read_key_material(settings.JWT_PUBLIC_KEY, settings.JWT_PUBLIC_KEY_PATH)

        if private_pem is None and public_pem is None and settings.DEBUG:
            # Development convenience: no key configured, so mint an ephemeral
            # pair. Tokens do not survive a restart, which is correct for a
            # throwaway local stack and impossible to do by accident in prod
            # (the settings validator refuses to start).
            logger.warning("No JWT signing key configured; generating an ephemeral RSA key pair")
            private_pem, public_pem = generate_key_pair()

        if private_pem is None:
            raise RuntimeError(
                "JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH is required to sign access tokens"
            )
        if public_pem is None:
            public_pem = public_key_from_private(private_pem)

        self._private_pem = private_pem
        self._public_pem = public_pem
        self._kid = settings.JWT_KEY_ID
        self._loaded_at = datetime.now(timezone.utc)

        # Keys that signed tokens still in circulation after a rotation. Only
        # the public half is needed, and only for verification.
        self._previous: dict[str, str] = self._load_previous_keys()

    def _load_previous_keys(self) -> dict[str, str]:
        raw = _read_key_material(
            settings.JWT_PREVIOUS_PUBLIC_KEYS, settings.JWT_PREVIOUS_PUBLIC_KEYS_PATH
        )
        if not raw:
            return {}
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise RuntimeError("JWT_PREVIOUS_PUBLIC_KEYS must be a JSON object of kid -> PEM")
        return {str(kid): str(pem) for kid, pem in parsed.items()}

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def private_key(self) -> str:
        return self._private_pem

    @property
    def public_key(self) -> str:
        return self._public_pem

    def verification_key(self, kid: str | None) -> str | None:
        """Return the public key for a token's ``kid``, or None if it is unknown.

        A missing ``kid`` is only accepted for the active key: tokens issued
        before key IDs existed, and every token this service issues, carry one.
        """
        if kid is None or kid == self._kid:
            return self._public_pem
        return self._previous.get(kid)

    def jwks(self) -> dict[str, list[dict]]:
        """The public JWKS document: active key first, then retired ones."""
        keys = [self._to_jwk(self._public_pem, self._kid)]
        keys.extend(self._to_jwk(pem, kid) for kid, pem in self._previous.items())
        return {"keys": keys}

    @staticmethod
    def _to_jwk(public_pem: str, kid: str) -> dict:
        jwk = json.loads(RSAAlgorithm.to_jwk(public_pem))
        jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
        return jwk


_manager: KeyManager | None = None


def get_key_manager() -> KeyManager:
    """Return the process-wide key manager, loading it on first use."""
    global _manager
    if _manager is None:
        _manager = KeyManager()
    return _manager


def reset_key_manager() -> None:
    """Drop the cached manager so tests can swap key configuration."""
    global _manager
    _manager = None

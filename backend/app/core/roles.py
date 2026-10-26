"""Role vocabulary shared by token issuance and the authorization gates.

A role here *is* a permission: ``roles`` in an access token is the list of
strings another system can be expected to recognise. That keeps the contract
readable by an outside consumer (``"admin" in roles``) without shipping a
permission catalogue nobody agreed on. If a deployment needs finer-grained
permissions, map roles to permissions there — the token stays as it is.

``admin`` is a superuser role: it satisfies every requirement. Everything else
must be matched explicitly.

Roles are snapshotted into the access token at issue time so a downstream
system can authorize without calling back here. This service's own gates
re-read ``users.roles`` on every request (the user row is loaded anyway), so a
revoked role takes effect immediately *here*, while an external consumer sees
the snapshot until the token expires (at most ACCESS_TOKEN_EXPIRE_MINUTES).
"""

from __future__ import annotations

from collections.abc import Iterable
import re

ROLE_ADMIN = "admin"
ROLE_SUPPORT = "support"
ROLE_USER = "user"

# Every new account starts here. Registration never grants anything else; an
# administrator has to promote it (or BOOTSTRAP_SUPERUSER_EMAILS has to name it).
DEFAULT_ROLES: tuple[str, ...] = (ROLE_USER,)

# What the admin API is allowed to hand out, with the meaning shown in docs and
# in GET /api/admin/roles.
ASSIGNABLE_ROLES: dict[str, str] = {
    ROLE_ADMIN: "Full access, including administering users and their roles",
    ROLE_SUPPORT: "Read-only access to other accounts for support purposes",
    ROLE_USER: "Baseline role every account receives at registration",
}

SUPERUSER_ROLES: frozenset[str] = frozenset({ROLE_ADMIN})

_ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9:_-]{0,63}$")


class InvalidRoleError(ValueError):
    """A caller asked for a role this deployment does not hand out."""


def normalize_roles(roles: Iterable[str] | None) -> list[str]:
    """Return a clean, deterministic role list.

    Deduplicates and sorts, because the token claim is compared by value in
    more than one place and an unordered JSON list would make that fragile.
    Unknown role names are *kept* here: this function must stay safe to call on
    a token claim or a database row written by an older version. Rejecting
    unknown names is :func:`validate_roles`' job, at the API boundary.
    """
    if not roles:
        return []
    cleaned = {
        str(role).strip().lower()
        for role in roles
        if role is not None and str(role).strip()
    }
    return sorted(cleaned)


def validate_roles(roles: Iterable[str] | None) -> list[str]:
    """Normalize roles for assignment, rejecting anything not assignable.

    Raises:
        InvalidRoleError: the list is empty, or names a role that is not in
            ``ASSIGNABLE_ROLES``.
    """
    normalized = normalize_roles(roles)
    if not normalized:
        raise InvalidRoleError("At least one role is required")
    malformed = [role for role in normalized if not _ROLE_PATTERN.match(role)]
    if malformed:
        raise InvalidRoleError(f"Malformed role name: {malformed[0]}")
    unknown = [role for role in normalized if role not in ASSIGNABLE_ROLES]
    if unknown:
        raise InvalidRoleError(
            f"Unknown role: {unknown[0]}. Assignable roles: "
            + ", ".join(sorted(ASSIGNABLE_ROLES))
        )
    return normalized


def is_superuser(roles: Iterable[str] | None) -> bool:
    """True when the role set includes a superuser role."""
    return bool(set(roles or ()) & SUPERUSER_ROLES)


def has_any_role(granted: Iterable[str] | None, required: Iterable[str]) -> bool:
    """Whether ``granted`` satisfies any of ``required``.

    A superuser role satisfies every requirement, so adding a new gate never
    needs the admin list updated.
    """
    granted_set = set(granted or ())
    if granted_set & SUPERUSER_ROLES:
        return True
    return bool(granted_set & set(required))

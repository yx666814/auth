"""Administrative routes for inspecting accounts and assigning roles.

Every route here is gated on a superuser role. The gate reads ``users.roles``
from the database on each request (see ``dependencies.require_roles``), so a
demotion takes effect on the very next call even though the caller's token
still carries the old ``roles`` claim.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.roles import (
    ASSIGNABLE_ROLES,
    ROLE_ADMIN,
    InvalidRoleError,
    is_superuser,
    validate_roles,
)
from ..database import get_db
from ..dependencies import AuthenticatedUser, require_roles
from ..repositories.user_repository import UserRepository
from ..schemas.auth import AdminUserResponse, RoleInfo, SetRolesRequest

router = APIRouter(prefix="/admin", tags=["administration"])


@router.get("/roles", response_model=list[RoleInfo])
async def list_roles(
    _: AuthenticatedUser = Depends(require_roles(ROLE_ADMIN)),
) -> list[RoleInfo]:
    """The role vocabulary this deployment hands out, with its meaning."""
    return [
        RoleInfo(name=name, description=description)
        for name, description in sorted(ASSIGNABLE_ROLES.items())
    ]


@router.get("/users", response_model=list[AdminUserResponse])
async def list_users(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: AuthenticatedUser = Depends(require_roles(ROLE_ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[AdminUserResponse]:
    """Accounts in the caller's tenant, oldest first so paging is stable."""
    users = await UserRepository(db, principal.tenant_id).list_users(limit=limit, offset=offset)
    return [
        AdminUserResponse(
            id=str(user.id),
            email=user.email,
            roles=list(user.roles or []),
            is_active=bool(user.is_active),
            email_verified=bool(user.email_verified),
            created_at=user.created_at.isoformat(),
        )
        for user in users
    ]


@router.post("/users/{user_id}/roles", response_model=AdminUserResponse)
async def set_user_roles(
    user_id: UUID,
    request: SetRolesRequest,
    principal: AuthenticatedUser = Depends(require_roles(ROLE_ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> AdminUserResponse:
    """Replace an account's role list.

    Tokens already issued keep the old roles until they expire or are
    refreshed; this service's own gates pick the change up immediately.
    """
    repository = UserRepository(db, principal.tenant_id)
    target = await repository.find_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    try:
        roles = validate_roles(request.roles)
    except InvalidRoleError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # Losing the last superuser locks everyone out of this API, with no way
    # back short of editing the database. Refuse that one transition; handing
    # admin to somebody else first is always possible.
    if is_superuser(target.roles) and not is_superuser(roles):
        others = await repository.count_superusers(exclude_user_id=target.id)
        if others == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot remove the last administrator",
            )

    stored = await repository.set_roles(target, roles, updated_by=principal.user.id)
    await db.commit()
    return AdminUserResponse(
        id=str(target.id),
        email=target.email,
        roles=stored,
        is_active=bool(target.is_active),
        email_verified=bool(target.email_verified),
        created_at=target.created_at.isoformat(),
    )

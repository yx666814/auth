"""Authenticated user routes."""

from fastapi import APIRouter, Depends

from ..dependencies import AuthenticatedUser, get_authenticated_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me")
async def me(principal: AuthenticatedUser = Depends(get_authenticated_user)) -> dict[str, str | bool]:
    user = principal.user
    return {
        "id": str(user.id),
        "email": user.email,
        "email_verified": user.email_verified,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat(),
    }

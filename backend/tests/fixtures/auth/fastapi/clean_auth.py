"""FastAPI fixture with correctly implemented authentication and authorization.

Should yield zero security debt findings.
"""

from fastapi import APIRouter, Depends, HTTPException, Security, status
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/secure")


class User(BaseModel):
    id: str
    username: str
    role: str


def get_current_user() -> User:
    """Dependency verifying caller credentials."""
    return User(id="u1", username="alice", role="user")


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Dependency enforcing admin role."""
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return user


@router.get("/profile")
def get_profile(current_user: User = Depends(get_current_user)):
    """Properly authenticated profile view."""
    return {"user": current_user.username}


@router.post("/settings")
def update_settings(payload: dict, current_user: User = Depends(get_current_user)):
    """Properly authenticated settings update."""
    return {"status": "updated", "user": current_user.username}


@router.get("/admin/dashboard")
def admin_dashboard(admin: User = Depends(require_admin)):
    """Properly authenticated and authorized admin dashboard."""
    return {"metrics": [1, 2, 3]}


@router.delete("/admin/users/{user_id}")
def purge_user(user_id: str, admin: User = Depends(require_admin)):
    """Properly authenticated and authorized admin user deletion."""
    return {"deleted": user_id}


@router.get("/health")
def health_check():
    """Explicitly public unauthenticated health endpoint."""
    return {"status": "ok"}

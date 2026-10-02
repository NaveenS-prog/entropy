"""FastAPI fixture with intentional authentication and authorization debt patterns.

Contains exact patterns for positive rule testing:
- ENT-AUTH-001: Unprotected security sensitive endpoint
- ENT-AUTH-002: Inconsistent authentication in group
- ENT-AUTH-003: Duplicated local authentication logic
- ENT-AUTHZ-001: Potentially missing authorization on admin route
- ENT-AUTHZ-002: Inconsistent authorization in admin group
- ENT-AUTHZ-003: Duplicated local authorization logic
"""

from fastapi import APIRouter, Depends, HTTPException, Request

router = APIRouter()


def get_current_user():
    return {"id": "1", "role": "user"}


# --- ENT-AUTH-001: Standalone security-sensitive unprotected route ---
@router.post("/payments/charge")
def charge_payment(amount: float):
    return {"status": "charged", "amount": amount}


# --- ENT-AUTH-002: Inconsistent authentication within the /account group ---
@router.get("/account/overview")
def account_overview(user=Depends(get_current_user)):
    return {"overview": "ok"}


@router.get("/account/settings")
def account_settings(user=Depends(get_current_user)):
    return {"settings": "ok"}


@router.get("/account/history")
def account_history():
    # Inconsistent: omitted auth in /account group
    return {"history": []}


# --- ENT-AUTH-003: Duplicated inline header extraction ---
@router.get("/verify/token_a")
def verify_token_a(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401)
    return {"valid": True}


@router.get("/verify/token_b")
def verify_token_b(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401)
    return {"valid": True}


# --- ENT-AUTHZ-001: Standalone administrative endpoint missing authorization check ---
@router.post("/system/reset")
def system_reset(user=Depends(get_current_user)):
    # Authenticated user, but no role or permission check before destructive action!
    return {"reset": True}


# --- ENT-AUTHZ-002: Inconsistent authorization in /admin group ---
@router.get("/admin/users")
def list_admin_users(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403)
    return {"users": []}


@router.get("/admin/roles")
def list_admin_roles(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403)
    return {"roles": []}


@router.get("/admin/config")
def get_admin_config(user=Depends(get_current_user)):
    # Inconsistent: user is authenticated, but role check is missing in admin group!
    return {"config": {}}


# --- ENT-AUTHZ-003: Duplicated inline authorization checks ---
@router.post("/ops/run_job_a")
def run_job_a(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"job": "a"}


@router.post("/ops/run_job_b")
def run_job_b(user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"job": "b"}

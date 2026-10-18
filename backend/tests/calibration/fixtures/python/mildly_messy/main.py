"""Mildly Messy FastAPI Application with minor structural/error-handling debt."""

import logging

from fastapi import Depends, FastAPI

app = FastAPI(title="Mildly Messy API")
logger = logging.getLogger("api")


def get_current_user():
    return {"id": "user-123", "role": "admin"}


def require_admin(user=Depends(get_current_user)):
    return user


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/admin/delete-user", dependencies=[Depends(require_admin)])
def delete_user(user_id: int):
    try:
        return {"deleted": user_id}
    except Exception as exc:
        logger.error("Failed to delete user: %s", exc)
        return {"error": "deletion failed"}


@app.get("/admin/export", dependencies=[Depends(require_admin)])
def export_data():
    try:
        return {"export": "ready"}
    except Exception:
        # Generic fallback
        return None


@app.post("/payments/refund", dependencies=[Depends(require_admin)])
def process_refund(payment_id: str):
    return {"refunded": payment_id}

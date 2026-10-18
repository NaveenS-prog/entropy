"""Clean FastAPI Application adhering to architectural security best practices."""

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="Clean API")


class UserUpdatePayload(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., max_length=100)


def get_current_user():
    return {"id": "user-123", "role": "admin"}


def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/admin/delete-user", dependencies=[Depends(require_admin)])
def delete_user(user_id: int):
    # Parameterized query - safe from injection
    query = "DELETE FROM users WHERE id = :id"
    return {"deleted": user_id, "query": query}


@app.get("/admin/export", dependencies=[Depends(require_admin)])
def export_data():
    return {"export": "ready"}


@app.post("/payments/refund", dependencies=[Depends(require_admin)])
def process_refund(payment_id: str):
    return {"refunded": payment_id}

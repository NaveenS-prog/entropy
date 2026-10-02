"""Clean Input Validation Fixture: Idiomatic FastAPI & Pydantic models with schema validation."""

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, Query
from typing import Annotated

router = APIRouter(prefix="/users")

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=100)
    age: int = Field(..., ge=18, le=120)

class UserUpdate(BaseModel):
    email: str | None = None
    age: int | None = None

def get_current_user():
    return {"id": 1, "username": "alice"}

@router.post("/create")
def create_user(payload: UserCreate, current_user=Depends(get_current_user)):
    """Clean endpoint utilizing strong Pydantic model validation."""
    return {"status": "created", "username": payload.username}

@router.put("/update/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    current_user=Depends(get_current_user)
):
    """Clean endpoint with typed path parameter and Pydantic update schema."""
    return {"status": "updated", "user_id": user_id}

@router.get("/search")
def search_users(
    q: Annotated[str, Query(min_length=2, max_length=50)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    """Clean query endpoint with FastAPI Query constraints."""
    return {"query": q, "limit": limit}

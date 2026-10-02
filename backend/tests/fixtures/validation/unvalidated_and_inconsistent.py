"""Input Validation Debt Fixture: Unvalidated input, inconsistent siblings, direct sink."""

import os
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/users")

class UserCreate(BaseModel):
    username: str
    email: str

# Inconsistent validation: /users/register uses schema, /users/profile_update uses raw dict
@router.post("/users/register")
def register_user(payload: UserCreate):
    return {"status": "registered"}

@router.post("/users/profile_update")
def profile_update(data: dict):
    # ENT-INPUT-002: Inconsistent Input Validation (and ENT-INPUT-001 suppressed)
    return {"updated": data.get("email")}

# Standalone unvalidated sensitive route
billing_router = APIRouter(prefix="/billing")

@billing_router.post("/billing/charge")
def charge_customer(raw_payload: dict):
    # ENT-INPUT-001: Potentially Unvalidated External Input
    amount = raw_payload.get("amount")
    return {"charged": amount}

# Unsafe direct input usage into SQL query and subprocess command
search_router = APIRouter(prefix="/search")

@search_router.get("/search/query")
def search_items(q: str):
    # ENT-INPUT-003: External input formatted directly into SQL query
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE name = '{q}'")
    return {"results": []}

@search_router.post("/search/ping")
def ping_host(host: str):
    # ENT-INPUT-003: External input passed directly to command execution
    os.system(f"ping -c 1 {host}")
    return {"pinged": host}

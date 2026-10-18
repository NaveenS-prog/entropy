"""Deliberately Insecure FastAPI Application.

Unprotected admin & payment routes with raw string-concatenated SQL sink.
"""

import sqlite3

from fastapi import FastAPI

app = FastAPI(title="Insecure API")


@app.post("/admin/delete-user")
def delete_user(user_id: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Unsafe direct input flow to SQL sink via concatenation
    query = "DELETE FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    conn.commit()
    return {"deleted": user_id}


@app.get("/admin/export")
def export_data():
    # Unprotected privileged endpoint
    return {"export": "all_user_records"}


@app.post("/payments/refund")
def process_refund(refund_id: str, amount: float):
    # Unprotected security-sensitive mutating financial route
    return {"refund_id": refund_id, "amount": amount, "status": "refunded"}

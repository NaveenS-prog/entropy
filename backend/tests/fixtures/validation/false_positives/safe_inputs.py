"""False Positives Mitigation Fixture: Internal functions, parameterized SQL, safe commands."""

import sqlite3
import subprocess

# 1. Ordinary internal functions (NOT route endpoints)
def calculate_tax(amount: float, rate: float = 0.05) -> float:
    """Internal business calculation helper with raw primitives."""
    return amount * (1.0 + rate)

def internal_data_parser(data: dict):
    """Internal dictionary parser not bound to any web framework route."""
    return data.get("key", "default")

# 2. Parameterized SQL queries (SAFE - not vulnerable to SQL injection)
def fetch_user_by_id(user_id: int):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Safe parameterized query with tuple parameters
    cursor.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# 3. Safe subprocess execution using argument list without shell=True
def execute_safe_git_status():
    result = subprocess.run(["git", "status"], capture_output=True, text=True)
    return result.stdout

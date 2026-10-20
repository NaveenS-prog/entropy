#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR/backend"

echo "=== Starting Entropy Backend Server ==="
export ENTROPY_ALLOW_LOCALHOST_NO_KEY=true

if [ -f ".venv/bin/uvicorn" ]; then
    PYTHON_BIN=".venv/bin/python"
    UVICORN_BIN=".venv/bin/uvicorn"
else
    PYTHON_BIN="python3"
    UVICORN_BIN="uvicorn"
fi

echo "API Docs will be available at: http://localhost:8000/docs"
echo "Health check endpoint: http://localhost:8000/api/v1/health"
echo "Press Ctrl+C to stop the server."

exec "$UVICORN_BIN" app.main:app --host 0.0.0.0 --port 8000 --reload

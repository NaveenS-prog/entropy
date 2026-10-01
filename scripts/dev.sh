#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/home/naveen/.local/bin:$PATH"

echo "=== Starting SilentGuard Local Development ==="

# Trap cleanup to kill child processes
cleanup() {
    echo "Stopping SilentGuard services..."
    kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting Backend on http://localhost:8000..."
cd "$DIR/backend"
PYTHONPATH=. .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

echo "Starting Frontend on http://localhost:3000..."
cd "$DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo "SilentGuard is running:"
echo "  - Backend API: http://localhost:8000 (Docs: http://localhost:8000/docs)"
echo "  - Frontend UI: http://localhost:3000"
echo "Press Ctrl+C to terminate both servers."

wait

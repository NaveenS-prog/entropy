#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/home/naveen/.local/bin:$PATH"

echo "=== Running Backend Tests (pytest) ==="
cd "$DIR/backend"
PYTHONPATH=. .venv/bin/pytest

echo ""
echo "=== Running Frontend Tests (vitest) ==="
cd "$DIR/frontend"
npm test

echo ""
echo "=== All Tests Passed Successfully ==="

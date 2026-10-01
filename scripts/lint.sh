#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/home/naveen/.local/bin:$PATH"

echo "=== Running Backend Linting (ruff) ==="
cd "$DIR/backend"
.venv/bin/ruff check .

echo ""
echo "=== Running Frontend Linting (eslint) ==="
cd "$DIR/frontend"
npm run lint

echo ""
echo "=== All Linting Checks Passed ==="

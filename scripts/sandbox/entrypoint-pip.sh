#!/bin/sh
# Python sandbox entrypoint: install with uv, then run pip-audit
set -e

echo "=== Installing packages with uv ==="
uv pip install --system "$@" 2>&1

echo ""
echo "=== Running pip-audit ==="
pip-audit --format=json --output=/tmp/pip-audit.json 2>&1 || true
pip-audit 2>&1 || true

echo ""
echo "=== Audit complete ==="

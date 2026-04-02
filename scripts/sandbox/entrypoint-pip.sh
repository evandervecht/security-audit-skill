#!/bin/sh
# Python sandbox entrypoint: install with uv, then run pip-audit
set -e

# Copy project files from read-only mount into writable sandbox
if [ -d /project ]; then
    cp -r /project/. /sandbox/ 2>/dev/null || true
    rm -rf /sandbox/node_modules /sandbox/.git /sandbox/.venv 2>/dev/null || true
fi

echo "=== Installing packages with uv ==="
uv pip install --system "$@" 2>&1 || echo "WARNING: install exited with errors (audit will still run)"

echo ""
echo "=== Running pip-audit ==="
pip-audit --format=json --output=/strace/audit.json 2>&1 || true
pip-audit 2>&1 || true

echo ""
echo "=== Audit complete ==="

#!/bin/sh
# npm sandbox entrypoint: install packages then run audit
set -e

echo "=== Installing packages ==="
npm install --ignore-scripts=false "$@" 2>&1

echo ""
echo "=== Running npm audit ==="
npm audit --json > /tmp/npm-audit.json 2>&1 || true
npm audit 2>&1 || true

echo ""
echo "=== Audit complete ==="

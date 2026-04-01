#!/bin/sh
# .NET sandbox entrypoint: restore + list vulnerable packages
set -e

echo "=== Restoring .NET packages ==="
dotnet restore "$@" 2>&1

echo ""
echo "=== Checking for vulnerable packages ==="
dotnet list package --vulnerable --format json > /tmp/dotnet-audit.json 2>&1 || true
dotnet list package --vulnerable 2>&1 || true

echo ""
echo "=== Audit complete ==="

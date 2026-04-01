#!/bin/sh
# Go sandbox entrypoint: download modules + govulncheck
set -e

echo "=== Downloading Go modules ==="
go mod download "$@" 2>&1

echo ""
echo "=== Running govulncheck ==="
govulncheck -json ./... > /tmp/govulncheck.json 2>&1 || true
govulncheck ./... 2>&1 || true

echo ""
echo "=== Audit complete ==="

#!/bin/sh
# Rust sandbox entrypoint: fetch crates + cargo-audit
set -e

echo "=== Fetching Rust crates ==="
cargo fetch "$@" 2>&1

echo ""
echo "=== Running cargo-audit ==="
cargo audit --json > /tmp/cargo-audit.json 2>&1 || true
cargo audit 2>&1 || true

echo ""
echo "=== Audit complete ==="

#!/bin/sh
# npm sandbox entrypoint (legacy — npm/npm-project now route to pnpm)
# Kept for backward compatibility with Dockerfile.npm
set -e

node -e "
const fs = require('fs');
const path = require('path');
function copyDir(src, dest) {
  let entries;
  try { entries = fs.readdirSync(src, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const s = path.join(src, e.name), d = path.join(dest, e.name);
    if (e.isDirectory()) { fs.mkdirSync(d, { recursive: true }); copyDir(s, d); }
    else { try { fs.copyFileSync(s, d); } catch {} }
  }
}
copyDir('/project', '/sandbox');
"

echo "=== Installing packages ==="
npm install --ignore-scripts=false "$@" 2>&1 || echo "WARNING: npm install exited with errors"

echo ""
echo "=== Running npm audit ==="
npm audit --json > /strace/audit.json 2>&1 || true
npm audit 2>&1 || true

echo ""
echo "=== Audit complete ==="

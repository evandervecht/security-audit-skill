#!/bin/sh
# uv sandbox entrypoint: install packages then run audit + SBOM
# Handles both single-package mode (args = package names) and project mode (/project/ mounted)

# Copy project files from read-only mount into writable sandbox
if [ -d /project ]; then
    cp -r /project/. /sandbox/ 2>/dev/null || true
    rm -rf /sandbox/node_modules /sandbox/.git /sandbox/.venv 2>/dev/null || true
fi

echo "=== Installing packages with uv ==="
if [ $# -gt 0 ]; then
    uv pip install --system "$@" 2>&1 || echo "WARNING: uv install exited with errors (audit will still run)"
else
    uv sync --frozen 2>&1 || uv sync 2>&1 || echo "WARNING: uv sync exited with errors (audit will still run)"
fi

echo ""
echo "=== Running pip-audit ==="
pip-audit --format=json --output=/strace/audit.json 2>&1 || true
pip-audit 2>&1 || true

echo ""
echo "=== Dependency tree ==="
uv pip list --format json > /strace/deps.json 2>&1 || pip list --format json > /strace/deps.json 2>&1 || true
uv pip list 2>&1 || pip list 2>&1 || true

echo ""
echo "=== Generating SBOM (CycloneDX) ==="
python3 -c "
import json, sys, datetime

deps = []
try:
    with open('/strace/deps.json') as f:
        deps = json.load(f)
except: pass

components = []
for pkg in deps:
    name = pkg.get('name', '')
    version = pkg.get('version', 'unknown')
    components.append({
        'type': 'library',
        'name': name,
        'version': version,
        'purl': f'pkg:pypi/{name.lower().replace(\".\", \"-\")}@{version}',
    })

sbom = {
    'bomFormat': 'CycloneDX',
    'specVersion': '1.5',
    'version': 1,
    'metadata': {
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'tools': [{'vendor': 'security-audit-skill', 'name': 'dependency-sandbox', 'version': '1.0.0'}],
        'component': {'type': 'application', 'name': 'sandbox-project', 'version': '1.0.0'}
    },
    'components': components
}

with open('/strace/sbom.json', 'w') as f:
    json.dump(sbom, f, indent=2)
print(f'SBOM generated: {len(components)} components')
" 2>&1 || echo "WARNING: SBOM generation failed"

echo ""
echo "=== Audit complete ==="

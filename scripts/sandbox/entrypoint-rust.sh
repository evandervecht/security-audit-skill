#!/bin/sh
# Rust sandbox entrypoint: fetch crates + cargo-audit + SBOM
set -e

# Copy project files from read-only mount into writable sandbox
if [ -d /project ]; then
    cp -r /project/. /sandbox/ 2>/dev/null || true
    rm -rf /sandbox/.git /sandbox/target 2>/dev/null || true
fi

echo "=== Fetching Rust crates ==="
cargo fetch "$@" 2>&1 || echo "WARNING: cargo fetch exited with errors"

echo ""
echo "=== Running cargo-audit ==="
cargo audit --json > /strace/audit.json 2>&1 || true
cargo audit 2>&1 || true

echo ""
echo "=== Dependency tree ==="
cargo metadata --format-version 1 > /strace/deps.json 2>&1 || true
cargo tree 2>&1 || true

echo ""
echo "=== Generating SBOM (CycloneDX) ==="
python3 -c "
import json, datetime

deps = {}
try:
    with open('/strace/deps.json') as f:
        deps = json.load(f)
except: pass

components = []
seen = set()
for pkg in deps.get('packages', []):
    name = pkg.get('name', '')
    version = pkg.get('version', '')
    key = f'{name}@{version}'
    if key in seen: continue
    seen.add(key)
    comp = {
        'type': 'library',
        'name': name,
        'version': version,
        'purl': f'pkg:cargo/{name}@{version}',
    }
    if pkg.get('license'):
        comp['licenses'] = [{'license': {'id': pkg['license']}}]
    if pkg.get('description'):
        comp['description'] = pkg['description']
    components.append(comp)

sbom = {
    'bomFormat': 'CycloneDX',
    'specVersion': '1.5',
    'version': 1,
    'metadata': {
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'tools': [{'vendor': 'security-audit-skill', 'name': 'dependency-sandbox', 'version': '1.0.0'}],
    },
    'components': components
}
with open('/strace/sbom.json', 'w') as f:
    json.dump(sbom, f, indent=2)
print(f'SBOM generated: {len(components)} components')
" 2>&1 || echo "WARNING: SBOM generation failed"

echo ""
echo "=== Audit complete ==="

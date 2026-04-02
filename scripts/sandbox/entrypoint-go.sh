#!/bin/sh
# Go sandbox entrypoint: download modules + govulncheck + SBOM
set -e

# Copy project files from read-only mount into writable sandbox
if [ -d /project ]; then
    cp -r /project/. /sandbox/ 2>/dev/null || true
    rm -rf /sandbox/.git 2>/dev/null || true
fi

echo "=== Downloading Go modules ==="
go mod download "$@" 2>&1 || echo "WARNING: go mod download exited with errors"

echo ""
echo "=== Running govulncheck ==="
govulncheck -json ./... > /strace/audit.json 2>&1 || true
govulncheck ./... 2>&1 || true

echo ""
echo "=== Dependency tree ==="
go list -m -json all > /strace/deps.json 2>&1 || true
go list -m all 2>&1 || true

echo ""
echo "=== Generating SBOM (CycloneDX) ==="
go list -m -json all 2>/dev/null | python3 -c "
import json, sys, datetime

components = []
decoder = json.JSONDecoder()
text = sys.stdin.read()
idx = 0
while idx < len(text):
    text = text[idx:].lstrip()
    if not text: break
    try:
        obj, end = decoder.raw_decode(text)
        idx = end
        path = obj.get('Path', '')
        version = obj.get('Version', '').lstrip('v')
        if path and version:
            components.append({
                'type': 'library',
                'name': path,
                'version': version,
                'purl': f'pkg:golang/{path}@{version}',
            })
    except: break

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

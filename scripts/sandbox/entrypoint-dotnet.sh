#!/bin/sh
# .NET sandbox entrypoint: restore + audit + SBOM
set -e

# Copy project files from read-only mount into writable sandbox
if [ -d /project ]; then
    cp -r /project/. /sandbox/ 2>/dev/null || true
    rm -rf /sandbox/.git /sandbox/bin /sandbox/obj 2>/dev/null || true
fi

echo "=== Restoring .NET packages ==="
dotnet restore "$@" 2>&1 || echo "WARNING: dotnet restore exited with errors"

echo ""
echo "=== Checking for vulnerable packages ==="
dotnet list package --vulnerable --format json > /strace/audit.json 2>&1 || true
dotnet list package --vulnerable 2>&1 || true

echo ""
echo "=== Dependency tree ==="
dotnet list package --include-transitive --format json > /strace/deps.json 2>&1 || true
dotnet list package --include-transitive 2>&1 || true

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
for project in deps.get('projects', []):
    for framework in project.get('frameworks', []):
        for pkg in framework.get('topLevelPackages', []) + framework.get('transitivePackages', []):
            name = pkg.get('id', '')
            version = pkg.get('resolvedVersion', pkg.get('requestedVersion', ''))
            key = f'{name}@{version}'
            if key in seen: continue
            seen.add(key)
            components.append({
                'type': 'library',
                'name': name,
                'version': version,
                'purl': f'pkg:nuget/{name}@{version}',
            })

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

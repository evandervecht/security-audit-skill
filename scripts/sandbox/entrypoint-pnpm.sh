#!/bin/sh
# pnpm sandbox entrypoint: install packages then run audit + SBOM
# Handles both single-package mode (args = package names) and project mode (/project/ mounted)

# Copy project files from read-only mount into writable sandbox
node -e "
const fs = require('fs');
const path = require('path');
function copyDir(src, dest) {
  let entries;
  try { entries = fs.readdirSync(src, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const s = path.join(src, e.name), d = path.join(dest, e.name);
    if (e.isDirectory()) {
      fs.mkdirSync(d, { recursive: true });
      copyDir(s, d);
    } else {
      try { const st = fs.statSync(d); if (st.isDirectory()) fs.rmSync(d, { recursive: true }); } catch {}
      try { fs.copyFileSync(s, d); } catch {}
    }
  }
}
copyDir('/project', '/sandbox');
"

# If no package.json exists, generate one from pnpm-lock.yaml
node -e "
const fs = require('fs');
const pj = '/sandbox/package.json';
try { if (fs.statSync(pj).isDirectory()) fs.rmSync(pj, { recursive: true }); } catch {}
try { if (fs.statSync(pj).isFile()) process.exit(0); } catch {}

const lockPath = '/sandbox/pnpm-lock.yaml';
let lockContent;
try { lockContent = fs.readFileSync(lockPath, 'utf8'); } catch {
  fs.writeFileSync(pj, JSON.stringify({name:'sandbox',version:'1.0.0',dependencies:{}}));
  process.exit(0);
}

const pkg = {name: 'sandbox', version: '1.0.0', dependencies: {}, devDependencies: {}};
let section = null, inRoot = false, currentPkg = null;
for (const line of lockContent.split('\n')) {
  if (line === 'packages:') break;
  if (line.match(/^  \.:$/)) { inRoot = true; continue; }
  if (inRoot && line === '    dependencies:') { section = 'dependencies'; continue; }
  if (inRoot && line === '    devDependencies:') { section = 'devDependencies'; continue; }
  if (inRoot && section && line.match(/^      '[^']+':$/)) { currentPkg = line.trim().replace(/[':]/g, ''); continue; }
  if (inRoot && section && line.match(/^      [^ ]/)) { currentPkg = line.trim().replace(/:$/, ''); continue; }
  if (inRoot && section && currentPkg && line.match(/^        specifier:/)) {
    pkg[section][currentPkg] = line.split('specifier:')[1].trim().replace(/^'|'$/g, '');
    currentPkg = null; continue;
  }
  if (inRoot && line.match(/^  [^ ]/) && !line.match(/^  \.:$/)) { inRoot = false; section = null; }
}
if (Object.keys(pkg.devDependencies).length === 0) delete pkg.devDependencies;
fs.writeFileSync(pj, JSON.stringify(pkg, null, 2));
console.log('Generated package.json with ' + Object.keys(pkg.dependencies).length + ' deps' +
  (pkg.devDependencies ? ' + ' + Object.keys(pkg.devDependencies).length + ' devDeps' : '') + ' from lockfile');
"

echo "=== Installing packages with pnpm ==="
if [ $# -gt 0 ]; then
    pnpm add "$@" 2>&1 || echo "WARNING: pnpm add exited with errors (audit will still run)"
else
    pnpm install --frozen-lockfile 2>&1 || pnpm install --no-frozen-lockfile 2>&1 || echo "WARNING: pnpm install exited with errors (audit will still run)"
fi

echo ""
echo "=== Running pnpm audit ==="
pnpm audit --json > /strace/audit.json 2>&1 || true
pnpm audit 2>&1 || true

echo ""
echo "=== Dependency tree ==="
pnpm ls --json --long --depth Infinity > /strace/deps.json 2>&1 || true
pnpm ls --depth Infinity 2>&1 || true

echo ""
echo "=== Generating SBOM (CycloneDX) ==="
node -e "
const fs = require('fs');
const path = require('path');

// Read pnpm ls --json output
let deps;
try { deps = JSON.parse(fs.readFileSync('/strace/deps.json', 'utf8')); } catch { deps = []; }

const components = [];
const seen = new Set();

function walk(pkgMap) {
  if (!pkgMap || typeof pkgMap !== 'object') return;
  for (const [name, info] of Object.entries(pkgMap)) {
    const version = info.version || 'unknown';
    const key = name + '@' + version;
    if (seen.has(key)) continue;
    seen.add(key);
    const scope = name.startsWith('@') ? name.split('/')[0].slice(1) : undefined;
    const bareName = name.startsWith('@') ? name.split('/')[1] : name;
    components.push({
      type: 'library',
      name: name,
      version: version,
      purl: 'pkg:npm/' + (scope ? scope + '/' : '') + bareName + '@' + version,
      ...(info.description ? { description: info.description } : {}),
      ...(info.license ? { licenses: [{ license: { id: info.license } }] } : {}),
    });
    if (info.dependencies) walk(info.dependencies);
    if (info.devDependencies) walk(info.devDependencies);
  }
}

// pnpm ls --json returns an array of workspace entries
const entries = Array.isArray(deps) ? deps : [deps];
for (const entry of entries) {
  if (entry.dependencies) walk(entry.dependencies);
  if (entry.devDependencies) walk(entry.devDependencies);
}

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [{ vendor: 'security-audit-skill', name: 'dependency-sandbox', version: '1.0.0' }],
    component: { type: 'application', name: 'sandbox-project', version: '1.0.0' }
  },
  components: components
};

fs.writeFileSync('/strace/sbom.json', JSON.stringify(sbom, null, 2));
console.log('SBOM generated: ' + components.length + ' components');
" 2>&1 || echo "WARNING: SBOM generation failed"

echo ""
echo "=== Audit complete ==="

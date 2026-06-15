#!/bin/bash
# Svelte / SvelteKit Security Scanner Module
# Scans Svelte and SvelteKit projects for common vulnerability patterns
# Part of security-audit-skill modular scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Svelte source directories
SCAN_DIRS=()
for dir in src lib routes; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
# Fall back to the project root if no conventional dirs exist
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS+=("$PROJECT_DIR")
fi

# Helper: grep across all Svelte source directories
scan_svelte() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.svelte" --include="*.ts" --include="*.js" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Svelte source directories
scan_svelte_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E "$pattern" "$dir" --include="*.svelte" --include="*.ts" --include="*.js" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Svelte / SvelteKit Security Scanner ---"
echo "Scanning directories: ${SCAN_DIRS[*]}"
echo ""

# SA-SVELTE-01: {@html} XSS
count=$(scan_svelte_count '\{@html[[:space:]]')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-SVELTE-01: Found $count {@html} usage(s) — raw HTML bypasses auto-escaping (XSS); sanitize first"
    scan_svelte '\{@html[[:space:]]'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-SVELTE-02: private $env imported (risk of client leak)
count=$(scan_svelte_count "from[[:space:]]+['\"]\\\$env/(static|dynamic)/private['\"]")
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-SVELTE-02: Found $count private \$env import(s) — keep secrets in server-only (*.server) modules"
    scan_svelte "from[[:space:]]+['\"]\\\$env/(static|dynamic)/private['\"]"
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-SVELTE-03: svelte:element with dynamic this
count=$(scan_svelte_count '<svelte:element[^>]*[[:space:]]this=\{[^}]*(tag|tagName|type|element|el|node|props|data|params|input|userTag|component|block|blockType|kind|variant|name)')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-SVELTE-03: Found $count <svelte:element this={...}> with dynamic tag — allowlist the element name"
    scan_svelte '<svelte:element[^>]*[[:space:]]this=\{[^}]*(tag|tagName|type|element|el|node|props|data|params|input|userTag|component|block|blockType|kind|variant|name)'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-SVELTE-04: eval() / new Function() in components
count=$(scan_svelte_count '\beval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-SVELTE-04: Found $count eval()/new Function() call(s) — code injection risk"
    scan_svelte '\beval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-SVELTE-05: CSRF checkOrigin disabled
count=$(scan_svelte_count 'checkOrigin[[:space:]]*:[[:space:]]*false')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-SVELTE-05: Found $count csrf.checkOrigin:false setting(s) — re-enable cross-origin protection"
    scan_svelte 'checkOrigin[[:space:]]*:[[:space:]]*false'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-SVELTE-06: server load() returning sensitive fields
count=$(scan_svelte_count 'return[[:space:]]*\{[^}]*(passwordHash|refreshToken|accessToken|apiToken|privateKey|creditCard)')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-SVELTE-06: Found $count load()/return block(s) exposing sensitive fields — return a DTO instead"
    scan_svelte 'return[[:space:]]*\{[^}]*(passwordHash|refreshToken|accessToken|apiToken|privateKey|creditCard)'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

echo "--- Svelte / SvelteKit Security Scanner Summary ---"
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo "Total:    $((ERRORS + WARNINGS))"

exit $ERRORS

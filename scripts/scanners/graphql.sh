#!/bin/bash
# GraphQL Security Scanner Module
# Scans GraphQL schemas and Apollo/Yoga server configs for common vulnerability patterns
# Part of security-audit-skill modular scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect GraphQL source directories
SCAN_DIRS=()
for dir in . src app server graphql schema api; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Helper: grep across all GraphQL/JS/TS source files
scan_gql() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E -e "$pattern" "$dir" --include="*.graphql" --include="*.gql" --include="*.js" --include="*.ts" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | sort -u | head -"$limit"
}

# Helper: count matches across all GraphQL/JS/TS source files
scan_gql_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E -e "$pattern" "$dir" --include="*.graphql" --include="*.gql" --include="*.js" --include="*.ts" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- GraphQL Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No GraphQL source directories found (looked for ./, src/, app/, server/, graphql/, schema/, api/)"
    exit 0
fi
echo "Scanning directories: ${SCAN_DIRS[*]}"
echo ""

# SA-GRAPHQL-01: introspection enabled in production
count=$(scan_gql_count 'introspection\s*:\s*true\b')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-GRAPHQL-01: Found $count introspection: true setting(s) — disable introspection in production"
    scan_gql 'introspection\s*:\s*true\b'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GRAPHQL-02: verbose error / stacktrace exposure
count=$(scan_gql_count '(debug|includeStacktraceInErrorResponses)\s*:\s*true\b')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-GRAPHQL-02: Found $count debug/stacktrace setting(s) — leaks internals via error responses"
    scan_gql '(debug|includeStacktraceInErrorResponses)\s*:\s*true\b'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GRAPHQL-03: missing query depth/complexity limit (empty validationRules)
count=$(scan_gql_count 'validationRules\s*:\s*\[\s*\]')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-GRAPHQL-03: Found $count empty validationRules array(s) — add query depth/complexity limits"
    scan_gql 'validationRules\s*:\s*\[\s*\]'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GRAPHQL-04: sensitive schema field without @auth directive
count=$(scan_gql_count '^[[:space:]]*(ssn|password|passwordHash|token|secret|apiKey|creditCard)[[:space:]]*:')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-GRAPHQL-04: Found $count sensitive field(s) — verify field-level @auth/@hasRole authorization"
    scan_gql '^[[:space:]]*(ssn|password|passwordHash|token|secret|apiKey|creditCard)[[:space:]]*:'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-GRAPHQL-05: query batching enabled
count=$(scan_gql_count 'allowBatchedHttpRequests\s*:\s*true\b')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-GRAPHQL-05: Found $count allowBatchedHttpRequests: true setting(s) — batching enables rate-limit bypass"
    scan_gql 'allowBatchedHttpRequests\s*:\s*true\b'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-GRAPHQL-06: CSRF prevention disabled
count=$(scan_gql_count 'csrfPrevention\s*:\s*false\b')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-GRAPHQL-06: Found $count csrfPrevention: false setting(s) — allows CSRF / GET-based mutations"
    scan_gql 'csrfPrevention\s*:\s*false\b'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-GRAPHQL-07: unbounded list field (no pagination args)
count=$(scan_gql_count '^[[:space:]]*[A-Za-z_]+[[:space:]]*:[[:space:]]*\[[A-Za-z_]+!?\]')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-GRAPHQL-07: Found $count list-returning field(s) — verify pagination (first/last/limit) to prevent unbounded result sets"
    scan_gql '^[[:space:]]*[A-Za-z_]+[[:space:]]*:[[:space:]]*\[[A-Za-z_]+!?\]'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

echo "--- GraphQL Security Scanner Summary ---"
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo "Total:    $((ERRORS + WARNINGS))"

exit $ERRORS

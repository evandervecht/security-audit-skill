#!/bin/bash
# Vapor (Swift) Security Scanner Module
# Scans Vapor 4.x server projects for framework-specific vulnerability patterns
# Excludes .build/ directory

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Vapor/SwiftPM source directories
SCAN_DIRS=()
for dir in Sources Tests App; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across all Swift source directories, excluding .build/
scan_swift() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.swift" --exclude-dir=.build --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

echo "--- Vapor Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-VAPOR-01: Wildcard CORS origin ===
echo "=== Checking CORS Configuration ==="
CORS_ALL=$(scan_swift 'allowedOrigin:\s*\.(all|originBased)\b')
if [[ -n "$CORS_ALL" ]]; then
    echo "WARNING: CORSMiddleware allowedOrigin: .all/.originBased opens the API to any site:"
    echo "$CORS_ALL"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No wildcard CORS origin detected"
fi

# === SA-VAPOR-02: SQL injection via interpolated .raw() ===
echo ""
echo "=== Checking for SQL Injection in .raw() ==="
RAW_SQL=$(scan_swift '(\.raw|SQLQueryString)\s*\(\s*"[^"]*\\\(([A-Za-z_][A-Za-z0-9_.]*\)|(unsafeRaw|raw)\s*:)')
if [[ -n "$RAW_SQL" ]]; then
    echo "ERROR: SQLKit .raw()/SQLQueryString with unbound Swift string interpolation:"
    echo "$RAW_SQL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No interpolated raw SQL detected"
fi

# === SA-VAPOR-03: TLS certificate verification disabled ===
echo ""
echo "=== Checking TLS Certificate Verification ==="
TLS_NONE=$(scan_swift 'certificateVerification\s*[:=]\s*\.none')
if [[ -n "$TLS_NONE" ]]; then
    echo "ERROR: certificateVerification = .none disables TLS validation:"
    echo "$TLS_NONE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No disabled certificate verification detected"
fi

# === SA-VAPOR-04: Hardcoded fallback secrets ===
echo ""
echo "=== Checking for Hardcoded Fallback Secrets ==="
FALLBACK_SECRETS=$(scan_swift 'Environment\.get\s*\(\s*"[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD|PASS)"\s*\)\s*\?\?\s*"')
if [[ -n "$FALLBACK_SECRETS" ]]; then
    echo "ERROR: Environment.get(...) with hardcoded fallback secret literal:"
    echo "$FALLBACK_SECRETS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No hardcoded fallback secrets detected"
fi

# === SA-VAPOR-05: Path traversal via streamFile ===
echo ""
echo "=== Checking for Path Traversal in File Streaming ==="
STREAM_TRAVERSAL=$(scan_swift 'streamFile\s*\(\s*at:\s*"[^"]*\\\([^)"]*req\.|streamFile\s*\(\s*at:[^)]*req\.parameters')
if [[ -n "$STREAM_TRAVERSAL" ]]; then
    echo "ERROR: req.fileio.streamFile path built from request-derived input:"
    echo "$STREAM_TRAVERSAL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No parameter-derived file streaming detected"
fi

# === SA-VAPOR-06: Insecure session cookie flags ===
echo ""
echo "=== Checking Session Cookie Flags ==="
INSECURE_COOKIE=$(scan_swift 'isSecure\s*:\s*false|isHTTPOnly\s*:\s*false')
if [[ -n "$INSECURE_COOKIE" ]]; then
    echo "WARNING: Session cookie configured with isSecure: false or isHTTPOnly: false:"
    echo "$INSECURE_COOKIE"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No insecure session cookie flags detected"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Vapor Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

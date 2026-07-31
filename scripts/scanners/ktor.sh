#!/bin/bash
# Ktor Security Scanner Module
# Scans Ktor (Kotlin server framework) projects for common vulnerability patterns
# Excludes build/ and .gradle/ directories

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Kotlin source directories (fall back to the project dir itself)
SCAN_DIRS=()
for dir in src app server backend; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across all Kotlin source directories, excluding build output
scan_kt() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E -e "$pattern" "$dir" --include="*.kt" --include="*.kts" --exclude-dir=build --exclude-dir=.gradle --exclude-dir=.git --exclude-dir=out 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: list files matching a pattern (for multi-line combination checks)
scan_kt_files() {
    local pattern="$1"
    for dir in "${SCAN_DIRS[@]}"; do
        grep -rl -E -e "$pattern" "$dir" --include="*.kt" --include="*.kts" --exclude-dir=build --exclude-dir=.gradle --exclude-dir=.git --exclude-dir=out 2>/dev/null || true
    done
}

echo "--- Ktor Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-KTOR-01: Wildcard CORS via anyHost() ===
echo "=== Checking for Wildcard CORS (anyHost) ==="
ANY_HOST=$(scan_kt '\banyHost\s*\(\s*\)')
if [[ -n "$ANY_HOST" ]]; then
    echo "WARNING: install(CORS) { anyHost() } allows every origin — use allowHost allowlists:"
    echo "$ANY_HOST"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No wildcard CORS detected"
fi

# === SA-KTOR-02: Credentialed wildcard CORS ===
# anyHost() and allowCredentials = true usually sit on separate lines,
# so check for both patterns within the same file.
echo ""
echo "=== Checking for Credentialed Wildcard CORS ==="
CRED_CORS=""
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if grep -q -E 'allowCredentials\s*=\s*true' "$f" 2>/dev/null; then
        CRED_CORS+="$f"$'\n'
    fi
done < <(scan_kt_files '\banyHost\s*\(\s*\)')
if [[ -n "$CRED_CORS" ]]; then
    echo "ERROR: anyHost() combined with allowCredentials = true — cookies leak to any origin:"
    echo "$CRED_CORS" | grep -v '^$' | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No credentialed wildcard CORS detected"
fi

# === SA-KTOR-03: JWT without signature verification ===
echo ""
echo "=== Checking for Unverified JWT Handling ==="
JWT_UNVERIFIED=$(scan_kt 'Algorithm\.none\s*\(\s*\)|\bJWT\.decode\s*\(')
if [[ -n "$JWT_UNVERIFIED" ]]; then
    echo "ERROR: JWT decoded without verification (Algorithm.none/JWT.decode) — use JWT.require(...).build():"
    echo "$JWT_UNVERIFIED"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No unverified JWT handling detected"
fi

# === SA-KTOR-04: Hardcoded JWT/HMAC secrets ===
echo ""
echo "=== Checking for Hardcoded JWT/HMAC Secrets ==="
HMAC_SECRET=$(scan_kt 'Algorithm\.HMAC(256|384|512)\s*\(\s*"[^"$]+"')
if [[ -n "$HMAC_SECRET" ]]; then
    echo "ERROR: Hardcoded HMAC signing secret — load from environment or config:"
    echo "$HMAC_SECRET"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No hardcoded HMAC secrets detected"
fi

# === SA-KTOR-05: Reflected XSS via respondText(..., ContentType.Text.Html) ===
echo ""
echo "=== Checking for Reflected XSS in HTML Responses ==="
XSS=$(scan_kt 'respondText\s*\(\s*(text\s*=\s*)?"[^"]*\$[A-Za-z_{].*ContentType\.Text\.Html|respondText\s*\(\s*contentType\s*=\s*ContentType\.Text\.Html\s*,\s*text\s*=\s*"[^"]*\$[A-Za-z_{]')
if [[ -n "$XSS" ]]; then
    echo "ERROR: Interpolated string served as text/html — escape output or use respondHtml/kotlinx.html:"
    echo "$XSS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No interpolated HTML responses detected"
fi

# === SA-KTOR-06: Path traversal via request-derived file paths ===
echo ""
echo "=== Checking for Path Traversal via Request Input ==="
TRAVERSAL=$(scan_kt 'respondFile\s*\(\s*([A-Za-z_.]*\.)?File\s*\([^()"]*call\.(parameters|request|receive)')
if [[ -n "$TRAVERSAL" ]]; then
    echo "ERROR: respondFile(File(...)) built from call parameters — jail-check the path or use respondFile(baseDir, fileName):"
    echo "$TRAVERSAL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No request-derived file paths detected"
fi

# === SA-KTOR-07: Trust-all TrustManager in HttpClient https {} ===
echo ""
echo "=== Checking for Trust-All TLS in Ktor HttpClient ==="
TRUST_ALL=$(scan_kt 'trustManager\s*=\s*object\s*:\s*X509TrustManager|trustManager\s*=\s*[A-Za-z_.]*(([Tt]rustAll|[Aa]cceptAll)([A-Z]|\b)|[Ii]nsecure|[Uu]nsafe|[Nn]oVerify)')
if [[ -n "$TRUST_ALL" ]]; then
    echo "ERROR: Trust-all TrustManager disables certificate validation — use TrustManagerFactory or pinning:"
    echo "$TRUST_ALL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No trust-all TLS configuration detected"
fi

# === SA-KTOR-08: Insecure session cookie flags ===
echo ""
echo "=== Checking for Insecure Session Cookie Flags ==="
COOKIE_FLAGS=$(scan_kt 'cookie\.secure\s*=\s*false|cookie\.httpOnly\s*=\s*false')
if [[ -n "$COOKIE_FLAGS" ]]; then
    echo "WARNING: Session cookie with secure/httpOnly disabled — enable both and set SameSite:"
    echo "$COOKIE_FLAGS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No insecure session cookie flags detected"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Ktor Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

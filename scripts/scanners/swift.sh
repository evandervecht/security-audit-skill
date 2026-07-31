#!/bin/bash
# Swift Security Scanner Module
# Scans Swift projects (iOS/macOS apps and server-side Swift) for common
# vulnerability patterns. Excludes .build/, Pods/, Carthage/, DerivedData/.
# Mirrors checkpoints SA-SWIFT-01..SA-SWIFT-12.

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Swift source directories; fall back to the project root
SCAN_DIRS=()
for dir in Sources Tests App Modules; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across all Swift source directories
scan_swift() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E -e "$pattern" "$dir" --include="*.swift" \
            --exclude-dir=.build --exclude-dir=Pods --exclude-dir=Carthage \
            --exclude-dir=DerivedData --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

echo "--- Swift Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-SWIFT-01: Insecure deserialization ===
echo "=== Checking for Legacy NSKeyedUnarchiver Deserialization ==="
UNARCHIVE=$(scan_swift 'NSKeyedUnarchiver\.unarchive(Object|TopLevelObjectWithData)\s*\(')
if [[ -n "$UNARCHIVE" ]]; then
    echo "ERROR: Legacy unarchiving allows object injection — use unarchivedObject(ofClass:from:):"
    echo "$UNARCHIVE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No legacy NSKeyedUnarchiver usage detected"
fi

# === SA-SWIFT-02: Command injection via shell ===
echo ""
echo "=== Checking for Process Shell Invocation ==="
SHELL_EXEC=$(scan_swift 'launchPath\s*=\s*"/bin/(sh|bash|zsh)"|executableURL\s*=\s*URL\(fileURLWithPath:\s*"/bin/(sh|bash|zsh)"')
if [[ -n "$SHELL_EXEC" ]]; then
    echo "ERROR: Process launches /bin/sh — command injection risk, exec the binary directly:"
    echo "$SHELL_EXEC"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No shell invocation via Process detected"
fi

# === SA-SWIFT-03: SQL injection via interpolation ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
SQL_INTERP=$(scan_swift '"(SELECT|DELETE)\s[^"]*FROM\s[^"]*[\\][(]|"INSERT\s+INTO\s[^"]*[\\][(]|"UPDATE\s[^"]*SET\s[^"]*[\\][(]|"SELECT\s[^"]*[\\][(][^"]*\sFROM\s')
if [[ -n "$SQL_INTERP" ]]; then
    echo "ERROR: SQL built with string interpolation — use ? placeholders with sqlite3_bind_*:"
    echo "$SQL_INTERP"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No interpolated SQL detected"
fi

# === SA-SWIFT-04: Predictable randomness ===
echo ""
echo "=== Checking for Predictable Random Number Generators ==="
WEAK_RNG=$(scan_swift '\b(drand48|srand48)\s*\(|(^|[^.A-Za-z0-9_])(rand|random)\s*\(\s*\)')
if [[ -n "$WEAK_RNG" ]]; then
    echo "WARNING: drand48/srand48/random()/rand() found — use SecRandomCopyBytes for security values:"
    echo "$WEAK_RNG"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No predictable PRNG usage detected"
fi

# === SA-SWIFT-05: App Transport Security disabled ===
echo ""
echo "=== Checking Info.plist App Transport Security ==="
ATS=$(grep -rn -A1 -E '<key>NSAllowsArbitraryLoads</key>' "$PROJECT_DIR" \
    --include="Info.plist" --exclude-dir=.build --exclude-dir=Pods --exclude-dir=Carthage \
    --exclude-dir=DerivedData --exclude-dir=.git 2>/dev/null | grep -E '<true' | head -5 || true)
if [[ -n "$ATS" ]]; then
    echo "ERROR: App Transport Security disabled — enforce HTTPS with scoped NSExceptionDomains:"
    echo "$ATS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: App Transport Security not disabled"
fi

# === SA-SWIFT-06: TLS bypass in challenge handler ===
echo ""
echo "=== Checking for TLS Certificate Validation Bypass ==="
TLS_BYPASS=$(scan_swift 'URLCredential\(trust:\s*challenge\.protectionSpace\.serverTrust')
if [[ -n "$TLS_BYPASS" ]]; then
    echo "ERROR: Blanket URLCredential(trust:) accepts any certificate — evaluate with SecTrustEvaluateWithError:"
    echo "$TLS_BYPASS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No blanket server trust detected"
fi

# === SA-SWIFT-07: Weak hash algorithms ===
echo ""
echo "=== Checking for Weak Hash Algorithms ==="
WEAK_HASH=$(scan_swift 'Insecure\.(MD5|SHA1)|CC_MD5\s*\(|CC_SHA1\s*\(')
if [[ -n "$WEAK_HASH" ]]; then
    echo "WARNING: MD5/SHA-1 usage found — use SHA256 via CryptoKit; KDF for passwords:"
    echo "$WEAK_HASH"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No weak hash algorithms detected"
fi

# === SA-SWIFT-08: Hardcoded secrets ===
echo ""
echo "=== Checking for Hardcoded Secrets ==="
SECRETS=$(scan_swift '\b(let|var)\s+\w*([pP]assword|[sS]ecret|[aA]pi[Kk]ey|[tT]oken)(\s*:\s*String)?\s*=\s*"[^"]{8,}"')
if [[ -n "$SECRETS" ]]; then
    echo "ERROR: Potential hardcoded credentials found — load secrets at runtime:"
    echo "$SECRETS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious hardcoded secrets detected"
fi

# === SA-SWIFT-09: Secrets in UserDefaults ===
echo ""
echo "=== Checking for Secrets in UserDefaults ==="
DEFAULTS=$(scan_swift 'UserDefaults\.standard\.set\([^,)]*([pP]assword|[tT]oken|[aA]pi[Kk]ey|[sS]ecret)[^A-Za-z0-9_]')
if [[ -n "$DEFAULTS" ]]; then
    echo "ERROR: Sensitive data stored in UserDefaults — use the Keychain via SecItemAdd:"
    echo "$DEFAULTS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No secrets in UserDefaults detected"
fi

# === SA-SWIFT-10: WKWebView JavaScript injection ===
echo ""
echo "=== Checking for WKWebView JavaScript Injection ==="
JS_INTERP=$(scan_swift 'evaluateJavaScript\s*\(\s*"[^"]*[\\][(]')
if [[ -n "$JS_INTERP" ]]; then
    echo "ERROR: evaluateJavaScript with interpolated string — use callAsyncJavaScript with arguments:"
    echo "$JS_INTERP"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No interpolated evaluateJavaScript calls detected"
fi

# === SA-SWIFT-11: Weak Keychain accessibility ===
echo ""
echo "=== Checking Keychain Accessibility Classes ==="
KEYCHAIN=$(scan_swift 'kSecAttrAccessibleAlways')
if [[ -n "$KEYCHAIN" ]]; then
    echo "ERROR: kSecAttrAccessibleAlways found — use kSecAttrAccessibleWhenUnlockedThisDeviceOnly:"
    echo "$KEYCHAIN"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No weak Keychain accessibility detected"
fi

# === SA-SWIFT-12: Path traversal ===
echo ""
echo "=== Checking for Path Traversal Patterns ==="
PATHS=$(scan_swift '(fileURLWithPath|atPath|contentsOfFile):\s*"[^"]*[\\][(]|(fileURLWithPath|atPath|contentsOfFile):\s*[A-Za-z_][A-Za-z0-9_.]*\s*\+\s*("[^"]*"\s*\+\s*)*[A-Za-z_]')
if [[ -n "$PATHS" ]]; then
    echo "ERROR: File path built from concatenated/interpolated input — canonicalize and prefix-check:"
    echo "$PATHS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No path traversal patterns detected"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Swift Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

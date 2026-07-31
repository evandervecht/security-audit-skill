#!/bin/bash
# Kotlin Security Scanner Module
# Scans Kotlin (server-side JVM + Android-flavored) projects for common vulnerability patterns
# Excludes build/ and .gradle/ directories

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Kotlin source directories
SCAN_DIRS=()
for dir in src app lib core buildSrc; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Fall back to scanning the project directory itself
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
        matches=$(grep -rn -E -e "$pattern" "$dir" --include="*.kt" --include="*.kts" --exclude-dir=build --exclude-dir=.gradle --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Kotlin source directories
scan_kt_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E -e "$pattern" "$dir" --include="*.kt" --include="*.kts" --exclude-dir=build --exclude-dir=.gradle --exclude-dir=.git 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Kotlin Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-KT-01: Command injection ===
echo "=== Checking for Command Injection ==="
CMD_INJECT=$(scan_kt 'Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*"[^"]*(\$[a-z_{]|"\s*\+\s*[A-Za-z_])|ProcessBuilder\s*\(\s*"[^"]*\$[a-z_{]|ProcessBuilder\s*\(\s*"(sh|bash|zsh|/bin/sh|cmd|cmd\.exe|powershell)"\s*,\s*"[-/][A-Za-z]+"\s*,\s*([a-z_][A-Za-z0-9_.]*\s*[,)]|"[^"]*(\$[a-z_{]|"\s*\+\s*[A-Za-z_]))')
if [[ -n "$CMD_INJECT" ]]; then
    echo "ERROR: Command built from string template or shell invocation:"
    echo "$CMD_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No command injection patterns detected"
fi

# === SA-KT-02: SQL injection via string templates ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
SQL_TMPL=$(scan_kt '(rawQuery|execSQL|createNativeQuery|createQuery)\s*\(\s*"[^"]*(\$[a-z_{]|"\s*\+\s*[A-Za-z_])')
if [[ -n "$SQL_TMPL" ]]; then
    echo "ERROR: SQL built with string template/concatenation — use bind parameters:"
    echo "$SQL_TMPL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No SQL injection patterns detected"
fi

# === SA-KT-03: Predictable randomness ===
echo ""
echo "=== Checking for Predictable Randomness ==="
WEAK_RANDOM_COUNT=$(scan_kt_count 'java\.util\.Random|\bRandom\s*\(|\bRandom\.next|Math\.random\s*\(')
if [[ "$WEAK_RANDOM_COUNT" -gt 0 ]]; then
    echo "WARNING: $WEAK_RANDOM_COUNT non-cryptographic Random usage(s) — use SecureRandom for tokens:"
    scan_kt 'java\.util\.Random|\bRandom\s*\(|\bRandom\.next|Math\.random\s*\(' 5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No java.util.Random/Math.random usage detected"
fi

# === SA-KT-04: Trust-all X509TrustManager ===
echo ""
echo "=== Checking for Trust-All TrustManagers ==="
TRUST_ALL=$(scan_kt 'object\s*:\s*X509(Extended)?TrustManager|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}')
if [[ -n "$TRUST_ALL" ]]; then
    echo "ERROR: Custom/empty X509TrustManager found — certificate validation may be disabled:"
    echo "$TRUST_ALL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No trust-all TrustManager patterns detected"
fi

# === SA-KT-05: Permissive HostnameVerifier ===
echo ""
echo "=== Checking for Permissive HostnameVerifiers ==="
HOSTNAME_TRUE=$(scan_kt '[Hh]ostnameVerifier\s*\{[^}]*->\s*true\s*\}|[Hh]ostnameVerifier\s*\(\s*\{[^}]*->\s*true\s*\}|fun\s+verify\s*\([^)]*SSLSession[^)]*\)\s*=\s*true')
if [[ -n "$HOSTNAME_TRUE" ]]; then
    echo "ERROR: HostnameVerifier that always returns true — hostname checks disabled:"
    echo "$HOSTNAME_TRUE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No permissive HostnameVerifier detected"
fi

# === SA-KT-06: Weak hash algorithms ===
echo ""
echo "=== Checking for Weak Hash Algorithms ==="
WEAK_HASH=$(scan_kt 'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"')
if [[ -n "$WEAK_HASH" ]]; then
    echo "WARNING: MD5/SHA-1 MessageDigest — use SHA-256 or PBKDF2/bcrypt for credentials:"
    echo "$WEAK_HASH"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No weak hash algorithms detected"
fi

# === SA-KT-07: Java native deserialization ===
echo ""
echo "=== Checking for Java Deserialization ==="
DESER=$(scan_kt '\bObjectInputStream\s*\(')
if [[ -n "$DESER" ]]; then
    echo "ERROR: ObjectInputStream construction — gadget-chain RCE risk on untrusted input:"
    echo "$DESER"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No Java native deserialization detected"
fi

# === SA-KT-08: ECB mode / bare AES ===
echo ""
echo "=== Checking for Weak Cipher Modes ==="
WEAK_CIPHER=$(scan_kt 'Cipher\.getInstance\s*\(\s*"AES"|Cipher\.getInstance\s*\(\s*"AES/ECB|Cipher\.getInstance\s*\(\s*"(DES|DESede|RC4|ARCFOUR|Blowfish)')
if [[ -n "$WEAK_CIPHER" ]]; then
    echo "ERROR: ECB mode, bare AES transformation, or legacy cipher — use AES/GCM/NoPadding:"
    echo "$WEAK_CIPHER"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No weak cipher modes detected"
fi

# === SA-KT-09: Hardcoded credentials ===
echo ""
echo "=== Checking for Hardcoded Credentials ==="
SECRETS=$(scan_kt '\b(val|var)\s+[A-Za-z_]*([Pp]assword|PASSWORD|[Ss]ecret([Kk]ey)?|SECRET(_KEY)?|[Aa]pi[Kk]ey|API_KEY|[Tt]oken|TOKEN)(\s*:\s*String)?\s*=\s*"[^"]{8,}"' 10)
if [[ -n "$SECRETS" ]]; then
    echo "ERROR: Potential hardcoded credentials found:"
    echo "$SECRETS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious hardcoded secrets detected"
fi

# === SA-KT-10: WebView JavaScript bridges ===
echo ""
echo "=== Checking for WebView JavaScript Bridges ==="
JS_BRIDGE=$(scan_kt 'addJavascriptInterface\s*\(')
if [[ -n "$JS_BRIDGE" ]]; then
    echo "WARNING: addJavascriptInterface found — native methods exposed to WebView JS:"
    echo "$JS_BRIDGE"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No WebView JavaScript bridges detected"
fi

# === SA-KT-11: Path traversal via File() ===
echo ""
echo "=== Checking for Path Traversal Patterns ==="
PATH_TRAVERSAL=$(scan_kt '\bFile\s*\(([^)"]|"[^"]*")*(request\.|req\.|params\[|getParameter\s*\(|queryParam|call\.parameters)')
if [[ -n "$PATH_TRAVERSAL" ]]; then
    echo "ERROR: File path built from request parameters — canonicalize and containment-check:"
    echo "$PATH_TRAVERSAL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No path traversal patterns detected"
fi

# === SA-KT-12: kotlinx.serialization polymorphic Any ===
echo ""
echo "=== Checking for Polymorphic Any Deserialization ==="
POLY_ANY=$(scan_kt 'decodeFromString\s*<\s*Any[?]?\s*>|PolymorphicSerializer\s*\(\s*Any::class|polymorphic\s*\(\s*Any::class')
if [[ -n "$POLY_ANY" ]]; then
    echo "ERROR: kotlinx.serialization polymorphic/Any decoding — sender chooses the concrete type:"
    echo "$POLY_ANY"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No polymorphic Any deserialization detected"
fi

# === Check dependencies ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/gradle.lockfile" || -f "$PROJECT_DIR/build.gradle.kts" || -f "$PROJECT_DIR/build.gradle" ]]; then
    echo "INFO: Gradle project detected — run the OWASP dependency-check plugin (dependencyCheckAnalyze) for CVE scanning"
else
    echo "INFO: No Gradle build files found — skipping dependency check"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Kotlin Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

#!/bin/bash
# Scala Security Scanner Module
# Scans Scala (2.13/3.x) projects for common vulnerability patterns
# Excludes target/ and .bloop/ build directories

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Scala source directories (sbt, Play, mill layouts)
SCAN_DIRS=()
for dir in src app modules core server test tests; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Fall back to scanning the project directory itself
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS+=("$PROJECT_DIR")
fi

# Helper: grep across all Scala source directories, excluding build output
scan_scala() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.scala" --exclude-dir=target --exclude-dir=.bloop --exclude-dir=.metals --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Scala source directories
scan_scala_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E "$pattern" "$dir" --include="*.scala" --exclude-dir=target --exclude-dir=.bloop --exclude-dir=.metals --exclude-dir=.git 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Scala Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-SCALA-01: Java deserialization ===
echo "=== Checking for Java Deserialization ==="
DESER=$(scan_scala 'new\s+ObjectInputStream\s*\(')
if [[ -n "$DESER" ]]; then
    echo "ERROR: ObjectInputStream construction found — readObject on untrusted data is RCE:"
    echo "$DESER"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No ObjectInputStream usage detected"
fi

# === SA-SCALA-02: sys.process command injection ===
echo ""
echo "=== Checking for sys.process Command Injection ==="
SYSPROC=$(scan_scala 's"[^"]*\$[^"]*"\s*\.(!!|!)|Seq\s*\(\s*"(sh|bash|/bin/sh|/bin/bash)"\s*,\s*"-c"\s*,\s*(s"|[A-Za-z_]|"[^"]*"\s*\+)')
if [[ -n "$SYSPROC" ]]; then
    echo "ERROR: Interpolated shell command or Seq(sh,-c) with a dynamic script via sys.process:"
    echo "$SYSPROC"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No sys.process injection patterns detected"
fi

# === SA-SCALA-03: SQL injection via string interpolation ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
SQLI=$(scan_scala '\b(executeQuery|executeUpdate)\s*\(\s*s"[^"]*\$')
if [[ -n "$SQLI" ]]; then
    echo "ERROR: s-interpolated SQL passed to JDBC executeQuery/executeUpdate:"
    echo "$SQLI"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No interpolated SQL detected"
fi

# === SA-SCALA-04: insecure randomness ===
echo ""
echo "=== Checking for Insecure Randomness ==="
RAND_COUNT=$(scan_scala_count 'scala\.util\.Random|\bRandom\.(alphanumeric|nextInt|nextLong|nextBytes|nextString)|new\s+Random\s*\(')
if [[ "$RAND_COUNT" -gt 0 ]]; then
    echo "WARNING: $RAND_COUNT scala.util.Random/java.util.Random usages — use SecureRandom for tokens:"
    scan_scala 'scala\.util\.Random|\bRandom\.(alphanumeric|nextInt|nextLong|nextBytes|nextString)|new\s+Random\s*\(' 5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No predictable RNG usage detected"
fi

# === SA-SCALA-05: Runtime.exec with dynamic strings ===
echo ""
echo "=== Checking for Runtime.exec Command Injection ==="
RTEXEC=$(scan_scala 'Runtime\.getRuntime(\(\))?\.exec\s*\(\s*(s"[^"]*\$|s?"[^"]*"\s*\+)')
if [[ -n "$RTEXEC" ]]; then
    echo "ERROR: Runtime.getRuntime.exec with concatenated/interpolated string:"
    echo "$RTEXEC"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No Runtime.exec injection patterns detected"
fi

# === SA-SCALA-06: weak MessageDigest algorithms ===
echo ""
echo "=== Checking for Weak Hash Algorithms ==="
WEAKHASH=$(scan_scala 'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"')
if [[ -n "$WEAKHASH" ]]; then
    echo "WARNING: MD5/SHA-1 MessageDigest found — use bcrypt/scrypt/Argon2 for credentials:"
    echo "$WEAKHASH"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No weak hash algorithms detected"
fi

# === SA-SCALA-07: trust-all TLS ===
echo ""
echo "=== Checking for Trust-All TLS ==="
TRUSTALL=$(scan_scala 'def\s+check(Client|Server)Trusted[^{}]*\{\s*\}|def\s+check(Client|Server)Trusted\([^)]*\)\s*:\s*Unit\s*=\s*\(\s*\)')
if [[ -n "$TRUSTALL" ]]; then
    echo "ERROR: Trust-all X509TrustManager (empty trust checks) — disables certificate validation:"
    echo "$TRUSTALL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No trust-all TLS patterns detected"
fi

# === SA-SCALA-08: hardcoded credentials ===
echo ""
echo "=== Checking for Hardcoded Credentials ==="
SECRETS=$(scan_scala 'val\s+\w*(password|Password|PASSWORD|passwd|secret|Secret|SECRET|apiKey|ApiKey|api_key|API_KEY|token|Token|TOKEN|credential|Credential|CREDENTIAL)[sS]?\s*(:\s*String\s*)?=\s*"[^"]{8,}"' 10)
if [[ -n "$SECRETS" ]]; then
    echo "ERROR: Potential hardcoded credentials in val declarations:"
    echo "$SECRETS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious hardcoded credentials detected"
fi

# === SA-SCALA-09: XXE ===
echo ""
echo "=== Checking for XXE-Prone XML Parser Configuration ==="
XXE=$(scan_scala '(SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES)\s*,\s*true|isSupportingExternalEntities"\s*,\s*true|setExpandEntityReferences\s*\(\s*true|disallow-doctype-decl"\s*,\s*false|external-(general|parameter)-entities"\s*,\s*true')
if [[ -n "$XXE" ]]; then
    echo "ERROR: XML parser configured with DTD/external entities enabled (XXE):"
    echo "$XXE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No XXE-prone XML parser configuration detected"
fi

# === SA-SCALA-10: unsafe reflection ===
echo ""
echo "=== Checking for Unsafe Reflection ==="
REFLECT=$(scan_scala 'Class\.forName\s*\(\s*[A-Za-z_]|Class\.forName\s*\(\s*"[^"]*"\s*\+')
if [[ -n "$REFLECT" ]]; then
    echo "WARNING: Class.forName on a dynamic value — verify input cannot reach it:"
    echo "$REFLECT"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No dynamic Class.forName usage detected"
fi

# === Check build configuration ===
echo ""
echo "=== Checking Build Configuration ==="
if [[ -f "$PROJECT_DIR/build.sbt" ]]; then
    OLD_SCALA=$(grep -En 'scalaVersion\s*:=\s*"2\.(10|11|12)\.' "$PROJECT_DIR/build.sbt" 2>/dev/null || true)
    if [[ -n "$OLD_SCALA" ]]; then
        echo "WARNING: End-of-life Scala version pinned in build.sbt:"
        echo "$OLD_SCALA"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: build.sbt does not pin an end-of-life Scala version"
    fi
else
    echo "INFO: No build.sbt found — skipping build configuration check"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Scala Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

#!/bin/bash
# Dart / Flutter Security Scanner Module
# Scans Dart and Flutter projects for common vulnerability patterns
# Excludes .dart_tool/ and build/ directories

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Dart source directories (pub layout + Flutter conventions)
SCAN_DIRS=()
for dir in lib bin test example integration_test; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Fall back to scanning the project directory itself
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across all Dart source directories, excluding build output
scan_dart() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.dart" --exclude-dir=.dart_tool --exclude-dir=build --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Dart source directories
scan_dart_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E "$pattern" "$dir" --include="*.dart" --exclude-dir=.dart_tool --exclude-dir=build --exclude-dir=.git 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Dart/Flutter Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-DART-01: Command injection via Process.run/start ===
echo "=== Checking for Command Injection (Process.run/start) ==="
CMD_INJECT=$(scan_dart "Process\.(run|runSync|start)\s*\([^)]*runInShell\s*:\s*true|Process\.(run|runSync|start)\s*\(\s*['\"](sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe|powershell)['\"]")
if [[ -n "$CMD_INJECT" ]]; then
    echo "ERROR: Shell invocation or runInShell:true found — command injection risk:"
    echo "$CMD_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No shell invocation patterns detected"
fi

# === SA-DART-02 / SA-FLUTTER-03: TLS certificate validation bypass ===
echo ""
echo "=== Checking for TLS Certificate Bypass ==="
TLS_BYPASS=$(scan_dart 'badCertificateCallback\s*=[^;{]*=>\s*true|badCertificateCallback\s*=[^;]*\{\s*return\s+true|onBadCertificate\s*:\s*\([^)]*\)\s*=>\s*true')
TLS_CALLBACK=$(scan_dart 'badCertificateCallback')
if [[ -n "$TLS_BYPASS" ]]; then
    echo "ERROR: badCertificateCallback returning true — accepts any certificate:"
    echo "$TLS_BYPASS"
    ERRORS=$((ERRORS + 1))
elif [[ -n "$TLS_CALLBACK" ]]; then
    echo "WARNING: badCertificateCallback override found — audit that it never returns true:"
    echo "$TLS_CALLBACK"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No certificate validation bypass detected"
fi

# === SA-DART-03: Insecure randomness ===
echo ""
echo "=== Checking for Insecure Randomness ==="
INSECURE_RANDOM_COUNT=$(scan_dart_count '\bRandom\s*\(')
if [[ "$INSECURE_RANDOM_COUNT" -gt 0 ]]; then
    echo "WARNING: $INSECURE_RANDOM_COUNT math.Random usage(s) — use Random.secure() for security-sensitive values:"
    scan_dart '\bRandom\s*\(' 5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No predictable Random usage detected"
fi

# === SA-DART-04: SQL injection in sqflite raw queries ===
echo ""
echo "=== Checking for SQL Injection (sqflite) ==="
SQL_INJECT=$(scan_dart "\\b(rawQuery|rawInsert|rawUpdate|rawDelete)\\s*\\(\\s*(\"[^\"]*(=|>|<|\\bLIKE\\b|\\bIN\\b|\\bVALUES\\b)[^\"]*\\\$|'[^']*(=|>|<|\\bLIKE\\b|\\bIN\\b|\\bVALUES\\b)[^']*\\\$|\"[^\"]*\"\\s*\\+\\s*[A-Za-z_(]|'[^']*'\\s*\\+\\s*[A-Za-z_(])")
if [[ -n "$SQL_INJECT" ]]; then
    echo "ERROR: Raw SQL built with interpolation/concatenation — use ? bind arguments:"
    echo "$SQL_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No SQL injection patterns detected"
fi

# === SA-DART-05 / SA-FLUTTER-05: Hardcoded secrets and API keys ===
echo ""
echo "=== Checking for Hardcoded Secrets ==="
SECRETS=$(scan_dart "(const|final)\\s+(String\\s+)?[a-zA-Z_]*([Pp]assword|[Ss]ecret|[Tt]oken|[Aa]pi[Kk]ey|[Pp]wd)[a-zA-Z0-9_]*\\s*=\\s*['\"][A-Za-z0-9_=-]*([A-Za-z0-9=-]*[0-9][A-Za-z0-9=-]{7,}|[A-Za-z0-9=-]{7,}[0-9][A-Za-z0-9=-]*)[A-Za-z0-9_=-]*['\"]" 10)
KNOWN_KEYS=$(scan_dart "['\"](AIza[0-9A-Za-z_-]{20,}|sk_live_[0-9A-Za-z]{16,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}|xox[bpars]-[0-9A-Za-z-]{10,})" 10)
if [[ -n "$SECRETS" || -n "$KNOWN_KEYS" ]]; then
    echo "ERROR: Potential hardcoded credentials/API keys found:"
    { echo "$SECRETS"; echo "$KNOWN_KEYS"; } | grep -v '^$' | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious hardcoded secrets detected"
fi

# === SA-DART-06: Plaintext HTTP endpoints ===
echo ""
echo "=== Checking for Plaintext HTTP Endpoints ==="
PLAIN_HTTP=$(scan_dart "(Uri\\.parse\\s*\\(\\s*|[a-zA-Z0-9_]*([Uu]rl|[Uu]ri|[Ee]ndpoint|[Hh]ost|[Bb]ase)[a-zA-Z0-9_]*\\s*[:=]\\s*)['\"]http://[a-zA-Z0-9.-]+\\.(com|net|org|io|dev|co|app|cloud|ai)|\\bUri\\.http\\s*\\(")
if [[ -n "$PLAIN_HTTP" ]]; then
    echo "WARNING: Plaintext http:// endpoints found — use https://:"
    echo "$PLAIN_HTTP"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No plaintext HTTP endpoints detected"
fi

# === SA-DART-07: Weak hashing (md5/sha1) ===
echo ""
echo "=== Checking for Weak Hash Usage ==="
WEAK_HASH=$(scan_dart '\b(md5|sha1)\s*\.\s*convert\s*\(|\bHmac\s*\(\s*(md5|sha1)\s*,')
if [[ -n "$WEAK_HASH" ]]; then
    echo "WARNING: md5/sha1 usage found — use sha256 for integrity, a KDF for passwords:"
    echo "$WEAK_HASH"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No weak hash usage detected"
fi

# === SA-DART-08: Remote code loading via Isolate.spawnUri ===
echo ""
echo "=== Checking for Isolate.spawnUri Code Loading ==="
SPAWN_URI=$(scan_dart 'Isolate\.spawnUri\s*\(')
if [[ -n "$SPAWN_URI" ]]; then
    echo "ERROR: Isolate.spawnUri found — executes code from a URI, RCE risk:"
    echo "$SPAWN_URI"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No Isolate.spawnUri usage detected"
fi

# === SA-DART-09: Path traversal via File() from user input ===
echo ""
echo "=== Checking for Path Traversal (File from user input) ==="
PATH_TRAVERSAL=$(scan_dart "\\bFile\\s*\\(\\s*['\"][^'\"]*\\\$\\{?(request|params|query|input|user(Input|Name|File|Path|Id)?\\b)|\\bFile\\s*\\([^)]*\\+\\s*(request|params|query|input|user(Input|Name|File|Path|Id)?\\b)")
if [[ -n "$PATH_TRAVERSAL" ]]; then
    echo "ERROR: File() path built from user-controlled input — sanitize with basename:"
    echo "$PATH_TRAVERSAL"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No path traversal patterns detected"
fi

# === SA-DART-10 / SA-FLUTTER-06: Sensitive data in logs ===
echo ""
echo "=== Checking for Sensitive Data in Logs ==="
SENSITIVE_LOG=$(scan_dart "\\b(print|log|debugPrint)\\s*\\(\\s*jsonEncode\\s*\\(\\s*[a-zA-Z_]*([Cc]redential|[Aa]uth|[Tt]oken|[Ss]ecret|[Uu]ser)s?\\b|\\b(print|debugPrint)\\s*\\([^)]*\\\$\\{?[a-zA-Z_.]*([Pp]assword|[Tt]oken|[Ss]ecret|[Aa]pi[Kk]ey|[Bb]earer)s?\\b")
if [[ -n "$SENSITIVE_LOG" ]]; then
    echo "WARNING: Credentials/tokens flowing into print/log — redact before logging:"
    echo "$SENSITIVE_LOG"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No sensitive logging patterns detected"
fi

# === SA-FLUTTER-01: WebView with unrestricted JavaScript ===
echo ""
echo "=== Checking for Unrestricted WebView JavaScript ==="
WEBVIEW_JS=$(scan_dart 'Java[Ss]criptMode\.unrestricted')
if [[ -n "$WEBVIEW_JS" ]]; then
    echo "WARNING: JavaScriptMode.unrestricted found — audit the content loaded into this WebView:"
    echo "$WEBVIEW_JS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No unrestricted WebView JavaScript detected"
fi

# === SA-FLUTTER-02: Secrets in SharedPreferences ===
echo ""
echo "=== Checking for Secrets in SharedPreferences ==="
PREFS_SECRETS=$(scan_dart "\\.setString\\s*\\(\\s*['\"]([a-zA-Z_.-]*([Aa]uth|[Aa]ccess|[Rr]efresh|[Ss]ession|[Ii]d|[Aa]pi|[Bb]earer|[Uu]ser)[_.-]?[Tt]oken|[Tt]oken['\"]|[a-zA-Z_.-]*([Pp]assword|[Ss]ecret|[Cc]redential|[Aa]pi[Kk]ey|[Jj]wt))")
if [[ -n "$PREFS_SECRETS" ]]; then
    echo "ERROR: Secrets stored via SharedPreferences.setString — use flutter_secure_storage:"
    echo "$PREFS_SECRETS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No secrets in SharedPreferences detected"
fi

# === SA-FLUTTER-04: Unvalidated launchUrl targets ===
echo ""
echo "=== Checking for Unvalidated URL Launching ==="
LAUNCH_URL=$(scan_dart '\blaunchUrl\s*\(\s*Uri\.parse\s*\(\s*[a-zA-Z_]|\blaunchUrlString\s*\(\s*[a-zA-Z_]')
if [[ -n "$LAUNCH_URL" ]]; then
    echo "WARNING: launchUrl/launchUrlString on a variable — validate scheme and host first:"
    echo "$LAUNCH_URL"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No unvalidated URL launching detected"
fi

# === SA-FLUTTER-07: Deep-link handling ===
echo ""
echo "=== Checking for Deep-Link Handling ==="
DEEP_LINKS=$(scan_dart '(uriLinkStream|linkStream)\s*\.\s*listen|getInitial(Uri|Link)\s*\(')
if [[ -n "$DEEP_LINKS" ]]; then
    echo "WARNING: Deep-link entry points found — verify scheme/host/path validation before use:"
    echo "$DEEP_LINKS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No deep-link entry points detected"
fi

# === SA-FLUTTER-08: WebView loading user-supplied URLs ===
echo ""
echo "=== Checking for WebView Loading Dynamic URLs ==="
WEBVIEW_URL=$(scan_dart 'loadRequest\s*\(\s*Uri\.parse\s*\(\s*[a-zA-Z_]|\.loadUrl\s*\(\s*[a-zA-Z_][a-zA-Z0-9_.]*\s*[),]')
if [[ -n "$WEBVIEW_URL" ]]; then
    echo "WARNING: WebView loads a URL from a variable — restrict to an allowlist:"
    echo "$WEBVIEW_URL"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No dynamic WebView URL loading detected"
fi

# === Check dependencies ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/pubspec.lock" ]]; then
    if command -v osv-scanner &> /dev/null; then
        OSV_OUTPUT=$(osv-scanner --lockfile "$PROJECT_DIR/pubspec.lock" 2>&1 || true)
        if echo "$OSV_OUTPUT" | grep -qi "vulnerab"; then
            echo "WARNING: Vulnerable dependencies found:"
            echo "$OSV_OUTPUT" | head -20
            WARNINGS=$((WARNINGS + 1))
        else
            echo "OK: No known vulnerable dependencies"
        fi
    else
        echo "INFO: osv-scanner not available — install it or run: dart pub outdated"
    fi
else
    echo "INFO: No pubspec.lock found — skipping dependency check"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Dart/Flutter Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

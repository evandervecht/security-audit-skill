#!/bin/bash
# PHP Security Scanner Module
# Extracted from security-audit.sh for modular scanner architecture
# Scans PHP projects for common vulnerability patterns

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect PHP source directories
SCAN_DIRS=()
for dir in src Classes; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Helper: grep across all PHP source directories
scan_php() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.php" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all PHP source directories
scan_php_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E "$pattern" "$dir" --include="*.php" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- PHP Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No PHP source directories found (looked for src/ and Classes/)"
    exit 0
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === Check for hardcoded secrets ===
echo "=== Checking for Hardcoded Secrets ==="
SECRETS=$(scan_php "(password|api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]" 10 | grep -v "getenv\|env(" || true)
if [[ -n "$SECRETS" ]]; then
    echo "WARNING: Potential hardcoded secrets found:"
    echo "$SECRETS" | head -5
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No obvious hardcoded secrets detected"
fi

# === Check for SQL injection patterns ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
# shellcheck disable=SC2016
SQL_VULN=$(scan_php '\$_(GET|POST|REQUEST|COOKIE).*->(query|execute|prepare)')
SQL_CONCAT=$(scan_php '"(SELECT|INSERT|UPDATE|DELETE)\s.*\.\s*\$' 5)
if [[ -n "$SQL_VULN" || -n "$SQL_CONCAT" ]]; then
    echo "ERROR: Potential SQL injection patterns found:"
    [[ -n "$SQL_VULN" ]] && echo "$SQL_VULN"
    [[ -n "$SQL_CONCAT" ]] && echo "$SQL_CONCAT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious SQL injection patterns detected"
fi

# === Check for XXE vulnerabilities ===
echo ""
echo "=== Checking for XXE Vulnerabilities ==="
XXE_PATTERNS=$(scan_php "(simplexml_load_string|DOMDocument|XMLReader)" 10)
if [[ -n "$XXE_PATTERNS" ]]; then
    SECURED=$(scan_php_count "LIBXML_NONET|libxml_disable_entity_loader")
    if [[ "$SECURED" -eq 0 ]]; then
        echo "WARNING: XML parsing found without obvious XXE protection:"
        echo "$XXE_PATTERNS" | head -5
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: XML parsing with security flags detected"
    fi
    DANGEROUS_FLAGS=$(scan_php "LIBXML_NOENT|LIBXML_DTDLOAD")
    if [[ -n "$DANGEROUS_FLAGS" ]]; then
        echo "ERROR: LIBXML_NOENT/LIBXML_DTDLOAD found (these ENABLE XXE):"
        echo "$DANGEROUS_FLAGS"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "OK: No XML parsing detected"
fi

# === Check for command injection ===
echo ""
echo "=== Checking for Command Injection ==="
CMD_INJECTION=$(scan_php "(exec|system|passthru|shell_exec|proc_open|popen)\s*\(.*\\\$")
if [[ -n "$CMD_INJECTION" ]]; then
    echo "ERROR: Potential command injection found:"
    echo "$CMD_INJECTION"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious command injection patterns detected"
fi

# === Check for dangerous functions ===
echo ""
echo "=== Checking for Dangerous Functions ==="
DANGEROUS=$(scan_php "(eval|assert|create_function|preg_replace.*\/e|unserialize\s*\(\s*\\\$)")
if [[ -n "$DANGEROUS" ]]; then
    echo "WARNING: Potentially dangerous functions found:"
    echo "$DANGEROUS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No obviously dangerous functions detected"
fi

# === Check for file inclusion vulnerabilities ===
echo ""
echo "=== Checking for File Inclusion Vulnerabilities ==="
INCLUDE_VULN=$(scan_php "(include|require|include_once|require_once)\s*\(\s*\\\$")
if [[ -n "$INCLUDE_VULN" ]]; then
    echo "WARNING: Potential file inclusion vulnerabilities:"
    echo "$INCLUDE_VULN"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No obvious file inclusion vulnerabilities"
fi

# === Check for XSS patterns ===
echo ""
echo "=== Checking for XSS Patterns ==="
XSS_PATTERNS=$(scan_php "echo\s+\\\$_(GET|POST|REQUEST)")
if [[ -n "$XSS_PATTERNS" ]]; then
    echo "ERROR: Potential XSS vulnerabilities:"
    echo "$XSS_PATTERNS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious XSS patterns detected"
fi

# === Check for insecure password hashing ===
echo ""
echo "=== Checking for Insecure Password Hashing ==="
INSECURE_HASH=$(scan_php "(md5|sha1)\s*\(.*\\\$(password|passwd|pass|pwd)")
if [[ -n "$INSECURE_HASH" ]]; then
    echo "ERROR: Insecure password hashing detected:"
    echo "$INSECURE_HASH"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No insecure password hashing detected"
fi

# === Check for insecure randomness ===
echo ""
echo "=== Checking for Insecure Randomness ==="
INSECURE_RAND=$(scan_php "\b(rand|mt_rand|srand|mt_srand)\s*\(")
if [[ -n "$INSECURE_RAND" ]]; then
    echo "WARNING: Insecure random functions found:"
    echo "$INSECURE_RAND"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No insecure random functions detected"
fi

# === Check for path traversal ===
echo ""
echo "=== Checking for Path Traversal ==="
PATH_TRAV=$(scan_php "(file_get_contents|fopen|readfile|file_put_contents)\s*\(.*\\\$_(GET|POST|REQUEST)")
if [[ -n "$PATH_TRAV" ]]; then
    echo "ERROR: Potential path traversal vulnerability:"
    echo "$PATH_TRAV"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious path traversal patterns detected"
fi

# === Check for phpinfo() exposure ===
echo ""
echo "=== Checking for Information Disclosure ==="
PHPINFO=$(scan_php "phpinfo\s*\(")
if [[ -n "$PHPINFO" ]]; then
    echo "WARNING: phpinfo() calls found:"
    echo "$PHPINFO"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No phpinfo() exposure detected"
fi

# === Check for missing strict_types ===
echo ""
echo "=== Checking for strict_types Declaration ==="
TOTAL_PHP=0
STRICT_PHP=0
for dir in "${SCAN_DIRS[@]}"; do
    local_total=$(find "$dir" -name "*.php" 2>/dev/null | wc -l || echo "0")
    local_strict=$(grep -rl "declare(strict_types=1)" "$dir" --include="*.php" 2>/dev/null | wc -l || echo "0")
    TOTAL_PHP=$((TOTAL_PHP + local_total))
    STRICT_PHP=$((STRICT_PHP + local_strict))
done
if [[ "$TOTAL_PHP" -gt 0 ]]; then
    PERCENT=$((STRICT_PHP * 100 / TOTAL_PHP))
    if [[ "$PERCENT" -lt 50 ]]; then
        echo "WARNING: Only $STRICT_PHP/$TOTAL_PHP PHP files ($PERCENT%) use declare(strict_types=1)"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: $STRICT_PHP/$TOTAL_PHP PHP files ($PERCENT%) use strict_types"
    fi
fi

# === Check for composer vulnerabilities ===
echo ""
echo "=== Checking Dependencies ==="
if [[ -f "$PROJECT_DIR/composer.lock" ]]; then
    if command -v composer &> /dev/null; then
        AUDIT_OUTPUT=$(cd "$PROJECT_DIR" && composer audit 2>&1 || true)
        if echo "$AUDIT_OUTPUT" | grep -q "Found"; then
            echo "WARNING: Vulnerable dependencies found:"
            echo "$AUDIT_OUTPUT" | head -20
            WARNINGS=$((WARNINGS + 1))
        else
            echo "OK: No known vulnerable dependencies"
        fi
    else
        echo "WARNING: Composer not available for dependency audit"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "WARNING: No composer.lock found"
    WARNINGS=$((WARNINGS + 1))
fi

# === Check security headers ===
echo ""
echo "=== Checking Security Headers ==="
HEADERS=$(scan_php_count "X-Content-Type-Options|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security")
if [[ "$HEADERS" -gt 0 ]]; then
    echo "OK: Security headers configuration found ($HEADERS references)"
else
    echo "WARNING: No security headers configuration detected"
    WARNINGS=$((WARNINGS + 1))
fi

# === Check for CSRF protection ===
echo ""
echo "=== Checking CSRF Protection ==="
CSRF=$(scan_php_count "(csrf|_token|CsrfToken|FormProtection)")
if [[ "$CSRF" -gt 0 ]]; then
    echo "OK: CSRF protection references found ($CSRF occurrences)"
else
    echo "WARNING: No CSRF protection detected"
    WARNINGS=$((WARNINGS + 1))
fi

# === Check for SSRF patterns ===
echo ""
echo "=== Checking for SSRF Patterns ==="
# shellcheck disable=SC2016
SSRF_PATTERNS=$(scan_php '(file_get_contents|curl_init|curl_setopt.*CURLOPT_URL)\s*\([^)]*\$_(GET|POST|REQUEST)')
if [[ -n "$SSRF_PATTERNS" ]]; then
    echo "ERROR: Potential SSRF vulnerability:"
    echo "$SSRF_PATTERNS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious SSRF patterns detected"
fi

# === Check for IDOR patterns ===
echo ""
echo "=== Checking for IDOR Patterns ==="
# shellcheck disable=SC2016
IDOR_PATTERNS=$(scan_php '->find\(\s*\$_(GET|POST|REQUEST)\[')
if [[ -n "$IDOR_PATTERNS" ]]; then
    echo "WARNING: Potential IDOR pattern:"
    echo "$IDOR_PATTERNS"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No obvious IDOR patterns detected"
fi

# === Check for type juggling ===
echo ""
echo "=== Checking for Type Juggling ==="
# shellcheck disable=SC2016
TYPE_JUGGLE=$(scan_php '==\s*\$_(GET|POST|REQUEST|COOKIE)')
if [[ -n "$TYPE_JUGGLE" ]]; then
    echo "ERROR: Loose comparison with user input:"
    echo "$TYPE_JUGGLE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious type juggling patterns detected"
fi

# === Check for PHAR deserialization ===
echo ""
echo "=== Checking for PHAR Deserialization ==="
PHAR_PATTERNS=$(scan_php 'phar://')
if [[ -n "$PHAR_PATTERNS" ]]; then
    echo "ERROR: phar:// stream wrapper found:"
    echo "$PHAR_PATTERNS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No phar:// usage detected"
fi

# === Check for email header injection ===
echo ""
echo "=== Checking for Email Header Injection ==="
# shellcheck disable=SC2016
EMAIL_INJECT=$(scan_php '\bmail\s*\([^)]*\$_(GET|POST|REQUEST)')
if [[ -n "$EMAIL_INJECT" ]]; then
    echo "ERROR: mail() with user input:"
    echo "$EMAIL_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No email header injection patterns detected"
fi

# === Check for LDAP injection ===
echo ""
echo "=== Checking for LDAP Injection ==="
# shellcheck disable=SC2016
LDAP_INJECT=$(scan_php 'ldap_(search|bind)\s*\([^)]*\$_(GET|POST|REQUEST)')
if [[ -n "$LDAP_INJECT" ]]; then
    echo "ERROR: LDAP operation with user input:"
    echo "$LDAP_INJECT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No LDAP injection patterns detected"
fi

# === Check for insecure token generation ===
echo ""
echo "=== Checking for Insecure Token Generation ==="
INSECURE_TOKEN=$(scan_php '(md5|sha1)\s*\(\s*(time|microtime|uniqid|rand|mt_rand)\s*\(')
if [[ -n "$INSECURE_TOKEN" ]]; then
    echo "ERROR: Predictable token generation:"
    echo "$INSECURE_TOKEN"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No insecure token generation detected"
fi

# === Check for session fixation ===
echo ""
echo "=== Checking for Session Fixation ==="
# shellcheck disable=SC2016
SESSION_FIX=$(scan_php 'session_id\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)')
if [[ -n "$SESSION_FIX" ]]; then
    echo "ERROR: Session ID set from user input:"
    echo "$SESSION_FIX"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No session fixation patterns detected"
fi

# === Check for log injection ===
echo ""
echo "=== Checking for Log Injection ==="
# shellcheck disable=SC2016
LOG_INJECT=$(scan_php 'error_log\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)')
if [[ -n "$LOG_INJECT" ]]; then
    echo "WARNING: Unsanitized user input in log calls:"
    echo "$LOG_INJECT"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No log injection patterns detected"
fi

# === Check for insecure cookie settings ===
echo ""
echo "=== Checking Cookie Security ==="
INSECURE_COOKIES=$(scan_php "setcookie\s*\(" 10)
if [[ -n "$INSECURE_COOKIES" ]]; then
    SECURE_COOKIES=$(scan_php_count "setcookie.*secure.*httponly|setcookie.*httponly.*secure|SameSite")
    if [[ "$SECURE_COOKIES" -eq 0 ]]; then
        echo "WARNING: setcookie() calls without secure flags:"
        echo "$INSECURE_COOKIES" | head -3
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: Cookie security flags detected"
    fi
else
    echo "OK: No direct setcookie() calls"
fi

# === Output results for dispatcher ===
echo ""
echo "--- PHP Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

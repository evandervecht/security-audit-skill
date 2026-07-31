#!/bin/bash
# Play Framework (Scala) Security Scanner Module
# Scans Play 2.9/3.x projects: Scala sources, Twirl templates, and HOCON config
# Excludes target/ directory

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Play source directories (app/, conf/, test/, modules/)
SCAN_DIRS=()
for dir in app conf test modules; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across all Play source directories with a per-check include glob
scan_play() {
    local pattern="$1"
    local include="$2"
    local limit="${3:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E -e "$pattern" "$dir" --include="$include" --exclude-dir=target --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

echo "--- Play Framework Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-PLAY-01: CSRF filter disabled ===
echo "=== Checking CSRF Filter Configuration ==="
CSRF_DISABLED=$(scan_play 'play\.filters\.disabled\s*(\+=|=).*"play\.filters\.csrf\.CSRFFilter"' "*.conf")
if [[ -n "$CSRF_DISABLED" ]]; then
    echo "ERROR: CSRFFilter removed via play.filters.disabled:"
    echo "$CSRF_DISABLED"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: CSRF filter not disabled in config"
fi

# === SA-PLAY-02: Raw HTML injection in Twirl templates ===
echo ""
echo "=== Checking Twirl Templates for Raw HTML ==="
RAW_HTML=$(scan_play '@Html\s*\(' "*.scala.html")
if [[ -n "$RAW_HTML" ]]; then
    echo "ERROR: @Html(...) bypasses Twirl auto-escaping:"
    echo "$RAW_HTML"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No raw @Html usage detected in templates"
fi

# === SA-PLAY-03: SQL injection via string interpolation ===
echo ""
echo "=== Checking for SQL Injection Patterns ==="
SQL_INTERP=$(scan_play '\bSQL\s*\(\s*s"+[^"]*\$|\bsqlu?"+[^"]*#\$' "*.scala")
if [[ -n "$SQL_INTERP" ]]; then
    echo "ERROR: Anorm SQL(s-interpolator) or Slick #\$ splicing embeds user input:"
    echo "$SQL_INTERP"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No interpolated SQL detected"
fi

# === SA-PLAY-04: Permissive CORS origins ===
echo ""
echo "=== Checking CORS Configuration ==="
CORS_OPEN=$(scan_play 'allowedOrigins\s*=\s*(null|\[\s*"\*"\s*\])' "*.conf")
if [[ -n "$CORS_OPEN" ]]; then
    echo "WARNING: allowedOrigins = null or [\"*\"] accepts any origin:"
    echo "$CORS_OPEN"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No permissive CORS origins detected"
fi

# === SA-PLAY-05: Session cookie without Secure flag ===
echo ""
echo "=== Checking Session Cookie Configuration ==="
SESSION_INSECURE=$(scan_play 'session\.secure\s*=\s*false|session\s*\{[^}]*secure\s*=\s*false' "*.conf")
if [[ -n "$SESSION_INSECURE" ]]; then
    echo "WARNING: play.http.session secure = false sends the session over HTTP:"
    echo "$SESSION_INSECURE"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: Session cookie Secure flag not disabled"
fi

# === SA-PLAY-06: AllowedHostsFilter wildcard ===
echo ""
echo "=== Checking Allowed Hosts Filter ==="
HOSTS_WILDCARD=$(scan_play 'allowed\s*=\s*\[[^]]*"\."' "*.conf")
if [[ -n "$HOSTS_WILDCARD" ]]; then
    echo "WARNING: play.filters.hosts allowed entry \".\" accepts any Host header:"
    echo "$HOSTS_WILDCARD"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No wildcard allowed-hosts entry detected"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Play Framework Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

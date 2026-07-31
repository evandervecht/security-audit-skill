#!/bin/bash
# Shell Script Security Scanner Module
# Scans shell scripts (.sh/.bash) for common vulnerability patterns
# Excludes .git/, node_modules/, and vendor/ directories

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect conventional shell script directories
SCAN_DIRS=()
for dir in scripts bin tools ci deploy hooks; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done

# Fall back to scanning the project directory itself
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS=("$PROJECT_DIR")
fi

# Helper: grep across all shell source directories
scan_sh() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E -e "$pattern" "$dir" --include="*.sh" --include="*.bash" \
            --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

echo "--- Shell Security Scanner ---"
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# === SA-SH-01: eval on variables ===
echo "=== Checking for eval on Variables ==="
EVAL_VAR=$(scan_sh '\beval\s+["'\'']?\$\{?[A-Za-z_0-9]|\beval\s+["'\'']?\$\((curl|wget)\b')
if [[ -n "$EVAL_VAR" ]]; then
    echo "ERROR: eval on variable/command output — command injection:"
    echo "$EVAL_VAR"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No eval-on-variable patterns detected"
fi

# === SA-SH-02: curl/wget piped to a shell ===
echo ""
echo "=== Checking for Download Piped to Shell ==="
PIPE_SH=$(scan_sh '\b(curl|wget)\s[A-Za-z0-9_ ="'\''@:.,%?#~$+/-]*\|\s*(sudo\s+)?(bash|sh|zsh)\b')
if [[ -n "$PIPE_SH" ]]; then
    echo "ERROR: curl/wget piped straight into a shell — unverified remote code execution:"
    echo "$PIPE_SH"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No download-piped-to-shell patterns detected"
fi

# === SA-SH-03: TLS verification disabled ===
echo ""
echo "=== Checking for Disabled TLS Verification ==="
TLS_OFF=$(scan_sh 'curl\s[A-Za-z0-9_ ="'\''@:.,%?#~$+/-]*\s-[A-Za-z]*k[A-Za-z]*\b|curl\s+-[A-Za-z]*k[A-Za-z]*\b|curl\s[A-Za-z0-9_ ="'\''@:.,%?#~$+/-]*--insecure\b|wget\s[A-Za-z0-9_ ="'\''@:.,%?#~$+/-]*--no-check-certificate\b')
if [[ -n "$TLS_OFF" ]]; then
    echo "ERROR: curl -k/--insecure or wget --no-check-certificate — MITM exposure:"
    echo "$TLS_OFF"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No disabled TLS verification detected"
fi

# === SA-SH-04: SSH host key verification disabled ===
echo ""
echo "=== Checking for Disabled SSH Host Key Verification ==="
SSH_OFF=$(scan_sh 'StrictHostKeyChecking[ =]+no\b|UserKnownHostsFile[ =]+/dev/null')
if [[ -n "$SSH_OFF" ]]; then
    echo "ERROR: StrictHostKeyChecking=no / UserKnownHostsFile=/dev/null — SSH MITM exposure:"
    echo "$SSH_OFF"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No disabled SSH host key verification detected"
fi

# === SA-SH-05: predictable temp files ===
echo ""
echo "=== Checking for Predictable Temp Files ==="
TMP_PID=$(scan_sh '/(tmp|var/tmp)/[A-Za-z0-9._-]*\$\$')
if [[ -n "$TMP_PID" ]]; then
    echo "WARNING: PID-based temp file — symlink attack risk, use mktemp:"
    echo "$TMP_PID"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No predictable temp file patterns detected"
fi

# === SA-SH-06: world-writable permissions ===
echo ""
echo "=== Checking for World-Writable chmod ==="
CHMOD_777=$(scan_sh 'chmod\s+(-[A-Za-z]+\s+)*(0?777|a\+rwx)\b')
if [[ -n "$CHMOD_777" ]]; then
    echo "WARNING: chmod 777/a+rwx — use least-privilege modes and chown:"
    echo "$CHMOD_777"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No world-writable chmod detected"
fi

# === SA-SH-07: hardcoded credentials ===
echo ""
echo "=== Checking for Hardcoded Credentials ==="
SECRETS=$(scan_sh '[A-Za-z_]*(PASSWORD|PASSWD|SECRET(_KEY)?|TOKEN|API_KEY|APIKEY|ACCESS_KEY)=["'\'']?[A-Za-z0-9+_.-]{8,}' 10)
if [[ -n "$SECRETS" ]]; then
    echo "ERROR: Potential hardcoded credentials found:"
    echo "$SECRETS" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No obvious hardcoded secrets detected"
fi

# === SA-SH-08: secrets echoed to stdout/logs ===
echo ""
echo "=== Checking for Secrets Echoed to Logs ==="
ECHO_SECRET=$(scan_sh '(echo|printf)\s[A-Za-z0-9_ ="'\''@:.,%?!#~()+{}$/-]*\$\{?[A-Za-z_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY)\b')
if [[ -n "$ECHO_SECRET" ]]; then
    echo "ERROR: Secret variable echoed to stdout/logs — credential leak:"
    echo "$ECHO_SECRET"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No echoed secrets detected"
fi

# === SA-SH-09: unquoted rm -rf with variable path ===
echo ""
echo "=== Checking for Unquoted rm -rf ==="
RM_UNQUOTED=$(scan_sh '\brm\s+-[A-Za-z]*r[A-Za-z]*\s+(-[A-Za-z]+\s+)*[A-Za-z0-9_./-]*\$')
if [[ -n "$RM_UNQUOTED" ]]; then
    echo "WARNING: Unquoted rm -rf with variable path — word splitting/empty-var disaster:"
    echo "$RM_UNQUOTED"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No unquoted rm -rf patterns detected"
fi

# === SA-SH-10: sourcing remote content ===
echo ""
echo "=== Checking for Sourced Remote Content ==="
SRC_REMOTE=$(scan_sh '(^|[^A-Za-z0-9_.])(source|bash|zsh|sh|\.)\s+<\(\s*(curl|wget)\b')
if [[ -n "$SRC_REMOTE" ]]; then
    echo "ERROR: Sourcing/running process substitution of curl/wget — unverified remote code:"
    echo "$SRC_REMOTE"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No sourced remote content detected"
fi

# === SA-SH-11: passwords on the command line ===
echo ""
echo "=== Checking for Passwords on the Command Line ==="
CLI_PASS=$(scan_sh 'mysql[A-Za-z0-9_ ="'\''@:.,%+/-]*\s(-p[A-Za-z0-9_.!@#%^*+=]|--password=)|psql[A-Za-z0-9_ ="'\''@:.,%+/-]*://[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+@|curl\s[A-Za-z0-9_ ="'\''@:.,%?#~+/-]*-u\s+["'\'']?[A-Za-z0-9_.-]+:[A-Za-z0-9]')
if [[ -n "$CLI_PASS" ]]; then
    echo "ERROR: Credential passed on the command line — visible in ps and shell history:"
    echo "$CLI_PASS"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No command-line credentials detected"
fi

# === SA-SH-12: find | xargs without -print0 ===
echo ""
echo "=== Checking for find | xargs Without NUL Delimiters ==="
XARGS_SPLIT=$(scan_sh '\bfind\s[A-Za-z0-9_ ="'\''@:.,%!*()+{}$\\/-]*\|\s*xargs\s+(-[A-Za-z]+\s+)*[A-Za-z/]')
if [[ -n "$XARGS_SPLIT" ]]; then
    echo "WARNING: find piped to xargs without -print0/-0 — crafted filenames inject arguments:"
    echo "$XARGS_SPLIT"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No unsafe find/xargs pipelines detected"
fi

# === Optional: shellcheck ===
echo ""
echo "=== Checking with shellcheck ==="
if command -v shellcheck &> /dev/null; then
    SC_OUT=""
    for dir in "${SCAN_DIRS[@]}"; do
        while IFS= read -r -d '' script; do
            SC_OUT+="$(shellcheck -S warning "$script" 2>/dev/null || true)"$'\n'
        done < <(find "$dir" -name "*.sh" -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" -print0 2>/dev/null)
    done
    if [[ -n "$SC_OUT" ]]; then
        echo "INFO: shellcheck reported findings (review recommended):"
        echo "$SC_OUT" | head -20
    else
        echo "OK: shellcheck reported no warnings"
    fi
else
    echo "INFO: shellcheck not available — install for deeper analysis"
fi

# === Output results for dispatcher ===
echo ""
echo "--- Shell Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

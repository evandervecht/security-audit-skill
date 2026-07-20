#!/bin/bash
# Rust Web Framework Security Scanner Module (actix-web / axum)
# Scans Rust web projects for framework-specific vulnerability patterns
# Framework detection via Cargo.toml; excludes target/ directory
# Complements rust.sh (language-level checks) with SA-ACTIX-* / SA-AXUM-* checks

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# --- Framework detection via Cargo.toml ---
HAS_ACTIX=0
HAS_AXUM=0
FOUND_MANIFEST=0
while IFS= read -r manifest; do
    FOUND_MANIFEST=1
    if grep -q "actix-web" "$manifest" 2>/dev/null; then
        HAS_ACTIX=1
    fi
    if grep -q -E '^\s*axum(-extra)?\s*=|dependencies\.axum' "$manifest" 2>/dev/null; then
        HAS_AXUM=1
    fi
done < <(find "$PROJECT_DIR" -name "Cargo.toml" -not -path "*/target/*" -not -path "*/.git/*" 2>/dev/null)

echo "--- Rust Web (actix-web / axum) Security Scanner ---"

if [[ "$FOUND_MANIFEST" -eq 0 ]]; then
    # No manifest at all: scan for both frameworks anyway (e.g. code fragments)
    HAS_ACTIX=1
    HAS_AXUM=1
    echo "No Cargo.toml found — scanning for both actix-web and axum patterns"
elif [[ "$HAS_ACTIX" -eq 0 && "$HAS_AXUM" -eq 0 ]]; then
    echo "Neither actix-web nor axum found in Cargo.toml — skipping"
    exit 0
else
    [[ "$HAS_ACTIX" -eq 1 ]] && echo "Detected: actix-web"
    [[ "$HAS_AXUM" -eq 1 ]] && echo "Detected: axum"
fi

# --- Auto-detect Rust source directories ---
SCAN_DIRS=()
for dir in src examples tests benches; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
# Fall back to the project directory itself if no conventional layout exists
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS+=("$PROJECT_DIR")
fi
echo "Scanning: ${SCAN_DIRS[*]}"
echo ""

# Helper: grep across all Rust source directories, excluding target/
scan_rs() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.rs" --exclude-dir=target --exclude-dir=.git 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# ===================== Shared checks (both frameworks) =====================

# === SA-ACTIX-04 / SA-AXUM-03: SQL built with format! ===
echo "=== Checking for SQL Built with format! (sqlx/diesel) ==="
SQL_FMT=$(scan_rs 'sqlx::query(_as|_scalar)?\s*\(\s*&\s*format!|sql_query\s*\(\s*&?\s*format!')
if [[ -n "$SQL_FMT" ]]; then
    echo "ERROR: SQL query assembled with format! — use bind parameters (\$1 + .bind()):"
    echo "$SQL_FMT"
    ERRORS=$((ERRORS + 1))
else
    echo "OK: No format!-built SQL detected"
fi

# === SA-ACTIX-06 / SA-AXUM-06: cookies with .secure(false) ===
echo ""
echo "=== Checking for Insecure Cookie Flags ==="
INSECURE_COOKIE=$(scan_rs '\.secure\s*\(\s*false\s*\)|cookie_secure\s*\(\s*false\s*\)')
if [[ -n "$INSECURE_COOKIE" ]]; then
    echo "WARNING: Cookie built with .secure(false) — set .secure(true) + http_only + SameSite:"
    echo "$INSECURE_COOKIE"
    WARNINGS=$((WARNINGS + 1))
else
    echo "OK: No insecure cookie flags detected"
fi

# ===================== actix-web specific checks =====================
if [[ "$HAS_ACTIX" -eq 1 ]]; then

    # === SA-ACTIX-01: Cors::permissive() ===
    echo ""
    echo "=== Checking for Cors::permissive() ==="
    CORS_PERM=$(scan_rs 'Cors::permissive\s*\(')
    if [[ -n "$CORS_PERM" ]]; then
        echo "WARNING: Cors::permissive() found — use Cors::default() with allowed_origin allowlist:"
        echo "$CORS_PERM"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: No Cors::permissive() detected"
    fi

    # === SA-ACTIX-02: allow_any_origin + supports_credentials (per-file AND) ===
    echo ""
    echo "=== Checking for Any-Origin CORS with Credentials ==="
    CRED_FILES=""
    for dir in "${SCAN_DIRS[@]}"; do
        while IFS= read -r f; do
            if grep -q "supports_credentials" "$f" 2>/dev/null; then
                CRED_FILES+="$f"$'\n'
            fi
        done < <(grep -rl -E 'allow_any_origin\s*\(' "$dir" --include="*.rs" --exclude-dir=target --exclude-dir=.git 2>/dev/null || true)
    done
    CRED_FILES=$(echo "$CRED_FILES" | grep -v '^$' || true)
    if [[ -n "$CRED_FILES" ]]; then
        echo "ERROR: allow_any_origin() combined with supports_credentials() — pin allowed_origin:"
        echo "$CRED_FILES" | head -5
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: No credentialed any-origin CORS detected"
    fi

    # === SA-ACTIX-03: NamedFile::open on request-derived path ===
    echo ""
    echo "=== Checking for NamedFile Path Traversal ==="
    NAMEDFILE=$(scan_rs 'NamedFile::open(_async)?\s*\(\s*(format!|&?req\.)')
    if [[ -n "$NAMEDFILE" ]]; then
        echo "ERROR: NamedFile::open on request-built path — validate file_name() and canonicalize:"
        echo "$NAMEDFILE"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: No NamedFile traversal patterns detected"
    fi

    # === SA-ACTIX-05: HttpResponse body(format!("<...")) reflected XSS ===
    echo ""
    echo "=== Checking for Reflected XSS via body(format!) ==="
    BODY_XSS=$(scan_rs '\.body\s*\(\s*format!\s*\(\s*"[^"]*<[a-zA-Z!/]')
    if [[ -n "$BODY_XSS" ]]; then
        echo "ERROR: HTML response body built with format! — use an escaping template engine:"
        echo "$BODY_XSS"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: No format!-built HTML bodies detected"
    fi
fi

# ===================== axum specific checks =====================
if [[ "$HAS_AXUM" -eq 1 ]]; then

    # === SA-AXUM-01: CorsLayer::permissive()/very_permissive() ===
    echo ""
    echo "=== Checking for CorsLayer::permissive()/very_permissive() ==="
    CORSLAYER=$(scan_rs 'CorsLayer::(very_)?permissive\s*\(')
    if [[ -n "$CORSLAYER" ]]; then
        echo "WARNING: Permissive CorsLayer found — use CorsLayer::new() with explicit allow_origin:"
        echo "$CORSLAYER"
        WARNINGS=$((WARNINGS + 1))
    else
        echo "OK: No permissive CorsLayer detected"
    fi

    # === SA-AXUM-02: Html(format!(...)) reflected XSS ===
    echo ""
    echo "=== Checking for Reflected XSS via Html(format!) ==="
    HTML_XSS=$(scan_rs '\bHtml\s*\(\s*format!\s*\(')
    if [[ -n "$HTML_XSS" ]]; then
        echo "ERROR: Html(format!(...)) found — render through askama/maud or escape input:"
        echo "$HTML_XSS"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: No Html(format!) patterns detected"
    fi

    # === SA-AXUM-04: command injection from extractor values ===
    echo ""
    echo "=== Checking for Command Injection from Extractors ==="
    CMD_INJ=$(scan_rs '\.arg\s*\(\s*"-l?c"\s*\)\s*\.arg\s*\(\s*&?format!\s*\(\s*"[^"]* [^"]*\{|Command::new\s*\(\s*&?(params|query|body|payload|form|req)\.')
    # grep is line-based: also catch builder chains split across lines
    # (files that spawn a shell AND feed it a format!-built argument)
    CMD_INJ_FILES=""
    for dir in "${SCAN_DIRS[@]}"; do
        while IFS= read -r f; do
            if grep -q -E '\.arg\s*\(\s*&?format!\s*\(\s*"[^"]* [^"]*\{' "$f" 2>/dev/null; then
                CMD_INJ_FILES+="$f"$'\n'
            fi
        done < <(grep -rl -E 'Command::new\s*\(\s*"(sh|bash|zsh|cmd|powershell)"' "$dir" --include="*.rs" --exclude-dir=target --exclude-dir=.git 2>/dev/null || true)
    done
    CMD_INJ_FILES=$(echo "$CMD_INJ_FILES" | grep -v '^$' || true)
    if [[ -n "$CMD_INJ" || -n "$CMD_INJ_FILES" ]]; then
        echo "ERROR: Shell command assembled from request values — pass fixed argv entries, no sh -c:"
        [[ -n "$CMD_INJ" ]] && echo "$CMD_INJ"
        [[ -n "$CMD_INJ_FILES" ]] && echo "$CMD_INJ_FILES" | head -5
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: No extractor-fed command patterns detected"
    fi

    # === SA-AXUM-05: fs reads on format!-built paths ===
    echo ""
    echo "=== Checking for Filesystem Path Traversal ==="
    FS_TRAV=$(scan_rs 'fs::read(_to_string)?\s*\(\s*&?\s*format!\s*\(\s*"[^"]*/\{|\bFile::open\s*\(\s*&?\s*format!\s*\(\s*"[^"]*/\{')
    if [[ -n "$FS_TRAV" ]]; then
        echo "ERROR: fs read on format!-built path — reject separators and canonicalize under a root:"
        echo "$FS_TRAV"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: No format!-built filesystem reads detected"
    fi
fi

# === Output results for dispatcher ===
echo ""
echo "--- Rust Web Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

# Exit with error count for dispatcher to aggregate
exit "$ERRORS"

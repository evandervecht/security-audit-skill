#!/bin/bash
# Elixir / Phoenix Security Scanner Module
# Scans Elixir & Phoenix projects for common vulnerability patterns
# Part of security-audit-skill modular scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Elixir source directories
SCAN_DIRS=()
for dir in lib config test priv; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
# Fall back to project root if no conventional dirs exist
if [[ ${#SCAN_DIRS[@]} -eq 0 ]] && [[ -d "$PROJECT_DIR" ]]; then
    SCAN_DIRS+=("$PROJECT_DIR")
fi

# Helper: grep across all Elixir source directories
scan_ex() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E "$pattern" "$dir" --include="*.ex" --include="*.exs" --include="*.heex" --include="*.eex" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all Elixir source directories
scan_ex_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E "$pattern" "$dir" --include="*.ex" --include="*.exs" --include="*.heex" --include="*.eex" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Elixir / Phoenix Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No Elixir source directories found (looked for lib/, config/, test/, priv/)"
    exit 0
fi
echo "Scanning directories: ${SCAN_DIRS[*]}"
echo ""

# SA-EX-01: String.to_atom / binary_to_atom on user input (atom exhaustion DoS)
count=$(scan_ex_count 'String\.to_atom\s*\(|:erlang\.binary_to_atom\s*\(|List\.to_atom\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-EX-01: Found $count to_atom call(s) — atom table exhaustion DoS; use String.to_existing_atom"
    scan_ex 'String\.to_atom\s*\(|:erlang\.binary_to_atom\s*\(|List\.to_atom\s*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-EX-02: Code.eval_string / Code.eval_quoted / EEx.eval_string code execution
count=$(scan_ex_count 'Code\.eval_string\s*\(|Code\.eval_quoted\s*\(|EEx\.eval_string\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-EX-02: Found $count eval call(s) — arbitrary Elixir code execution"
    scan_ex 'Code\.eval_string\s*\(|Code\.eval_quoted\s*\(|EEx\.eval_string\s*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-EX-03: System.cmd / :os.cmd with interpolated user input (command injection)
count=$(scan_ex_count '(System\.cmd|:os\.cmd)\s*\([^)]*#\{')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-EX-03: Found $count command call(s) with interpolation — OS command injection; pass args as a list"
    scan_ex '(System\.cmd|:os\.cmd)\s*\([^)]*#\{'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-EX-04: secrets passed to Logger / inspect (sensitive data disclosure)
count=$(scan_ex_count -i 'Logger\.[a-z_]+\([^)]*(password|secret|token|api[_-]?key|private[_-]?key|credential)[^)]*inspect|inspect\([^)]*(password|secret_key|api_key|private_key|credential)')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-EX-04: Found $count secret(s) passed to Logger/inspect — sensitive data disclosure in logs"
    scan_ex -i 'Logger\.[a-z_]+\([^)]*(password|secret|token|api[_-]?key|private[_-]?key|credential)[^)]*inspect|inspect\([^)]*(password|secret_key|api_key|private_key|credential)'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-PHOENIX-01: Ecto fragment/where with string interpolation (SQL injection)
count=$(scan_ex_count 'fragment\(\s*"[^"]*#\{|where:\s*"[^"]*#\{')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-PHOENIX-01: Found $count Ecto query/fragment(s) with interpolation — SQL injection; use ? placeholders and ^pins"
    scan_ex 'fragment\(\s*"[^"]*#\{|where:\s*"[^"]*#\{'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-PHOENIX-02: raw() in HEEx/~H templates (XSS)
count=$(scan_ex_count '<%=\s*raw\s*\(|\{\{\s*raw\s*\(|Phoenix\.HTML\.raw\s*\(')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-PHOENIX-02: Found $count raw() call(s) in templates — bypasses auto-escaping, XSS risk"
    scan_ex '<%=\s*raw\s*\(|\{\{\s*raw\s*\(|Phoenix\.HTML\.raw\s*\('
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-PHOENIX-03: CSRF protection disabled in router pipeline / form helper
count=$(scan_ex_count '#\s*plug\s+:protect_from_forgery|csrf_token:\s*false|with_csrf_token:\s*false')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-PHOENIX-03: Found $count disabled CSRF protection — cross-site request forgery risk"
    scan_ex '#\s*plug\s+:protect_from_forgery|csrf_token:\s*false|with_csrf_token:\s*false'
    ERRORS=$((ERRORS + count))
    echo ""
fi

echo "--- Elixir / Phoenix Security Scanner Summary ---"
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo "Total:    $((ERRORS + WARNINGS))"

exit $ERRORS

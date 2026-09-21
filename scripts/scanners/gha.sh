#!/bin/bash
# GitHub Actions Workflow Security Scanner Module
# Scans .github/workflows/*.yml and composite actions for pwn requests, expression
# injection, unpinned actions, over-broad tokens and other CI supply-chain risks.
# Part of security-audit-skill modular scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

WORKFLOW_DIR="$PROJECT_DIR/.github"

echo "--- GitHub Actions Security Scanner ---"
if [[ ! -d "$WORKFLOW_DIR" ]]; then
    echo "No .github/ directory found"
    exit 0
fi

# All workflow + composite action YAML files
mapfile -t FILES < <(find "$WORKFLOW_DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)
if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "No workflow YAML files found under .github/"
    exit 0
fi
echo "Scanning ${#FILES[@]} file(s) under $WORKFLOW_DIR"
echo ""

# report ID SEVERITY PATTERN MESSAGE
# Multi-line aware: grep -Pz treats the whole file as one record, so patterns may span lines.
report() {
    local id="$1" severity="$2" pattern="$3" message="$4"
    local hits=()
    for f in "${FILES[@]}"; do
        if grep -Pzq -- "$pattern" "$f" 2>/dev/null; then
            hits+=("$f")
        fi
    done
    local count=${#hits[@]}
    [[ $count -eq 0 ]] && return 0
    echo "[$severity] $id: $message ($count file(s))"
    printf '  %s\n' "${hits[@]:0:5}"
    echo ""
    if [[ "$severity" == "ERROR" ]]; then
        ERRORS=$((ERRORS + count))
    else
        WARNINGS=$((WARNINGS + count))
    fi
}

# SA-GHA-01: pull_request_target + checkout of PR head (pwn request)
report SA-GHA-01 ERROR \
    'pull_request_target[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}' \
    'pull_request_target checks out untrusted PR head — fork code runs with write token/secrets'

# SA-GHA-02: untrusted github.event context interpolated into run:/script:
report SA-GHA-02 ERROR \
    '(run|script):(?:[^\n]|\n(?![ \t]*(?:-\s|env:|with:|if:|id:|name:|uses:|shell:)))*?\$\{\{\s*github\.(head_ref|event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label)|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.(?:name|email))|commits\[[^\]]*\]\.(?:message|author\.(?:name|email))|inputs\.\w+))\s*\}\}' \
    'Untrusted github.event context inside run:/script: — expression injection; pass via env: instead'

# SA-GHA-03: third-party action not pinned to a commit SHA
report SA-GHA-03 WARNING \
    'uses:\s*(?!actions/|github/|\./|docker://)[\w.-]+/[\w./-]+@(?![0-9a-f]{40}\b)\S+' \
    'Third-party action pinned to mutable tag/branch — pin to full commit SHA'

# SA-GHA-04: permissions: write-all
report SA-GHA-04 ERROR \
    'permissions:\s*write-all' \
    'GITHUB_TOKEN granted write-all — scope permissions per job'

# SA-GHA-05: toJSON(secrets)
report SA-GHA-05 ERROR \
    'toJ[Ss][Oo][Nn]\(\s*secrets\s*\)' \
    'toJSON(secrets) dumps every repository secret'

# SA-GHA-06: ACTIONS_ALLOW_UNSECURE_COMMANDS
report SA-GHA-06 ERROR \
    'ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*['"'"'"]?true' \
    'Deprecated set-env/add-path re-enabled (CVE-2020-15228)'

# SA-GHA-07: self-hosted runner on pull_request trigger
report SA-GHA-07 WARNING \
    'pull_request[\s\S]*?runs-on:[\s\S]{0,80}?self-hosted' \
    'Self-hosted runner on pull_request workflow — fork PRs can run code on your infra'

# SA-GHA-08: curl | sh
report SA-GHA-08 WARNING \
    '(curl|wget)\s[^\n|]*\|\s*(sudo\s+(-E\s+)?)?(ba|z)?sh\b' \
    'Remote script piped into shell — download, verify, then execute'

echo "--- GitHub Actions Security Scanner Summary ---"
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo "Total:    $((ERRORS + WARNINGS))"

exit $ERRORS

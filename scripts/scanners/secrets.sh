#!/bin/bash
# Secrets Scanner Module
# Scans projects for leaked secrets using TruffleHog and fallback regex patterns.
#
# Checks for: API keys, tokens, passwords, private keys, cloud credentials,
# database connection strings, and other sensitive values in source code and git history.

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

echo "--- Secrets Scanner ---"
echo "Scanning: $PROJECT_DIR"
echo ""

# === TruffleHog (if available) ===
if command -v trufflehog &>/dev/null; then
    echo "=== TruffleHog Filesystem Scan ==="
    TRUFFLEHOG_OUTPUT=$(trufflehog filesystem "$PROJECT_DIR" --no-update --json 2>/dev/null || true)
    TRUFFLEHOG_COUNT=$(echo "$TRUFFLEHOG_OUTPUT" | grep -c '"SourceMetadata"' 2>/dev/null || true)

    if [[ "$TRUFFLEHOG_COUNT" -gt 0 ]]; then
        echo "ERROR: TruffleHog found $TRUFFLEHOG_COUNT secret(s):"
        echo "$TRUFFLEHOG_OUTPUT" | head -20
        ERRORS=$((ERRORS + TRUFFLEHOG_COUNT))
    else
        echo "OK: TruffleHog found no secrets"
    fi

    # Also scan git history if it's a git repo
    if [[ -d "$PROJECT_DIR/.git" ]]; then
        echo ""
        echo "=== TruffleHog Git History Scan ==="
        GIT_OUTPUT=$(trufflehog git "file://$PROJECT_DIR" --no-update --json 2>/dev/null || true)
        GIT_COUNT=$(echo "$GIT_OUTPUT" | grep -c '"SourceMetadata"' 2>/dev/null || true)

        if [[ "$GIT_COUNT" -gt 0 ]]; then
            echo "ERROR: TruffleHog found $GIT_COUNT secret(s) in git history:"
            echo "$GIT_OUTPUT" | head -20
            ERRORS=$((ERRORS + GIT_COUNT))
        else
            echo "OK: No secrets in git history"
        fi
    fi
else
    echo "TruffleHog not installed — falling back to regex patterns"
    echo "  Install: https://github.com/trufflesecurity/trufflehog#installation"
    echo ""
fi

# === Fallback regex patterns (always run as defense-in-depth) ===
echo ""
echo "=== Regex-Based Secret Detection ==="

# Patterns to search for
declare -A SECRET_PATTERNS
SECRET_PATTERNS=(
    ["AWS Access Key"]='(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}'
    ["AWS Secret Key"]='[Aa][Ww][Ss].{0,30}['\''"][0-9a-zA-Z/+]{40}['\''"]'
    ["GitHub Token"]='gh[pousr]_[A-Za-z0-9_]{36,}'
    ["GitHub Fine-Grained PAT"]='github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}'
    ["GitLab Token"]='glpat-[A-Za-z0-9\-_]{20,}'
    ["Slack Token"]='xox[baprs]-[0-9a-zA-Z\-]{10,}'
    ["Slack Webhook"]='hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}'
    ["Private Key"]='-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    ["Generic API Key"]='[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*['\''"][0-9a-zA-Z]{16,}['\''"]'
    ["Generic Secret"]='[sS][eE][cC][rR][eE][tT]\s*[:=]\s*['\''"][0-9a-zA-Z]{16,}['\''"]'
    ["Generic Password"]='[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*['\''"][^'\''\"]{8,}['\''"]'
    ["JWT Token"]='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    ["Stripe Key"]='[sr]k_(live|test)_[0-9a-zA-Z]{24,}'
    ["SendGrid Key"]='SG\.[0-9a-zA-Z\-_]{22,}\.[0-9a-zA-Z\-_]{43,}'
    ["Twilio Key"]='SK[0-9a-fA-F]{32}'
    ["Database URL"]='(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+'
    ["Heroku API Key"]='[Hh][Ee][Rr][Oo][Kk][Uu].{0,30}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    ["Google API Key"]='AIza[0-9A-Za-z\-_]{35}'
    ["Google OAuth Refresh Token"]='1//0[A-Za-z0-9_-]{30,}'
    ["Firebase Key"]='AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'
    ["Anthropic API Key"]='sk-ant-[A-Za-z0-9]{3,8}-[A-Za-z0-9_-]{40,}'
    ["OpenAI API Key"]='sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{48}\b'
    ["xAI API Key"]='xai-[A-Za-z0-9]{60,}'
    ["Groq API Key"]='gsk_[A-Za-z0-9]{50,}'
    ["Perplexity API Key"]='pplx-[a-f0-9]{48}'
    ["Replicate Token"]='r8_[A-Za-z0-9]{37}'
    ["Hugging Face Token"]='hf_[A-Za-z0-9]{34,}'
    ["npm Token"]='npm_[A-Za-z0-9]{36}'
    ["PyPI Token"]='pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}'
    ["Docker Hub PAT"]='dckr_pat_[A-Za-z0-9_-]{27,}'
    ["Stripe Webhook Secret"]='whsec_[A-Za-z0-9]{32,}'
    ["Slack App Token"]='xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{60,}'
    ["Discord Webhook"]='discord(app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}'
    ["Telegram Bot Token"]='[0-9]{8,10}:AA[A-Za-z0-9_-]{33}'
    ["Grafana Token"]='gl(c|sa)_[A-Za-z0-9+/=_]{32,}'
    ["Supabase Token"]='sbp_[a-f0-9]{40}'
    ["Doppler Token"]='dp\.(st|pt|sa|ct)\.[A-Za-z0-9_-]{40,}'
    ["Databricks Token"]='dapi[a-f0-9]{32}(-[0-9])?'
    ["Postman API Key"]='PMAK-[a-f0-9]{24}-[a-f0-9]{34}'
    ["Shopify Token"]='shp(at|ca|pa|ss)_[a-fA-F0-9]{32}'
    ["HashiCorp Vault Token"]='hvs\.[A-Za-z0-9_-]{24,}'
    ["Terraform Cloud Token"]='[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}'
    ["DigitalOcean Token"]='do[opr]_v1_[a-f0-9]{64}'
    ["Netlify Token"]='nfp_[A-Za-z0-9_-]{40,}'
    ["Linear API Key"]='lin_api_[A-Za-z0-9]{40}'
    ["Notion Token"]='(ntn|secret)_[A-Za-z0-9]{40,}'
    ["Sentry Token"]='sntrys_[A-Za-z0-9+/=]{40,}'
    ["New Relic Key"]='NRAK-[A-Z0-9]{27}'
    ["Figma Token"]='figd_[A-Za-z0-9_-]{40}'
    ["Atlassian API Token"]='ATATT3[A-Za-z0-9_=-]{180,}'
    ["Mailgun API Key"]='key-[0-9a-zA-Z]{32}\b'
    ["Mailchimp API Key"]='[0-9a-f]{32}-us[0-9]{1,2}\b'
    ["Square Token"]='sq0(atp|csp)-[A-Za-z0-9_-]{22,}'
    ["Azure Storage Key"]='AccountKey=[A-Za-z0-9+/=]{88}'
    ["age Secret Key"]='AGE-SECRET-KEY-1[A-Z0-9]{58}'
)

# Directories and files to skip
EXCLUDE_DIRS="node_modules|vendor|dist|build|\.git|target|\.next|coverage|__pycache__|\.cargo|\.nuget"
EXCLUDE_FILES="\.(lock|sum|min\.js|min\.css|map|woff|woff2|ttf|eot|png|jpg|jpeg|gif|ico|svg|pdf)$"

# Allowlist: drop well-known documentation/placeholder secrets (reduce false positives).
# AWS docs example key, common placeholder tokens, and clearly-fake test values are not real leaks.
SECRET_ALLOWLIST='AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY|EXAMPLE|PLACEHOLDER|YOUR[_-]?(API[_-]?)?KEY([_-]?HERE)?|CHANGE[_-]?ME|DUMMY|FAKE|TEST[_-]?(KEY|SECRET|TOKEN)|xxxxxxxx|0{8,}|<[^>]+>'

for name in "${!SECRET_PATTERNS[@]}"; do
    pattern="${SECRET_PATTERNS[$name]}"
    MATCHES=$(grep -rn -E -e "$pattern" "$PROJECT_DIR" \
        --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" --include="*.py" \
        --include="*.java" --include="*.cs" --include="*.go" --include="*.rs" --include="*.rb" \
        --include="*.php" --include="*.yaml" --include="*.yml" --include="*.json" --include="*.xml" \
        --include="*.env" --include="*.cfg" --include="*.conf" --include="*.ini" --include="*.toml" \
        --include="*.properties" --include="*.sh" --include="*.bash" --include="*.zsh" \
        2>/dev/null | grep -vE "$EXCLUDE_DIRS" | grep -vE "$EXCLUDE_FILES" | grep -vE "\.(example|sample|template)" | grep -viE "$SECRET_ALLOWLIST" | head -5 || true)

    if [[ -n "$MATCHES" ]]; then
        echo "WARNING: Potential $name found:"
        echo "$MATCHES" | head -3
        WARNINGS=$((WARNINGS + 1))
    fi
done

# === Check for .env files in repo ===
echo ""
echo "=== Environment Files ==="
ENV_FILES=$(find "$PROJECT_DIR" -maxdepth 3 -name ".env" -o -name ".env.local" -o -name ".env.production" 2>/dev/null | grep -vE "$EXCLUDE_DIRS" || true)
if [[ -n "$ENV_FILES" ]]; then
    echo "WARNING: Environment files found (should not be in VCS):"
    echo "$ENV_FILES"
    WARNINGS=$((WARNINGS + 1))
fi

# === Check .gitignore for env exclusion ===
if [[ -f "$PROJECT_DIR/.gitignore" ]]; then
    if ! grep -q "\.env" "$PROJECT_DIR/.gitignore" 2>/dev/null; then
        echo "WARNING: .gitignore does not exclude .env files"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

# === Summary ===
echo ""
echo "--- Secrets Scanner Results ---"
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"

exit "$ERRORS"

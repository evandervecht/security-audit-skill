#!/bin/bash
# Kubernetes Security Scanner Module
# Scans Kubernetes manifests (and Helm chart templates) for common misconfigurations
# Part of security-audit-skill modular scanner architecture

set -e

PROJECT_DIR="${1:-.}"
ERRORS=0
WARNINGS=0

# Auto-detect Kubernetes manifest directories
SCAN_DIRS=()
for dir in k8s kubernetes deploy deployment manifests charts helm templates; do
    if [[ -d "$PROJECT_DIR/$dir" ]]; then
        SCAN_DIRS+=("$PROJECT_DIR/$dir")
    fi
done
# Fall back to project root if nothing matched
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    SCAN_DIRS+=("$PROJECT_DIR")
fi

# Helper: grep across all manifest directories
scan_kube() {
    local pattern="$1"
    local limit="${2:-5}"
    local results=""
    for dir in "${SCAN_DIRS[@]}"; do
        local matches
        matches=$(grep -rn -E -e "$pattern" "$dir" --include="*.yaml" --include="*.yml" 2>/dev/null || true)
        if [[ -n "$matches" ]]; then
            results+="$matches"$'\n'
        fi
    done
    echo "$results" | grep -v '^$' | head -"$limit"
}

# Helper: count matches across all manifest directories
scan_kube_count() {
    local pattern="$1"
    local total=0
    for dir in "${SCAN_DIRS[@]}"; do
        local count
        count=$(grep -rn -E -e "$pattern" "$dir" --include="*.yaml" --include="*.yml" 2>/dev/null | wc -l || echo "0")
        total=$((total + count))
    done
    echo "$total"
}

echo "--- Kubernetes Security Scanner ---"
if [[ ${#SCAN_DIRS[@]} -eq 0 ]]; then
    echo "No Kubernetes manifest directories found (looked for k8s/, kubernetes/, deploy/, manifests/, charts/)"
    exit 0
fi
echo "Scanning directories: ${SCAN_DIRS[*]}"
echo ""

# SA-KUBE-01: privileged container
count=$(scan_kube_count 'privileged:\s*true')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-KUBE-01: Found $count privileged container(s) — full host access / container escape"
    scan_kube 'privileged:\s*true'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-KUBE-02: hostPath volume
count=$(scan_kube_count 'hostPath:')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-KUBE-02: Found $count hostPath volume(s) — host filesystem exposure / container escape"
    scan_kube 'hostPath:'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-KUBE-03: allowPrivilegeEscalation: true
count=$(scan_kube_count 'allowPrivilegeEscalation:\s*true')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-KUBE-03: Found $count allowPrivilegeEscalation: true setting(s) — set it to false"
    scan_kube 'allowPrivilegeEscalation:\s*true'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-KUBE-04: running as root (runAsUser: 0)
count=$(scan_kube_count 'runAsUser:\s*0\b')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-KUBE-04: Found $count container(s) running as root (runAsUser: 0)"
    scan_kube 'runAsUser:\s*0\b'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-KUBE-05: host namespace sharing
count=$(scan_kube_count 'host(Network|PID|IPC):\s*true')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-KUBE-05: Found $count host namespace sharing setting(s) (hostNetwork/hostPID/hostIPC)"
    scan_kube 'host(Network|PID|IPC):\s*true'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-KUBE-06: dangerous Linux capabilities added
count=$(scan_kube_count '-\s*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)\b')
if [[ $count -gt 0 ]]; then
    echo "[ERROR] SA-KUBE-06: Found $count dangerous capability reference(s) (SYS_ADMIN/NET_ADMIN/SYS_PTRACE/ALL) — verify these are not added"
    scan_kube '-\s*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)\b'
    ERRORS=$((ERRORS + count))
    echo ""
fi

# SA-KUBE-07: image pinned to :latest
count=$(scan_kube_count 'image:\s*\S+:latest\b')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-KUBE-07: Found $count image(s) pinned to :latest — pin a version tag or digest"
    scan_kube 'image:\s*\S+:latest\b'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

# SA-KUBE-08: plaintext secret in env value
count=$(scan_kube_count 'name:\s*\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*')
if [[ $count -gt 0 ]]; then
    echo "[WARNING] SA-KUBE-08: Found $count secret-named env var(s) — verify they use valueFrom.secretKeyRef, not plaintext value"
    scan_kube 'name:\s*\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*'
    WARNINGS=$((WARNINGS + count))
    echo ""
fi

echo "--- Kubernetes Security Scanner Summary ---"
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo "Total:    $((ERRORS + WARNINGS))"

exit $ERRORS

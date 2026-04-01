#!/bin/bash
# Analyze strace output for suspicious behavior during package installation.
#
# Usage: analyze-strace.sh <strace-log> [--registry <host>]... [--monitor-auth <path>]
#
# Flags:
#   - Network connections to non-registry hosts
#   - DNS lookups for non-registry domains
#   - File writes outside the package directory
#   - Process spawning (fork/exec of unexpected binaries)
#   - Environment variable reads (secrets harvesting)
#   - Credential file access by install scripts (exfiltration detection)

set -e

# --- Parse arguments ---
STRACE_LOG=""
EXTRA_SAFE_HOSTS=""
AUTH_CREDENTIAL_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)
            # Escape dots for regex and append to safe hosts
            ESCAPED=$(echo "$2" | sed 's/\./\\./g')
            if [[ -n "$EXTRA_SAFE_HOSTS" ]]; then
                EXTRA_SAFE_HOSTS="${EXTRA_SAFE_HOSTS}|${ESCAPED}"
            else
                EXTRA_SAFE_HOSTS="$ESCAPED"
            fi
            shift 2
            ;;
        --monitor-auth)
            AUTH_CREDENTIAL_PATH="$2"
            shift 2
            ;;
        *)
            if [[ -z "$STRACE_LOG" ]]; then
                STRACE_LOG="$1"
            fi
            shift
            ;;
    esac
done

STRACE_LOG="${STRACE_LOG:-/dev/stdin}"
FINDINGS=0

echo "=== Dependency Sandbox Analysis ==="
echo ""

# --- Known safe registries (public) ---
SAFE_HOSTS="registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org|github\.com|objects\.githubusercontent\.com|proxy\.golang\.org|sum\.golang\.org|storage\.googleapis\.com|static\.crates\.io|crates\.io|index\.crates\.io|api\.nuget\.org|nuget\.org|static\.rust-lang\.org"

# Add private registries to safe list
if [[ -n "$EXTRA_SAFE_HOSTS" ]]; then
    SAFE_HOSTS="${SAFE_HOSTS}|${EXTRA_SAFE_HOSTS}"
    echo "Private registries allowlisted in analysis"
fi

# --- Network connections ---
echo "=== Network Connections ==="
NETWORK_CALLS=$(grep -E "connect\(" "$STRACE_LOG" 2>/dev/null | grep -v "127\.0\.0\.1\|::1\|ENOENT\|EINPROGRESS" || true)

SUSPICIOUS_NETWORK=$(echo "$NETWORK_CALLS" | grep -vE "$SAFE_HOSTS" | grep -E "sa_family=AF_INET" || true)
if [[ -n "$SUSPICIOUS_NETWORK" ]]; then
    echo "WARNING: Connections to non-registry hosts detected:"
    echo "$SUSPICIOUS_NETWORK" | head -10
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No suspicious network connections"
fi

# --- DNS lookups ---
echo ""
echo "=== DNS Lookups ==="
DNS_LOOKUPS=$(grep -E "getaddrinfo|gethostbyname" "$STRACE_LOG" 2>/dev/null || true)
SUSPICIOUS_DNS=$(echo "$DNS_LOOKUPS" | grep -vE "$SAFE_HOSTS|localhost" || true)
if [[ -n "$SUSPICIOUS_DNS" ]]; then
    echo "WARNING: DNS lookups for non-registry domains:"
    echo "$SUSPICIOUS_DNS" | head -10
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No suspicious DNS lookups"
fi

# --- File writes outside package dir ---
echo ""
echo "=== File System Writes ==="
FILE_WRITES=$(grep -E "openat\(.*O_WRONLY\|openat\(.*O_RDWR" "$STRACE_LOG" 2>/dev/null || true)
SAFE_PATHS="/sandbox/node_modules\|/sandbox/.local\|/tmp\|/sandbox/.npm\|/sandbox/.cache\|/sandbox/go\|/sandbox/.cargo\|/sandbox/.dotnet\|/sandbox/.nuget"
SUSPICIOUS_WRITES=$(echo "$FILE_WRITES" | grep -v "$SAFE_PATHS" | grep -v "ENOENT\|EACCES" || true)
if [[ -n "$SUSPICIOUS_WRITES" ]]; then
    echo "WARNING: File writes outside package directory:"
    echo "$SUSPICIOUS_WRITES" | head -10
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No suspicious file writes"
fi

# --- Process spawning ---
echo ""
echo "=== Process Spawning ==="
EXEC_CALLS=$(grep -E "execve\(" "$STRACE_LOG" 2>/dev/null || true)
SAFE_BINARIES="node\|npm\|python\|pip\|sh\|env\|strace\|git\|gcc\|g++\|make\|cc\|go\|cargo\|rustc\|dotnet\|nuget\|ld\|ar\|as\|rustup"
SUSPICIOUS_EXEC=$(echo "$EXEC_CALLS" | grep -vE "$SAFE_BINARIES" || true)
if [[ -n "$SUSPICIOUS_EXEC" ]]; then
    echo "WARNING: Unexpected process execution:"
    echo "$SUSPICIOUS_EXEC" | head -10
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No unexpected process spawning"
fi

# --- Environment variable reads ---
echo ""
echo "=== Environment Access ==="
SENSITIVE_VARS="AWS_SECRET\|GITHUB_TOKEN\|NPM_TOKEN\|API_KEY\|PASSWORD\|PRIVATE_KEY\|SECRET_KEY\|DATABASE_URL\|ARTIFACTORY\|REGISTRY_TOKEN\|NUGET_API_KEY\|CARGO_REGISTRY_TOKEN\|GONOSUMCHECK"
ENV_READS=$(grep -E "openat.*environ\|getenv" "$STRACE_LOG" 2>/dev/null || true)
SUSPICIOUS_ENV=$(echo "$ENV_READS" | grep -iE "$SENSITIVE_VARS" || true)
if [[ -n "$SUSPICIOUS_ENV" ]]; then
    echo "WARNING: Sensitive environment variable access detected:"
    echo "$SUSPICIOUS_ENV" | head -10
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No sensitive environment variable access"
fi

# --- Credential file exfiltration detection ---
if [[ -n "$AUTH_CREDENTIAL_PATH" ]]; then
    echo ""
    echo "=== Credential File Access (Exfiltration Detection) ==="

    # The auth file is expected to be read by the package manager itself (npm, pip, etc.)
    # But if an install SCRIPT (postinstall, setup.py, build.rs) reads it, that's suspicious.
    AUTH_READS=$(grep -E "openat.*${AUTH_CREDENTIAL_PATH}" "$STRACE_LOG" 2>/dev/null || true)

    if [[ -n "$AUTH_READS" ]]; then
        # Count distinct PIDs that accessed the file
        AUTH_PIDS=$(echo "$AUTH_READS" | grep -oE "^\[pid [0-9]+" | sort -u | wc -l)

        # If more than 2 PIDs accessed it (package manager + its child), flag it
        # The package manager itself reading credentials is expected
        # But install scripts reading credentials is exfiltration
        if [[ "$AUTH_PIDS" -gt 3 ]]; then
            echo "CRITICAL: Credential file accessed by multiple processes ($AUTH_PIDS PIDs):"
            echo "  This may indicate install scripts are reading your auth tokens."
            echo "$AUTH_READS" | head -10
            FINDINGS=$((FINDINGS + 1))
        else
            echo "OK: Credential file accessed only by package manager (expected)"
        fi

        # Check if credential file was read AND a network connection happened close in time
        # (heuristic: if strace shows read of auth file followed by connect())
        AUTH_THEN_NETWORK=$(echo "$AUTH_READS" | head -1 | grep -oE "^\[pid [0-9]+" || true)
        if [[ -n "$AUTH_THEN_NETWORK" ]]; then
            PID_NUM=$(echo "$AUTH_THEN_NETWORK" | grep -oE "[0-9]+")
            PID_NETWORK=$(grep -E "^\[pid $PID_NUM.*connect\(" "$STRACE_LOG" 2>/dev/null | grep -vE "$SAFE_HOSTS" || true)
            if [[ -n "$PID_NETWORK" ]]; then
                echo "CRITICAL: Process that read credentials also connected to non-registry host:"
                echo "$PID_NETWORK" | head -5
                FINDINGS=$((FINDINGS + 1))
            fi
        fi
    else
        echo "OK: Credential file was not accessed"
    fi
fi

# --- Summary ---
echo ""
echo "=== Summary ==="
echo "Findings: $FINDINGS"
if [[ $FINDINGS -gt 0 ]]; then
    echo "SUSPICIOUS: $FINDINGS suspicious behavior(s) detected during installation"
    exit 1
else
    echo "CLEAN: No suspicious behavior detected"
    exit 0
fi

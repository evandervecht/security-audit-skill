#!/bin/bash
# Analyze strace output for suspicious behavior during package installation.
# Reads strace log from stdin or file argument.
#
# Flags:
#   - Network connections to non-registry hosts
#   - DNS lookups for non-registry domains
#   - File writes outside the package directory
#   - Process spawning (fork/exec of unexpected binaries)
#   - Environment variable reads (secrets harvesting)

set -e

STRACE_LOG="${1:-/dev/stdin}"
FINDINGS=0

echo "=== Dependency Sandbox Analysis ==="
echo ""

# --- Network connections ---
echo "=== Network Connections ==="
# Look for connect() syscalls to non-loopback, non-registry addresses
NETWORK_CALLS=$(grep -E "connect\(" "$STRACE_LOG" 2>/dev/null | grep -v "127\.0\.0\.1\|::1\|ENOENT\|EINPROGRESS" || true)

# Known safe registries
SAFE_HOSTS="registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org|github\.com|objects\.githubusercontent\.com|proxy\.golang\.org|sum\.golang\.org|storage\.googleapis\.com|static\.crates\.io|crates\.io|index\.crates\.io|api\.nuget\.org|nuget\.org|static\.rust-lang\.org"

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
# Look for openat() with O_WRONLY or O_RDWR flags outside expected paths
FILE_WRITES=$(grep -E "openat\(.*O_WRONLY\|openat\(.*O_RDWR" "$STRACE_LOG" 2>/dev/null || true)
SAFE_PATHS="/sandbox/node_modules\|/sandbox/.local\|/tmp\|/sandbox/.npm\|/sandbox/.cache"
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
# Look for execve of unexpected binaries
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
# Look for reads of sensitive env vars
SENSITIVE_VARS="AWS_SECRET\|GITHUB_TOKEN\|NPM_TOKEN\|API_KEY\|PASSWORD\|PRIVATE_KEY\|SECRET_KEY\|DATABASE_URL"
ENV_READS=$(grep -E "openat.*environ\|getenv" "$STRACE_LOG" 2>/dev/null || true)
SUSPICIOUS_ENV=$(echo "$ENV_READS" | grep -iE "$SENSITIVE_VARS" || true)
if [[ -n "$SUSPICIOUS_ENV" ]]; then
    echo "WARNING: Sensitive environment variable access detected:"
    echo "$SUSPICIOUS_ENV" | head -10
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No sensitive environment variable access"
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

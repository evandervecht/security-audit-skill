#!/bin/bash
# Analyze strace output for suspicious behavior during package installation.
#
# Usage: analyze-strace.sh <strace-log> [--registry <host>]... [--monitor-auth <path>]
#
# Performance: pre-indexes the strace log into small files by syscall type,
# then uses those for all analysis. Handles 10MB+ logs efficiently.

set +e

# --- Parse arguments ---
STRACE_LOG=""
EXTRA_SAFE_HOSTS=""
AUTH_CREDENTIAL_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)
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

# --- Temp directory for all working files ---
IDX=$(mktemp -d)
trap 'rm -rf "$IDX"' EXIT

# ============================================================
# PHASE 1: Single-pass index of the strace log
# Split into small files by syscall type — all further analysis
# uses these instead of re-reading the full log.
# ============================================================
echo "Indexing strace log ($(wc -c < "$STRACE_LOG" | tr -d ' ') bytes)..."

# Split log into indexed files by syscall type (parallel grep, one read each)
grep -E "execve\("             "$STRACE_LOG" > "$IDX/execve.log"        2>/dev/null &
grep -E "clone"                "$STRACE_LOG" > "$IDX/clone.log"         2>/dev/null &
grep -E "connect\("            "$STRACE_LOG" > "$IDX/connect.log"       2>/dev/null &
grep -E "openat\(.*O_WRONLY|openat\(.*O_RDWR" "$STRACE_LOG" > "$IDX/openat_write.log" 2>/dev/null &
grep -E "openat.*node_modules/" "$STRACE_LOG" > "$IDX/openat_nodemod.log" 2>/dev/null &
grep -E "openat.*site-packages/" "$STRACE_LOG" > "$IDX/openat_sitepack.log" 2>/dev/null &
grep -E "openat.*environ|getenv" "$STRACE_LOG" > "$IDX/environ.log"    2>/dev/null &
wait

# Touch all files so later reads don't fail on empty results
for f in execve clone connect openat_write openat_nodemod openat_sitepack environ; do
    touch "$IDX/$f.log"
done

# ============================================================
# PHASE 2: Build PID attribution from indexed files
# ============================================================

# PID → package (from execve paths)
# PID → command name (from execve first arg)
# child → parent (from clone calls)
touch "$IDX/pid_pkg" "$IDX/pid_cmd" "$IDX/pid_parent" "$IDX/pid_cache"

# Parse execve for package attribution and command names
while IFS= read -r line; do
    pid=${line%%[^0-9]*}
    [[ -z "$pid" ]] && continue

    # Extract package from path
    pkg=""
    case "$line" in
        *node_modules/*)
            pkg=$(echo "$line" | sed -n 's|.*node_modules/\(@[^/"]*\/[^/"]*\|[^/"]*\).*|\1|p' | head -1) ;;
        *site-packages/*)
            pkg=$(echo "$line" | sed -n 's|.*site-packages/\([^/"]*\).*|\1|p' | head -1) ;;
        *registry/src/*)
            pkg=$(echo "$line" | sed -n 's|.*registry/src/[^/]*/\([^/"]*\)-[0-9].*|\1|p' | head -1) ;;
    esac
    [[ -n "$pkg" ]] && echo "$pid $pkg" >> "$IDX/pid_pkg"

    # Command name from first quoted arg
    cmd=$(echo "$line" | sed -n 's|.*execve("\([^"]*\)".*|\1|p' | sed 's|.*/||')
    [[ -n "$cmd" ]] && echo "$pid $cmd" >> "$IDX/pid_cmd"
done < "$IDX/execve.log"

# Parse clone for parent→child
while IFS= read -r line; do
    parent=${line%%[^0-9]*}
    child=$(echo "$line" | grep -oE '= [0-9]+$' | grep -oE '[0-9]+')
    [[ -n "$parent" && -n "$child" ]] && echo "$child $parent" >> "$IDX/pid_parent"
done < "$IDX/clone.log"

# --- resolve_pid: cached PID→package lookup ---
resolve_pid() {
    local pid="$1"
    # Check cache first
    local cached
    cached=$(grep -m1 "^${pid} " "$IDX/pid_cache" 2>/dev/null | cut -d' ' -f2-)
    if [[ -n "$cached" ]]; then
        echo "$cached"
        return
    fi

    local current="$pid" depth=0 result=""

    # Walk parent chain looking for package attribution
    while [[ $depth -lt 10 ]]; do
        local pkg
        pkg=$(grep -m1 "^${current} " "$IDX/pid_pkg" 2>/dev/null | cut -d' ' -f2-)
        if [[ -n "$pkg" ]]; then
            result="$pkg"
            break
        fi
        local parent
        parent=$(grep -m1 "^${current} " "$IDX/pid_parent" 2>/dev/null | cut -d' ' -f2)
        [[ -z "$parent" || "$parent" == "$current" ]] && break
        current="$parent"
        depth=$((depth + 1))
    done

    # Fallback: check indexed openat for node_modules paths (fast — small file)
    if [[ -z "$result" ]]; then
        result=$(grep -m5 "^${pid}" "$IDX/openat_nodemod.log" 2>/dev/null | \
            grep -oE 'node_modules/(@[^/"]+/[^/"]+|[^/"]+)' | \
            sed 's|node_modules/||' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
    fi

    # Fallback: command name
    if [[ -z "$result" ]]; then
        local cmd
        cmd=$(grep -m1 "^${pid} " "$IDX/pid_cmd" 2>/dev/null | cut -d' ' -f2-)
        [[ -z "$cmd" ]] && cmd=$(grep -m1 "^${current} " "$IDX/pid_cmd" 2>/dev/null | cut -d' ' -f2-)
        result="${cmd:+[$cmd]}"
    fi

    result="${result:-[unknown:PID $pid]}"
    echo "$pid $result" >> "$IDX/pid_cache"
    echo "$result"
}

# --- Print findings grouped by package ---
print_grouped_findings() {
    local suspicious_lines="$1"
    local category="$2"
    [[ -z "$suspicious_lines" ]] && return

    local group_dir="$IDX/groups_$$_$RANDOM"
    mkdir -p "$group_dir"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local pid=${line%%[^0-9]*}
        [[ -z "$pid" ]] && continue
        local pkg
        pkg=$(resolve_pid "$pid")
        local safename
        safename=$(echo "$pkg" | tr '/@:[] ' '______')
        echo "$pkg" > "$group_dir/${safename}.name"
        echo "$line" >> "$group_dir/${safename}.lines"
    done <<< "$suspicious_lines"

    for pass in other manager; do
        for namefile in "$group_dir"/*.name; do
            [[ -f "$namefile" ]] || continue
            local pkg
            pkg=$(cat "$namefile")
            local linesfile="${namefile%.name}.lines"
            local count
            count=$(wc -l < "$linesfile" | tr -d ' ')
            local is_manager=false
            [[ "$pkg" == \[* ]] && is_manager=true

            [[ "$pass" == "other" && "$is_manager" == true ]] && continue
            [[ "$pass" == "manager" && "$is_manager" == false ]] && continue

            local max_show=5
            [[ "$is_manager" == true ]] && max_show=3

            echo "  $pkg ($count $category):"
            head -"$max_show" "$linesfile" | sed 's/^/    /'
            [[ "$count" -gt "$max_show" ]] && echo "    ... and $(( count - max_show )) more"
            echo ""
        done
    done
    rm -rf "$group_dir"
}

# --- Extract unique public IPs ---
extract_ips() {
    local lines="$1"
    local outfile="$2"
    [[ -z "$lines" ]] && return
    echo "$lines" | grep -oE 'inet_addr\("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"\)' | \
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | while IFS= read -r ip; do
        case "$ip" in
            10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|127.*|169.254.*|0.*) continue ;;
        esac
        echo "$ip"
    done > "$outfile" 2>/dev/null || true
}

# ============================================================
# PHASE 3: Analysis (uses indexed files only)
# ============================================================

echo "=== Dependency Sandbox Analysis ==="
echo ""

SAFE_HOSTS="registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org|github\.com|objects\.githubusercontent\.com|proxy\.golang\.org|sum\.golang\.org|storage\.googleapis\.com|static\.crates\.io|crates\.io|index\.crates\.io|api\.nuget\.org|nuget\.org|static\.rust-lang\.org"

if [[ -n "$EXTRA_SAFE_HOSTS" ]]; then
    SAFE_HOSTS="${SAFE_HOSTS}|${EXTRA_SAFE_HOSTS}"
    echo "Private registries allowlisted in analysis"
fi

# --- Network connections (from indexed connect.log) ---
echo "=== Network Connections ==="
NETWORK_CALLS=$(grep -vE "127\.0\.0\.1|::1|ENOENT|EINPROGRESS" "$IDX/connect.log" 2>/dev/null || true)

# Build safe IP set: DNS resolvers + all IPs used only by package manager PIDs
SAFE_IPS_FILE="$IDX/safe_ips"
touch "$SAFE_IPS_FILE"

ALL_IPS=$(echo "$NETWORK_CALLS" | grep -oE 'inet_addr\("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"\)' | \
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u)

# DNS resolver IPs are safe
echo "$NETWORK_CALLS" | grep "htons(53)" | \
    grep -oE 'inet_addr\("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"\)' | \
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u >> "$SAFE_IPS_FILE"

# Check each IP — if only package manager PIDs connect, it's safe
for ip in $ALL_IPS; do
    case "$ip" in
        10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*|169.254.*|0.*)
            echo "$ip" >> "$SAFE_IPS_FILE"; continue ;;
    esac
    CONNECTING_PIDS=$(echo "$NETWORK_CALLS" | grep "$ip" | grep -oE "^[0-9]+" | sort -u)
    ALL_PKG_MGR=true
    for pid in $CONNECTING_PIDS; do
        pkg=$(resolve_pid "$pid" 2>/dev/null)
        case "$pkg" in
            *pnpm*|*npm*|*node*|*pip*|*uv*|*python*|*cargo*|*go*|*dotnet*|\[*) ;;
            *) ALL_PKG_MGR=false; break ;;
        esac
    done
    $ALL_PKG_MGR && echo "$ip" >> "$SAFE_IPS_FILE"
done

SAFE_IP_PATTERN=$(sort -u "$SAFE_IPS_FILE" | sed 's/\./\\./g' | tr '\n' '|' | sed 's/|$//')

SUSPICIOUS_NETWORK=""
if [[ -n "$SAFE_IP_PATTERN" ]]; then
    SUSPICIOUS_NETWORK=$(echo "$NETWORK_CALLS" | grep -E "sa_family=AF_INET" | grep -vE "$SAFE_IP_PATTERN" || true)
else
    SUSPICIOUS_NETWORK=$(echo "$NETWORK_CALLS" | grep -vE "$SAFE_HOSTS" | grep -E "sa_family=AF_INET" || true)
fi

extract_ips "$NETWORK_CALLS" "$(dirname "$STRACE_LOG")/ips.txt"

if [[ -n "$SUSPICIOUS_NETWORK" ]]; then
    echo "WARNING: Connections to non-registry hosts detected:"
    print_grouped_findings "$SUSPICIOUS_NETWORK" "connections"
    extract_ips "$SUSPICIOUS_NETWORK" "$(dirname "$STRACE_LOG")/suspicious_ips.txt"
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No suspicious network connections (all traffic attributed to package manager)"
    TOTAL_IPS=$(wc -l < "$(dirname "$STRACE_LOG")/ips.txt" 2>/dev/null | tr -d ' ')
    echo "  ($TOTAL_IPS unique public IPs contacted — see ips.txt for reverse DNS)"
fi

# --- DNS lookups ---
echo ""
echo "=== DNS Lookups ==="
DNS_LOOKUPS=$(grep -E "getaddrinfo|gethostbyname" "$IDX/connect.log" 2>/dev/null || true)
SUSPICIOUS_DNS=$(echo "$DNS_LOOKUPS" | grep -vE "$SAFE_HOSTS|localhost" || true)
if [[ -n "$SUSPICIOUS_DNS" ]]; then
    echo "WARNING: DNS lookups for non-registry domains:"
    print_grouped_findings "$SUSPICIOUS_DNS" "lookups"
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No suspicious DNS lookups"
fi

# --- File writes outside sandbox (from indexed openat_write.log) ---
echo ""
echo "=== File System Writes ==="
SAFE_PATHS="/sandbox/|/tmp/|/dev/tty|/dev/null|/strace/|/usr/local/lib/|\"\./"
SUSPICIOUS_WRITES=$(grep -vE "$SAFE_PATHS" "$IDX/openat_write.log" 2>/dev/null | grep -vE "ENOENT|EACCES|EROFS" || true)
if [[ -n "$SUSPICIOUS_WRITES" ]]; then
    echo "WARNING: File writes outside package directory:"
    print_grouped_findings "$SUSPICIOUS_WRITES" "writes"
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No suspicious file writes"
fi

# --- Process spawning (from indexed execve.log) ---
echo ""
echo "=== Process Spawning ==="
SAFE_BINARIES="node|npm|pnpm|python|pip|uv|sh|bash|env|strace|git|gcc|g[+][+]|make|cc|go|cargo|rustc|dotnet|nuget|ld|ar|as|rustup"
SUSPICIOUS_EXEC=$(grep -vE "$SAFE_BINARIES" "$IDX/execve.log" 2>/dev/null || true)
if [[ -n "$SUSPICIOUS_EXEC" ]]; then
    echo "WARNING: Unexpected process execution:"
    print_grouped_findings "$SUSPICIOUS_EXEC" "executions"
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No unexpected process spawning"
fi

# --- Environment variable reads (from indexed environ.log) ---
echo ""
echo "=== Environment Access ==="
SENSITIVE_VARS="AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|API_KEY|PASSWORD|PRIVATE_KEY|SECRET_KEY|DATABASE_URL|ARTIFACTORY|REGISTRY_TOKEN|NUGET_API_KEY|CARGO_REGISTRY_TOKEN|GONOSUMCHECK"
SUSPICIOUS_ENV=$(grep -iE "$SENSITIVE_VARS" "$IDX/environ.log" 2>/dev/null || true)
if [[ -n "$SUSPICIOUS_ENV" ]]; then
    echo "WARNING: Sensitive environment variable access detected:"
    print_grouped_findings "$SUSPICIOUS_ENV" "env reads"
    FINDINGS=$((FINDINGS + 1))
else
    echo "OK: No sensitive environment variable access"
fi

# --- Credential file exfiltration ---
if [[ -n "$AUTH_CREDENTIAL_PATH" ]]; then
    echo ""
    echo "=== Credential File Access (Exfiltration Detection) ==="
    AUTH_READS=$(grep -E "$AUTH_CREDENTIAL_PATH" "$IDX/openat_write.log" "$IDX/openat_nodemod.log" 2>/dev/null || true)

    if [[ -n "$AUTH_READS" ]]; then
        AUTH_PIDS=$(echo "$AUTH_READS" | grep -oE "^[0-9]+" | sort -u | wc -l)
        if [[ "$AUTH_PIDS" -gt 3 ]]; then
            echo "CRITICAL: Credential file accessed by multiple processes ($AUTH_PIDS PIDs):"
            print_grouped_findings "$AUTH_READS" "credential reads"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "OK: Credential file accessed only by package manager (expected)"
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

#!/bin/bash
# Dependency Sandbox — Install packages in an isolated Docker container
# and monitor for suspicious behavior (network calls, file writes, process spawning).
#
# Usage:
#   ./scripts/dependency-sandbox.sh npm <package-name>[@version]
#   ./scripts/dependency-sandbox.sh pip <package-name>[==version]
#   ./scripts/dependency-sandbox.sh npm-project /path/to/package.json
#   ./scripts/dependency-sandbox.sh pip-project /path/to/requirements.txt
#
# Requires: Docker
#
# Exit codes:
#   0 — Clean (no suspicious behavior)
#   1 — Suspicious behavior detected
#   2 — Usage error or Docker not available

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_DIR="$SCRIPT_DIR/sandbox"
CONTAINER_PREFIX="security-audit-sandbox"

# --- Option parsing ---
PRIVATE_REGISTRIES=()
AUTH_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)
            [[ $# -ge 2 ]] || { echo "ERROR: --registry requires a value" >&2; exit 2; }
            PRIVATE_REGISTRIES+=("$2")
            shift 2
            ;;
        --auth-file)
            [[ $# -ge 2 ]] || { echo "ERROR: --auth-file requires a value" >&2; exit 2; }
            AUTH_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] <ecosystem> <package-or-path>"
            echo ""
            echo "Ecosystems: npm, pip, go, rust, dotnet, npm-project, pnpm-project, uv-project, pip-project, go-project, rust-project, dotnet-project"
            echo "  (npm uses pnpm, pip uses uv under the hood)"
            echo ""
            echo "Options:"
            echo "  --registry <host>     Add a private registry to the safe allowlist (can be repeated)"
            echo "  --auth-file <path>    Mount a scoped credential file (read-only, access is monitored)"
            echo ""
            echo "Examples:"
            echo "  $0 npm lodash@4.17.21"
            echo "  $0 --registry npm.mycompany.com --auth-file ./scoped-npmrc npm @mycompany/sdk@1.0.0"
            echo "  $0 --registry artifactory.corp.com pip my-internal-lib==2.0.0"
            echo "  $0 go github.com/gin-gonic/gin"
            echo "  $0 rust serde"
            echo "  $0 dotnet Newtonsoft.Json"
            echo "  $0 pnpm-project ./pnpm-lock.yaml"
            echo "  $0 uv-project ./uv.lock"
            echo "  $0 npm-project ./package.json"
            echo ""
            echo "Auth file format (scoped — never mount your full ~/.npmrc):"
            echo "  npm:    //npm.mycompany.com/:_authToken=<token>"
            echo "  pip:    [global]"
            echo "          index-url = https://user:token@pypi.mycompany.com/simple/"
            echo "  go:     GONOSUMCHECK=mycompany.com/* in env file"
            echo "  rust:   [registries.mycompany]"
            echo "          token = \"<token>\""
            echo "  dotnet: <packageSourceCredentials> in nuget.config"
            exit 0
            ;;
        -*)
            echo "ERROR: Unknown option '$1'. Use --help for usage."
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -lt 2 ]]; then
    echo "ERROR: Missing arguments. Usage: $0 [OPTIONS] <ecosystem> <package>"
    echo "Run $0 --help for full usage."
    exit 2
fi

MODE="$1"
TARGET="$2"

# Validate package name — reject shell metacharacters that enable injection
# Allows: alphanumerics, @, ., _, -, /, =, :, ^, ~ (covers npm, pip, go, rust, dotnet)
if [[ "$MODE" != *-project ]]; then
    if [[ ! "$TARGET" =~ ^[a-zA-Z0-9@._/=:^~-]+$ ]]; then
        echo "ERROR: Invalid package name '$TARGET' — contains disallowed characters"
        exit 2
    fi
fi

# Validate auth file if provided
if [[ -n "$AUTH_FILE" ]]; then
    if [[ ! -f "$AUTH_FILE" ]]; then
        echo "ERROR: Auth file not found: $AUTH_FILE"
        exit 2
    fi
    AUTH_FILE="$(cd "$(dirname "$AUTH_FILE")" && pwd)/$(basename "$AUTH_FILE")"
    echo "Private registry auth file: $AUTH_FILE (mounted read-only, access monitored)"
fi

if [[ ${#PRIVATE_REGISTRIES[@]} -gt 0 ]]; then
    echo "Private registries allowlisted: ${PRIVATE_REGISTRIES[*]}"
fi

# --- Check Docker ---
if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is required but not installed"
    exit 2
fi

if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon is not running"
    exit 2
fi

# --- Build sandbox image ---
build_image() {
    local dockerfile="$1"
    local tag="$2"

    echo "Building sandbox image: $tag"
    docker build -q -f "$dockerfile" -t "$tag" "$SANDBOX_DIR" >/dev/null
}

# --- Run sandboxed install ---
run_sandbox() {
    local image="$1"
    shift
    local container_name="${CONTAINER_PREFIX}-$$"
    local strace_dir
    strace_dir="$(mktemp -d "/tmp/${container_name}-strace.XXXXXX")"
    chmod 777 "$strace_dir"

    echo "Running sandboxed install in container: $container_name"
    echo "Command: $*"
    echo ""

    # Build docker run arguments
    local docker_args=(
        --name "$container_name"
        --rm=false
        --read-only
        --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=10001,gid=10001
        --tmpfs /sandbox:rw,exec,size=512m,uid=10001,gid=10001
        -v "$strace_dir:/strace:rw"
        --memory=512m
        --cpus=1
        --cap-drop=ALL
        --security-opt=no-new-privileges:true
        --pids-limit=256
    )

    # Mount auth file read-only if provided
    # Placed at a known path so strace can detect if install scripts read it
    if [[ -n "$AUTH_FILE" ]]; then
        docker_args+=(-v "$AUTH_FILE:/sandbox/.auth-credentials:ro")
        echo "Auth file mounted at /sandbox/.auth-credentials (read-only, monitored)"
    fi

    docker run "${docker_args[@]}" "$image" "$@" 2>&1 || true

    echo ""
    echo "Extracting analysis data..."

    # Cleanup container (strace dir persists with strace.log + audit.json)
    docker rm -f "$container_name" >/dev/null 2>&1 || true

    # Build analyzer arguments
    local analyzer_args=("$strace_dir/strace.log")
    for reg in "${PRIVATE_REGISTRIES[@]}"; do
        analyzer_args+=(--registry "$reg")
    done
    if [[ -n "$AUTH_FILE" ]]; then
        analyzer_args+=(--monitor-auth "/sandbox/.auth-credentials")
    fi

    # Analyze strace for supply chain behavior
    if [[ -f "$strace_dir/strace.log" ]]; then
        local result=0
        bash "$SANDBOX_DIR/analyze-strace.sh" "${analyzer_args[@]}" || result=$?

        # Show artifacts summary
        echo ""
        echo "=== Artifacts ==="
        echo "Results directory: $strace_dir"
        for f in audit.json sbom.json deps.json ips.txt strace.log; do
            if [[ -f "$strace_dir/$f" ]]; then
                local size
                size=$(wc -c < "$strace_dir/$f" | tr -d ' ')
                echo "  $f (${size} bytes)"
            fi
        done

        return $result
    else
        echo "WARNING: Could not extract strace log — container may have crashed"
        rm -rf "$strace_dir"
        return 1
    fi
}

# --- Analyze project sandbox results ---
analyze_project() {
    local strace_dir="$1"
    echo ""
    echo "Extracting analysis data..."

    docker rm -f "${CONTAINER_PREFIX}-project-$$" >/dev/null 2>&1 || true

    if [[ -f "$strace_dir/strace.log" ]]; then
        local result=0
        bash "$SANDBOX_DIR/analyze-strace.sh" "$strace_dir/strace.log" || result=$?

        echo ""
        echo "=== Artifacts ==="
        echo "Results directory: $strace_dir"
        for f in audit.json sbom.json deps.json ips.txt strace.log; do
            if [[ -f "$strace_dir/$f" ]]; then
                local size
                size=$(wc -c < "$strace_dir/$f" | tr -d ' ')
                echo "  $f (${size} bytes)"
            fi
        done

        exit $result
    else
        echo "WARNING: Could not extract strace log — container may have crashed"
        exit 1
    fi
}

# --- Execute based on mode ---
case "$MODE" in
    npm|pnpm)
        build_image "$SANDBOX_DIR/Dockerfile.pnpm" "$CONTAINER_PREFIX-pnpm"
        run_sandbox "$CONTAINER_PREFIX-pnpm" "$TARGET"
        ;;

    pip|uv)
        build_image "$SANDBOX_DIR/Dockerfile.uv" "$CONTAINER_PREFIX-uv"
        run_sandbox "$CONTAINER_PREFIX-uv" "$TARGET"
        ;;

    pip-project|uv-project)
        if [[ ! -f "$TARGET" ]]; then
            echo "ERROR: File not found: $TARGET"
            exit 2
        fi
        target_dir="$(cd "$(dirname "$TARGET")" && pwd)"
        build_image "$SANDBOX_DIR/Dockerfile.uv" "$CONTAINER_PREFIX-uv"
        strace_dir_proj="$(mktemp -d "/tmp/${CONTAINER_PREFIX}-project-$$-strace.XXXXXX")"
        chmod 777 "$strace_dir_proj"
        docker run \
            --name "${CONTAINER_PREFIX}-project-$$" \
            --rm=false \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=10001,gid=10001 \
            --tmpfs /sandbox:rw,exec,size=4g,uid=10001,gid=10001 \
            -v "$strace_dir_proj:/strace:rw" \
            -v "$target_dir:/project:ro" \
            --memory=4g \
            --cpus=2 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges:true \
            --pids-limit=256 \
            "$CONTAINER_PREFIX-uv" 2>&1 || true

        analyze_project "$strace_dir_proj"
        ;;

    go)
        build_image "$SANDBOX_DIR/Dockerfile.go" "$CONTAINER_PREFIX-go"
        # Go needs a go.mod; pass TARGET as positional arg to prevent sh -c injection
        run_sandbox "$CONTAINER_PREFIX-go" sh -c 'go mod init sandbox && go get -- "$1" && go mod download' _ "$TARGET"
        ;;

    rust)
        build_image "$SANDBOX_DIR/Dockerfile.rust" "$CONTAINER_PREFIX-rust"
        # Rust needs a Cargo.toml; pass TARGET as positional arg to prevent sh -c injection
        run_sandbox "$CONTAINER_PREFIX-rust" sh -c 'cargo init --name sandbox . && cargo add -- "$1" && cargo fetch' _ "$TARGET"
        ;;

    dotnet)
        build_image "$SANDBOX_DIR/Dockerfile.dotnet" "$CONTAINER_PREFIX-dotnet"
        # .NET needs a .csproj; pass TARGET as positional arg to prevent sh -c injection
        run_sandbox "$CONTAINER_PREFIX-dotnet" sh -c 'dotnet new console -o . --no-restore && dotnet add package "$1" && dotnet restore' _ "$TARGET"
        ;;

    go-project)
        if [[ ! -f "$TARGET" ]]; then
            echo "ERROR: File not found: $TARGET"
            exit 2
        fi
        build_image "$SANDBOX_DIR/Dockerfile.go" "$CONTAINER_PREFIX-go"
        strace_dir_proj="$(mktemp -d "/tmp/${CONTAINER_PREFIX}-project-$$-strace.XXXXXX")"
        chmod 777 "$strace_dir_proj"
        docker run \
            --name "${CONTAINER_PREFIX}-project-$$" \
            --rm=false \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=10001,gid=10001 \
            --tmpfs /sandbox:rw,exec,size=1g,uid=10001,gid=10001 \
            -v "$strace_dir_proj:/strace:rw" \
            -v "$(cd "$(dirname "$TARGET")" && pwd):/project:ro" \
            --memory=1g \
            --cpus=2 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges:true \
            --pids-limit=256 \
            "$CONTAINER_PREFIX-go" 2>&1 || true

        analyze_project "$strace_dir_proj"
        ;;

    rust-project)
        if [[ ! -f "$TARGET" ]]; then
            echo "ERROR: File not found: $TARGET"
            exit 2
        fi
        build_image "$SANDBOX_DIR/Dockerfile.rust" "$CONTAINER_PREFIX-rust"
        strace_dir_proj="$(mktemp -d "/tmp/${CONTAINER_PREFIX}-project-$$-strace.XXXXXX")"
        chmod 777 "$strace_dir_proj"
        docker run \
            --name "${CONTAINER_PREFIX}-project-$$" \
            --rm=false \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=10001,gid=10001 \
            --tmpfs /sandbox:rw,exec,size=1g,uid=10001,gid=10001 \
            -v "$strace_dir_proj:/strace:rw" \
            -v "$(cd "$(dirname "$TARGET")" && pwd):/project:ro" \
            --memory=1g \
            --cpus=2 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges:true \
            --pids-limit=256 \
            "$CONTAINER_PREFIX-rust" 2>&1 || true

        analyze_project "$strace_dir_proj"
        ;;

    dotnet-project)
        if [[ ! -f "$TARGET" ]]; then
            echo "ERROR: File not found: $TARGET"
            exit 2
        fi
        build_image "$SANDBOX_DIR/Dockerfile.dotnet" "$CONTAINER_PREFIX-dotnet"
        strace_dir_proj="$(mktemp -d "/tmp/${CONTAINER_PREFIX}-project-$$-strace.XXXXXX")"
        chmod 777 "$strace_dir_proj"
        docker run \
            --name "${CONTAINER_PREFIX}-project-$$" \
            --rm=false \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=10001,gid=10001 \
            --tmpfs /sandbox:rw,exec,size=1g,uid=10001,gid=10001 \
            -v "$strace_dir_proj:/strace:rw" \
            -v "$(cd "$(dirname "$TARGET")" && pwd):/project:ro" \
            --memory=1g \
            --cpus=2 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges:true \
            --pids-limit=256 \
            "$CONTAINER_PREFIX-dotnet" \
            --project /project 2>&1 || true

        analyze_project "$strace_dir_proj"
        ;;

    npm-project|pnpm-project)
        if [[ ! -f "$TARGET" ]]; then
            echo "ERROR: File not found: $TARGET"
            exit 2
        fi
        target_dir="$(cd "$(dirname "$TARGET")" && pwd)"
        build_image "$SANDBOX_DIR/Dockerfile.pnpm" "$CONTAINER_PREFIX-pnpm"
        strace_dir_proj="$(mktemp -d "/tmp/${CONTAINER_PREFIX}-project-$$-strace.XXXXXX")"
        chmod 777 "$strace_dir_proj"
        docker run \
            --name "${CONTAINER_PREFIX}-project-$$" \
            --rm=false \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=10001,gid=10001 \
            --tmpfs /sandbox:rw,exec,size=4g,uid=10001,gid=10001 \
            -v "$strace_dir_proj:/strace:rw" \
            -v "$target_dir:/project:ro" \
            --memory=4g \
            --cpus=2 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges:true \
            --pids-limit=256 \
            "$CONTAINER_PREFIX-pnpm" 2>&1 || true

        analyze_project "$strace_dir_proj"
        ;;

    *)
        echo "ERROR: Unknown mode '$MODE'. Use: npm, pip, go, rust, dotnet, pnpm-project, uv-project, npm-project, pip-project, go-project, rust-project, dotnet-project"
        exit 2
        ;;
esac

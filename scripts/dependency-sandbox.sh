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

# --- Argument parsing ---
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <npm|pip|npm-project|pip-project> <package-or-path>"
    echo ""
    echo "Examples:"
    echo "  $0 npm lodash@4.17.21       # Sandbox a single npm package"
    echo "  $0 pip requests==2.31.0      # Sandbox a single pip package"
    echo "  $0 npm-project ./package.json  # Sandbox a project's dependencies"
    echo "  $0 pip-project ./requirements.txt  # Sandbox a project's dependencies"
    exit 2
fi

MODE="$1"
TARGET="$2"

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

    echo "Running sandboxed install in container: $container_name"
    echo "Command: $*"
    echo ""

    # Run with:
    # - No network access to non-registry hosts (restricted via DNS)
    # - Read-only root filesystem (except /tmp and /sandbox)
    # - No capabilities
    # - Memory limit
    # - CPU limit
    # - Timeout
    docker run \
        --name "$container_name" \
        --rm=false \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=256m \
        --tmpfs /sandbox:rw,exec,size=512m \
        --memory=512m \
        --cpus=1 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges:true \
        --pids-limit=256 \
        "$image" \
        "$@" 2>&1 || true

    # Extract strace log from container
    echo ""
    echo "Extracting analysis data..."
    docker cp "$container_name:/tmp/strace.log" "/tmp/${container_name}-strace.log" 2>/dev/null || true

    # Cleanup container
    docker rm -f "$container_name" >/dev/null 2>&1 || true

    # Analyze
    if [[ -f "/tmp/${container_name}-strace.log" ]]; then
        bash "$SANDBOX_DIR/analyze-strace.sh" "/tmp/${container_name}-strace.log"
        local result=$?
        rm -f "/tmp/${container_name}-strace.log"
        return $result
    else
        echo "WARNING: Could not extract strace log — container may have crashed"
        return 1
    fi
}

# --- Execute based on mode ---
case "$MODE" in
    npm)
        build_image "$SANDBOX_DIR/Dockerfile.npm" "$CONTAINER_PREFIX-npm"
        run_sandbox "$CONTAINER_PREFIX-npm" "$TARGET"
        ;;

    pip)
        build_image "$SANDBOX_DIR/Dockerfile.pip" "$CONTAINER_PREFIX-pip"
        run_sandbox "$CONTAINER_PREFIX-pip" "$TARGET"
        ;;

    npm-project)
        if [[ ! -f "$TARGET" ]]; then
            echo "ERROR: File not found: $TARGET"
            exit 2
        fi
        build_image "$SANDBOX_DIR/Dockerfile.npm" "$CONTAINER_PREFIX-npm"
        # Copy package.json into container via volume mount
        docker run \
            --name "${CONTAINER_PREFIX}-project-$$" \
            --rm=false \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=256m \
            --tmpfs /sandbox:rw,exec,size=512m \
            -v "$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET"):/sandbox/package.json:ro" \
            --memory=512m \
            --cpus=1 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges:true \
            --pids-limit=256 \
            "$CONTAINER_PREFIX-npm" 2>&1 || true

        docker cp "${CONTAINER_PREFIX}-project-$$:/tmp/strace.log" "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log" 2>/dev/null || true
        docker rm -f "${CONTAINER_PREFIX}-project-$$" >/dev/null 2>&1 || true

        if [[ -f "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log" ]]; then
            bash "$SANDBOX_DIR/analyze-strace.sh" "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log"
            result=$?
            rm -f "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log"
            exit $result
        fi
        ;;

    pip-project)
        if [[ ! -f "$TARGET" ]]; then
            echo "ERROR: File not found: $TARGET"
            exit 2
        fi
        build_image "$SANDBOX_DIR/Dockerfile.pip" "$CONTAINER_PREFIX-pip"
        docker run \
            --name "${CONTAINER_PREFIX}-project-$$" \
            --rm=false \
            --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,size=256m \
            --tmpfs /sandbox:rw,exec,size=512m \
            -v "$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET"):/sandbox/requirements.txt:ro" \
            --memory=512m \
            --cpus=1 \
            --cap-drop=ALL \
            --security-opt=no-new-privileges:true \
            --pids-limit=256 \
            "$CONTAINER_PREFIX-pip" \
            -r /sandbox/requirements.txt 2>&1 || true

        docker cp "${CONTAINER_PREFIX}-project-$$:/tmp/strace.log" "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log" 2>/dev/null || true
        docker rm -f "${CONTAINER_PREFIX}-project-$$" >/dev/null 2>&1 || true

        if [[ -f "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log" ]]; then
            bash "$SANDBOX_DIR/analyze-strace.sh" "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log"
            result=$?
            rm -f "/tmp/${CONTAINER_PREFIX}-project-$$-strace.log"
            exit $result
        fi
        ;;

    *)
        echo "ERROR: Unknown mode '$MODE'. Use: npm, pip, npm-project, pip-project"
        exit 2
        ;;
esac

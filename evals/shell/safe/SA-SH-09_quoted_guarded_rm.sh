#!/bin/bash
# Clean up old releases before deploying the new one
set -euo pipefail

RELEASE_DIR=${1:?usage: cleanup RELEASE_DIR STAGING_NAME}
STAGING_DIR=/srv/staging/${2:?usage: cleanup RELEASE_DIR STAGING_NAME}

rm -rf "${RELEASE_DIR:?}/old"
rm -rf "${STAGING_DIR:?}/"

# Static path with no expansion; the assignment on the next line must not
# be bridged into the rm by a multiline-happy scanner regex
rm -rf /srv/staging/.build-cache
NEW_RELEASE_STAMP=$(date +%Y%m%d%H%M)

mkdir -p "$RELEASE_DIR/old" "$STAGING_DIR"
echo "workspace reset at $NEW_RELEASE_STAMP"

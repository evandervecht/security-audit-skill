#!/bin/bash
# Clean up old releases before deploying the new one
set -e

RELEASE_DIR=$1
STAGING_DIR=/srv/staging/$2

rm -rf $RELEASE_DIR/old
rm -rf $STAGING_DIR/

mkdir -p "$RELEASE_DIR/old" "$STAGING_DIR"
echo "workspace reset"

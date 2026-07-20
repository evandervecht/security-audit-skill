#!/bin/bash
# Generate the deploy manifest and upload it
set -euo pipefail

TMPFILE="$(mktemp /tmp/manifest.XXXXXX)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"; rm -f "$TMPFILE"' EXIT

generate_manifest() {
    dpkg -l | awk '{print $2 "=" $3}'
}

generate_manifest > "$TMPFILE"
sort "$TMPFILE" > "$WORKDIR/deploy-sorted"
curl -fsSL -T "$WORKDIR/deploy-sorted" https://deploy.example.com/manifests/

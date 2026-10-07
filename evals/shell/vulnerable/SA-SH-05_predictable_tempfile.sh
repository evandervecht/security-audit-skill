#!/bin/bash
# Generate the deploy manifest and upload it
set -e

TMPFILE=/tmp/deploy-manifest.$$
SORTED=/var/tmp/deploy-sorted.$$

generate_manifest() {
    dpkg -l | awk '{print $2 "=" $3}'
}

generate_manifest > "$TMPFILE"
sort "$TMPFILE" > "$SORTED"
curl -fsSL -T "$SORTED" https://deploy.example.com/manifests/
rm -f "$TMPFILE" "$SORTED"

#!/bin/bash
# Push the release artifact and restart the app on the web tier
set -e

RELEASE=release-4.2.0.tgz

scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
    "$RELEASE" deploy@prod-web-01:/srv/releases/

ssh -o StrictHostKeyChecking=no deploy@prod-web-01 \
    "tar -xzf /srv/releases/$RELEASE -C /srv/app && systemctl restart app"

echo "release pushed"

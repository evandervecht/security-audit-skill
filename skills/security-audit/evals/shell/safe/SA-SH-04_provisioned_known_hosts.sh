#!/bin/bash
# Push the release artifact and restart the app on the web tier
set -euo pipefail

RELEASE=release-4.2.0.tgz
KNOWN_HOSTS=/etc/ssh/ssh_known_hosts   # provisioned at image build via ssh-keyscan

scp -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
    "$RELEASE" deploy@prod-web-01:/srv/releases/

ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
    deploy@prod-web-01 \
    "tar -xzf /srv/releases/$RELEASE -C /srv/app && systemctl restart app"

echo "release pushed"

#!/bin/bash
# Pull deploy metadata from the internal API (internal CA trusted explicitly)
set -euo pipefail

CA_BUNDLE=/etc/ssl/certs/internal-ca.pem

curl -fsSL --cacert "$CA_BUNDLE" \
    https://internal-api.example.com/v1/deploy-token -o /etc/app/token.json

curl -fsSL --cacert "$CA_BUNDLE" -X POST -d @payload.json \
    https://internal-api.example.com/v1/events

wget --ca-certificate="$CA_BUNDLE" https://artifacts.example.com/release-4.2.0.tgz

# Chained decompression: the -dk cluster belongs to gzip, not to this curl
curl -fsSL --cacert "$CA_BUNDLE" -o notes.gz https://artifacts.example.com/notes.gz && gzip -dk notes.gz

echo "metadata refreshed"

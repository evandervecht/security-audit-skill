#!/bin/bash
# Pull deploy metadata from the internal API
set -e

curl -sk https://internal-api.example.com/v1/deploy-token -o /etc/app/token.json

curl --insecure -X POST -d @payload.json https://internal-api.example.com/v1/events

curl -kv https://legacy-api.example.com/health -o /dev/null

wget --no-check-certificate https://artifacts.example.com/release-4.2.0.tgz

echo "metadata refreshed"

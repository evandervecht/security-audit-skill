#!/bin/bash
# Deploy the app and log progress without leaking credentials
set -euo pipefail

SECRETS_DIR=/run/secrets
DEPLOY_TOKEN="$(cat "$SECRETS_DIR/deploy_token")"
DB_PASSWORD="$(cat "$SECRETS_DIR/db_password")"

if [ -z "$DB_PASSWORD" ] || [ -z "$DEPLOY_TOKEN" ]; then
    echo "ERROR: deploy credentials are not set" >&2
    exit 1
fi

# A log line followed by legitimate secret use on the next line must not match
echo "starting deploy"
deploy --token-stdin <<< "$DEPLOY_TOKEN"
unset DEPLOY_TOKEN DB_PASSWORD

echo "deploy finished for release 4.2.0" >> /var/log/deploy.log
# Logging a non-secret path variable is fine - name does not end in a keyword
echo "credentials were read from $SECRETS_DIR" >> /var/log/deploy.log

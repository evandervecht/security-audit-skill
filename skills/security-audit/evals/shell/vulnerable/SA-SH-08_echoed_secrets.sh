#!/bin/bash
# Deploy the app and log progress
set -e

DEPLOY_TOKEN="$(cat /run/secrets/deploy_token)"
DB_PASSWORD="$(cat /run/secrets/db_password)"

echo "Deploying with token $DEPLOY_TOKEN"
echo "db password: ${DB_PASSWORD}" >> /var/log/deploy.log

deploy --token-stdin <<< "$DEPLOY_TOKEN"
echo "deploy finished"

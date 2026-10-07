#!/bin/bash
# Sync inventory to the reporting warehouse
set -euo pipefail

# Non-secret configuration: names contain credential keywords but hold
# endpoints, header labels, and paths - not secrets
TOKEN_ENDPOINT="https://warehouse.example.com/oauth2/token"
API_KEY_HEADER="X-Api-Key"
PASSWORD_FILE=/run/secrets/db_password
SECRET_NAME=warehouse-report-credentials

DB_PASSWORD="$(cat "$PASSWORD_FILE")"
API_KEY="${APP_API_KEY:?APP_API_KEY must be set}"
DEPLOY_TOKEN="$(vault kv get -field=token "secret/ci/$SECRET_NAME")"

export PGPASSWORD="$DB_PASSWORD"
pg_dump -h db.example.com -U app inventory > inventory.sql

curl -fsSL -H "Authorization: Bearer $DEPLOY_TOKEN" \
    -H "$API_KEY_HEADER: $API_KEY" \
    -T inventory.sql "$TOKEN_ENDPOINT"

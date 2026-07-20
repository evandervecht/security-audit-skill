#!/bin/bash
# Sync inventory to the reporting warehouse
set -e

DB_PASSWORD="Sup3rS3cretPw2024"
export API_KEY=sk_live_9a8b7c6d5e4f3a2b
export SECRET_KEY=dj4ng0-s3ss10n-s1gn1ng-k3y
DEPLOY_TOKEN='ghp_Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0De'

export PGPASSWORD="$DB_PASSWORD"
pg_dump -h db.example.com -U app inventory > inventory.sql

curl -fsSL -H "Authorization: Bearer $DEPLOY_TOKEN" \
    -T inventory.sql https://warehouse.example.com/ingest

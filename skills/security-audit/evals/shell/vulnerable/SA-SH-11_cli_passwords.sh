#!/bin/bash
# Nightly reporting job
set -e

mysql -h db.example.com -u appuser -pS3cretPw99 inventory \
    -e "SELECT COUNT(*) FROM parts" > parts_count.txt

psql "postgresql://reporter:R3p0rtPass@db.example.com:5432/analytics" \
    -c "COPY daily_sales TO STDOUT" > daily_sales.csv

curl -u admin:hunter2 https://ci.example.com/api/queue > queue.json

echo "reports refreshed"

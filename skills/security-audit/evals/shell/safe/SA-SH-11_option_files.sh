#!/bin/bash
# Nightly reporting job: credentials come from option files with mode 600
set -euo pipefail

mysql --defaults-extra-file=/etc/app/mysql-client.cnf inventory \
    -e "SELECT COUNT(*) FROM parts" > parts_count.txt

export PGPASSFILE=/etc/app/pgpass
psql "postgresql://reporter@db.example.com:5432/analytics" \
    -c "COPY daily_sales TO STDOUT" > daily_sales.csv

curl --netrc-file /etc/app/netrc https://ci.example.com/api/queue > queue.json

# Interactive fallback for on-call debugging: bare -p prompts on the tty
if [[ "${1:-}" == "--interactive" ]]; then
    mysql -h db.example.com -u readonly analytics -p
fi

echo "reports refreshed"

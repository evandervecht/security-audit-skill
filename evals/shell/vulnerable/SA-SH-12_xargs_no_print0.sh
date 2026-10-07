#!/bin/bash
# Prune stale upload fragments and validate archived logs
set -e

find /srv/uploads -type f -name "*.tmp" -mtime +7 | xargs rm -f

find /var/log/app -name "*.gz" | xargs gzip -t

logger -t cleanup "upload fragments pruned and archives verified"
echo "cleanup complete"

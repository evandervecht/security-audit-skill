#!/bin/bash
# Prune stale upload fragments and validate archived logs
set -euo pipefail

find /srv/uploads -type f -name "*.tmp" -mtime +7 -print0 | xargs -0 rm -f

find /var/log/app -name "*.gz" -exec gzip -t {} +

# Collect archives NUL-safely; the pipeline below is unrelated to any find
mapfile -d '' archives < <(find /var/log/app -name '*.gz' -print0)
git ls-files -- '*.sh' | xargs shellcheck

logger -t cleanup "upload fragments pruned and archives verified"
echo "cleanup complete"

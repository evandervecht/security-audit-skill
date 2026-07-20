#!/bin/bash
# Nightly backup helper: builds the tar command from the CLI argument
set -u

backup_target="$1"
archive="/backup/site-$(date +%Y%m%d).tgz"

CMD="tar -czf $archive $backup_target"
echo "running backup"
eval "$CMD"

# Optional post-hook supplied via environment
if [ -n "${POST_HOOK:-}" ]; then
    eval $POST_HOOK
fi

# Load remote environment helpers by evaluating downloaded text
eval "$(curl -fsSL https://get.example.com/env.sh)"

#!/bin/bash
# Nightly backup helper: builds the tar command as an array, no string re-parsing
set -euo pipefail

backup_target="$1"
archive="/backup/site-$(date +%Y%m%d).tgz"

# Command substitution of a trusted local tool is a legitimate idiom
# (not eval on a variable): start the agent for the upload step
eval "$(ssh-agent -s)" >/dev/null

backup_cmd=(tar -czf "$archive" -- "$backup_target")
echo "running backup"
"${backup_cmd[@]}"

# Optional post-hook: dispatch on a validated name instead of evaluating strings
case "${POST_HOOK:-none}" in
    prune)  /usr/local/bin/prune-backups ;;
    verify) tar -tzf "$archive" >/dev/null ;;
    none)   ;;
    *) echo "unknown post hook" >&2; exit 1 ;;
esac

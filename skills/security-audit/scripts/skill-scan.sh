#!/bin/bash
# Agent skill scan, pattern pass: one line per match, for a reviewer to read in context
# (references/agent-skill-scan.md). A hit is a place to look, not a verdict.
#
#   skill-scan.sh <skill-dir> [<skill-dir>...]
#   HIT <code> <file>:<line> <the line, trimmed>
#
# Codes as in the reference: RC remote code, OB obfuscation, PI prompt injection,
# EX data leaving, SE secrets, PE persistence/privilege. Exit 0 with or without hits;
# 2 when a directory is missing.

set -u
[ $# -ge 1 ] || { echo "usage: $0 <skill-dir>..." >&2; exit 2; }

S='[[:space:]]'
PATTERNS=(
  "RC|(curl|wget)[^|]*\|$S*(ba|z|da)?sh([^a-z]|$)"
  "RC|(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)[^|]*\|$S*(iex|Invoke-Expression)"
  "RC|Invoke-Expression|(^|[^a-z])iex$S"
  "RC|@latest([^a-z]|$)"
  "RC|(install|add)$S.*$S(-y|--yes)([^a-z]|$)"
  "OB|base64$S+(-d|--decode)|FromBase64String|-EncodedCommand|(^|[^a-z])atob\(|new$S+Function\("
  "OB|(^|[^a-z_.])eval$S*\("
  "PI|ignore$S+(all$S+|any$S+)?(previous|prior|above|earlier)$S+(instructions|rules|messages)"
  "PI|(do$S+not|don't|never)$S+(tell|inform|show|mention)$S+(this$S+to$S+)?the$S+user"
  "PI|without$S+(telling|asking|informing)$S+the$S+user|disregard$S+(the$S+|all$S+)?(system|previous)"
  "EX|discord(app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|requestbin|pipedream\.net|ngrok|pastebin\.com|transfer\.sh"
  "EX|(curl|wget)[^#]*(-d|--data|-F|--form|-T|--upload-file)$S"
  "SE|~/\.ssh|\.ssh/(id_|authorized_keys)|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.credentials\.json"
  "SE|(process\.env|os\.environ|\\\$env:|getenv)[^;]*(TOKEN|SECRET|PASSWORD|API_KEY)"
  "PE|--dangerously|bypassPermissions|dangerouslySkipPermissions|chmod$S+(-R$S+)?777|(^|[^a-z])sudo$S"
  "PE|\.bashrc|\.zshrc|\.bash_profile|crontab|schtasks|Register-ScheduledTask|New-Service"
  "PE|\.claude/settings(\.local)?\.json|\"hooks\"$S*:"
)

status=0
for dir in "$@"; do
  if [ ! -d "$dir" ]; then echo "skill-scan: no directory $dir" >&2; status=2; continue; fi
  for entry in "${PATTERNS[@]}"; do
    code=${entry%%|*}; re=${entry#*|}
    grep -rnIiE --exclude-dir=.git --exclude-dir=node_modules -e "$re" "$dir" 2>/dev/null |
      while IFS= read -r hit; do
        file=${hit%%:*}; rest=${hit#*:}; line=${rest%%:*}; text=${rest#*:}
        text=$(printf '%s' "$text" | tr -s '[:space:]' ' ' | cut -c1-160)
        printf 'HIT %s %s:%s %s\n' "$code" "$file" "$line" "$text"
      done
  done
  # hidden Unicode: zero-width, bidi overrides, word joiners, tag characters (a BOM opening a file is fine)
  grep -rlIZ --exclude-dir=.git --exclude-dir=node_modules '' "$dir" 2>/dev/null |
    xargs -0 -r perl -CSD -ne 's/^\x{FEFF}// if $. == 1; if (/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}\x{E0000}-\x{E007F}]/) { print "HIT OB $ARGV:$. hidden Unicode U+", sprintf("%04X", ord($&)), "\n" } close ARGV if eof' 2>/dev/null
done
exit $status

